/*  =========================================================================
    range_scan - Perform one range scan

    Copyright (C) 2014 - 2020 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

#include "range_scan.h"
#include "cidr.h"
#include "device_scan.h"
#include "fty_discovery_server.h"
#include <fty/convert.h>
#include <fty_log.h>


//  --------------------------------------------------------------------------
//  Create a new range_scan

range_scan_t* range_scan_new(const char* range)
{
    assert(range);
    range_scan_t* self = static_cast<range_scan_t*>(zmalloc(sizeof(range_scan_t)));
    assert(self);
    //  Initialize class properties here
    self->range   = strdup(range);
    const char* p = strchr(range, '/');
    if (p) {
        ++p;
        int prefix = atoi(p);
        if (prefix <= 32) {
            self->size = 1 << (32 - prefix);
        }
        self->cursor = 0;
    }
    return self;
}

//  --------------------------------------------------------------------------
//  report progress in % (0 - 100);

int range_scan_progress(range_scan_t* self)
{
    int64_t result = self->cursor * 100 / self->size;
    if (result > 100)
        result = 100;
    return fty::convert<int>(result);
}

//  --------------------------------------------------------------------------
//  Returns current scanning range (cidr format)

const char* range_scan_range(range_scan_t* self)
{
    return self->range;
}

//  --------------------------------------------------------------------------
//  Destroy the range_scan

void range_scan_destroy(range_scan_t** self_p)
{
    assert(self_p);
    if (*self_p) {
        range_scan_t* self = *self_p;
        //  Free class properties here
        zstr_free(&self->range);
        //  Free object itself
        free(self);
        *self_p = NULL;
    }
}

void range_scan_actor(zsock_t* pipe, void* args)
{
    zsock_signal(pipe, 0);
    range_scan_args_t*         params;
    discovered_devices_t*      params2;
    const fty::nut::KeyValues* mappings;
    const fty::nut::KeyValues* sensorMappings;
    zlist_t*                   argv;
    {
        // args check
        if (!args) {
            log_error("Scanning params not defined!");
            zstr_send(pipe, REQ_DONE);
            return;
        }
        argv = static_cast<zlist_t*>(args);
        if (!argv || zlist_size(argv) != 4) {
            log_error("Error in parameters");
            zstr_send(pipe, REQ_DONE);
            zlist_destroy(&argv);
            return;
        }
        params         = static_cast<range_scan_args_t*>(zlist_first(argv));
        params2        = static_cast<discovered_devices_t*>(zlist_next(argv));
        mappings       = static_cast<const fty::nut::KeyValues*>(zlist_next(argv));
        sensorMappings = static_cast<const fty::nut::KeyValues*>(zlist_next(argv));
        if (!params || (params->ranges.size() < 1) || !params->config || !params2) {
            log_error("Scanning range not defined!");
            zstr_send(pipe, REQ_DONE);
            zlist_destroy(&argv);
            return;
        }

        for (auto range : params->ranges) {
            CIDRAddress addrcheck(range.first);
            if (!addrcheck.valid()) {
                log_error("Address range (%s) is not valid!", range.first);
                zstr_send(pipe, REQ_DONE);
                zlist_destroy(&argv);
                return;
            }
            if (addrcheck.protocol() != 4) {
                log_error("Scanning is not supported for such range (%s)!", range.first);
                zstr_send(pipe, REQ_DONE);
                zlist_destroy(&argv);
                return;
            }
        }
    }

    zlist_t* listScans = zlist_new();
    for (auto range : params->ranges) {
        CIDRList*   list = new CIDRList();
        CIDRAddress addr;
        CIDRAddress addrDest;

        if (!range.second) {
            CIDRAddress addr_network(range.first);
            list->add(addr_network.network());
        } else {
            // real range and not subnetwork, need to scan all ips
            CIDRAddress addrStart(range.first);
            list->add(addrStart.host());
            addrDest = CIDRAddress(range.second);
            list->add(addrDest.host());
        }
        zstr_free(&(range.first));
        zstr_free(&(range.second));
        zlist_append(listScans, list);
    }

    zactor_t*  device_actor = device_scan_new(listScans, params2, mappings, sensorMappings);
    zpoller_t* poller       = zpoller_new(pipe, device_actor, NULL);

    zstr_sendx(device_actor, "SCAN", NULL);

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, 1000);
        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            if (msg) {
                char* cmd = zmsg_popstr(msg);
                if (cmd) {
                    if (streq(cmd, "$TERM")) {
                        zstr_free(&cmd);
                        zactor_destroy(&device_actor);
                        zmsg_destroy(&msg);
                        break;
                    }
                    zstr_free(&cmd);
                }
                zmsg_destroy(&msg);
            }
        } else if (which == NULL) {
            // timeout
        } else {
            // from device actor
            zmsg_t* msg = zmsg_recv(which);
            if (msg) {
                zmsg_print(msg);
                char* cmd = zmsg_popstr(msg);
                if (streq(cmd, REQ_DONE)) {
                    zstr_free(&cmd);
                    zmsg_destroy(&msg);
                    break;
                }
                zstr_free(&cmd);
                zmsg_pushstr(msg, "FOUND");
                zmsg_send(&msg, pipe);
                zmsg_destroy(&msg);
            } else {
                // strange failure
                break;
            }
        }
    }
    params->ranges.clear();
    zlist_destroy(&argv);
    zactor_destroy(&device_actor);
    zpoller_destroy(&poller);
    zstr_send(pipe, REQ_DONE);
}
