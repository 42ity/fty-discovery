/*  =========================================================================
    device_scan - Perform one IP address scan

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

#include "device_scan.h"
#include "cidr.h"
#include "scan_nut.h"
#include "scan_nm2.h"
#include <fty/convert.h>
#include <fty_log.h>

bool device_scan_scan(zlist_t* listScans, discovered_devices_t* devices, zsock_t* pipe,
    const fty::nut::KeyValues* mappings, const fty::nut::KeyValues* sensorMappings,
    const std::set<std::string>& documentIds)
{
    CIDRList*              listAddr = static_cast<CIDRList*>(zlist_first(listScans));
    zpoller_t*             poller   = zpoller_new(pipe, NULL);
    std::vector<zactor_t*> listActor;
    bool                   term = false;
    while (listAddr != NULL) {
        {
            zlist_t* args = zlist_new();
            zlist_append(args, listAddr);
            zlist_append(args, devices);
            zlist_append(args, const_cast<void*>(static_cast<const void*>(mappings)));
            zlist_append(args, const_cast<void*>(static_cast<const void*>(sensorMappings)));
            zlist_append(args, const_cast<void*>(static_cast<const void*>(&documentIds)));

            zactor_t* scan_nut = zactor_new(scan_nut_actor, args);
            zpoller_add(poller, scan_nut);
            listActor.push_back(scan_nut);
        }

        {
            //listAddr deletes in nut scanner :(, clone it for nm2 actor
            CIDRList* cloned = new CIDRList;
            CIDRAddress addr;
            while(listAddr->next(addr)) {
                cloned->add(addr);
            }

            zlist_t* args = zlist_new();
            zlist_append(args, cloned);
            zlist_append(args, devices);
            zlist_append(args, const_cast<void*>(static_cast<const void*>(&documentIds)));
            zlist_append(args, const_cast<void*>(static_cast<const void*>(mappings)));
            zlist_append(args, const_cast<void*>(static_cast<const void*>(sensorMappings)));

            zactor_t* scan_nm2 = zactor_new(scan_nm2_actor, args);
            zpoller_add(poller, scan_nm2);
            listActor.push_back(scan_nm2);
        }


        listAddr = static_cast<CIDRList*>(zlist_next(listScans));
    }

    size_t number_end_actor = 0;

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, 5000);
        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            if (msg) {
                char* cmd = zmsg_popstr(msg);
                if (cmd) {
                    if (streq(cmd, "$TERM")) {
                        zstr_free(&cmd);
                        zmsg_destroy(&msg);
                        term = true;
                        break;
                    }
                    zstr_free(&cmd);
                }
                zmsg_destroy(&msg);
            }
        } else if (which == NULL) {
            // time out, nothing to do
        } else { // any of scan_nut_actor
            zmsg_t* msg = zmsg_recv(which);
            if (msg) {
                char* cmd = zmsg_popstr(msg);
                if (cmd) {
                    if (streq(cmd, "$TERM")) {
                        zstr_free(&cmd);
                        zmsg_destroy(&msg);
                        break;
                    } else if (streq(cmd, REQ_DONE)) {
                        zstr_free(&cmd);
                        zmsg_destroy(&msg);
                        auto end_actor = std::find(listActor.begin(), listActor.end(), static_cast<zactor_t*>(which));
                        if (end_actor == listActor.end()) {
                            // ERROR ? Normaly can't happened
                            log_error("%s Error : actor not in the actor list", __FUNCTION__);
                        } else {
                            listActor.erase(end_actor);
                        }
                        zpoller_remove(poller, which);
                        zactor_destroy(reinterpret_cast<zactor_t**>(&which));
                        if (listActor.empty())
                            break;
                        else if (number_end_actor >= listActor.size()) {
                            for (auto actor : listActor) {
                                zmsg_t* msg_cont = zmsg_new();
                                zmsg_pushstr(msg_cont, CMD_CONTINUE);
                                zmsg_send(&msg_cont, actor);
                            }
                            number_end_actor = 0;
                        }
                    } else if (streq(cmd, INFO_READY)) {
                        number_end_actor++;
                        if (number_end_actor >= listActor.size()) {
                            for (auto actor : listActor) {
                                zmsg_t* msg_cont = zmsg_new();
                                zmsg_pushstr(msg_cont, CMD_CONTINUE);
                                zmsg_send(&msg_cont, actor);
                            }
                            number_end_actor = 0;
                        }
                        zstr_free(&cmd);
                        zmsg_destroy(&msg);
                    } else if (streq(cmd, REQ_FOUND)) {
                        zmsg_t* reply = zmsg_dup(msg);
                        zmsg_pushstr(reply, REQ_FOUND);
                        zmsg_send(&reply, pipe);
                        zstr_free(&cmd);
                    }
                    zstr_free(&cmd);
                }
                zmsg_destroy(&msg);
            }
        }
    }

    for (auto actor : listActor) {
        zactor_destroy(&actor);
    }

    listActor.clear();
    zlist_destroy(&listScans);
    log_debug("QUIT device scan scan");
    zpoller_destroy(&poller);
    return term;
}

//  --------------------------------------------------------------------------
//  One device scan actor

void device_scan_actor(zsock_t* pipe, void* args)
{
    zsock_signal(pipe, 0);
    if (!args) {
        log_error("dsa: actor created without parameters");
        return;
    }

    zlist_t* argv = static_cast<zlist_t*>(args);

    if (!argv || zlist_size(argv) != 4) {
        log_error("dsa: actor created without config");
        zlist_destroy(&argv);
        return;
    }
    zlist_t* listScans = static_cast<zlist_t*>(zlist_first(argv));
    if (zlist_size(listScans) < 1) {
        log_error("dsa: actor created without any scans");
        zlist_destroy(&argv);
        zlist_destroy(&listScans);
        return;
    }
    discovered_devices_t*      devices        = static_cast<discovered_devices_t*>(zlist_next(argv));
    const fty::nut::KeyValues* mappings       = static_cast<const fty::nut::KeyValues*>(zlist_next(argv));
    const fty::nut::KeyValues* sensorMappings = static_cast<const fty::nut::KeyValues*>(zlist_next(argv));

    log_debug("dsa: device scan actor created");
    while (!zsys_interrupted) {
        zmsg_t* msg = zmsg_recv(pipe);
        if (msg) {
            char* cmd = zmsg_popstr(msg);
            if (streq(cmd, "$TERM")) {
                zstr_free(&cmd);
                break;
            } else if (streq(cmd, "SCAN")) {
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                zconfig_t* config = zconfig_load(getDiscoveryConfigFile().c_str());
                if (!config) {
                    log_error("failed to load config file %s", getDiscoveryConfigFile().c_str());
                    config = zconfig_new("root", NULL);
                }
                char* strNbPool = zconfig_get(config, CFG_PARAM_MAX_SCANPOOL_NUMBER, DEFAULT_MAX_SCANPOOL_NUMBER);
                const size_t          number_max_pool = fty::convert<size_t>(strNbPool);
                std::set<std::string> documentIds;
                {
                    zconfig_t* documents = zconfig_locate(config, CFG_DISCOVERY_DOCUMENTS);
                    if (documents) {
                        for (zconfig_t* document = zconfig_child(documents); document;
                             document            = zconfig_next(document)) {
                            const char* documentName = zconfig_value(document);
                            if (documentName && documentName[0] != '\0') {
                                documentIds.emplace(documentName);
                            }
                        }
                    }
                }
                zconfig_destroy(&config);
                bool stopped = false;
                while (!stopped && zlist_size(listScans) > 0) {
                    size_t   number_of_scans = 0;
                    zlist_t* scanPool        = zlist_new();
                    while (number_of_scans < number_max_pool && zlist_size(listScans) > 0) {
                        zlist_append(scanPool, zlist_pop(listScans));
                        number_of_scans++;
                    }
                    stopped = device_scan_scan(scanPool, devices, pipe, mappings, sensorMappings, documentIds);
                }
                zlist_destroy(&listScans);

                zmsg_t* end = zmsg_new();
                zmsg_pushstr(end, REQ_DONE);
                zmsg_send(&end, pipe);
                break;
            }
            zmsg_destroy(&msg);
        }
    }
    log_debug("dsa: device scan actor exited");
    zlist_destroy(&argv);
}


//  --------------------------------------------------------------------------
//  Create a new device_scan actor

zactor_t* device_scan_new(zlist_t* arg0, discovered_devices_t* arg1, const fty::nut::KeyValues* mappings,
    const fty::nut::KeyValues* sensorMappings)
{
    zlist_t* args = zlist_new();
    zlist_append(args, arg0);
    zlist_append(args, arg1);
    zlist_append(args, const_cast<void*>(static_cast<const void*>(mappings)));
    zlist_append(args, const_cast<void*>(static_cast<const void*>(sensorMappings)));
    return zactor_new(device_scan_actor, static_cast<void*>(args));
}
