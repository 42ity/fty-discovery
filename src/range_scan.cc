/*  =========================================================================
    range_scan - Perform one range scan

    Copyright (C) 2014 - 2017 Eaton

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

/*
@header
    range_scan - Perform one range scan
@discuss
@end
*/

#include "fty_discovery_classes.h"

//  Structure of our class

struct _range_scan_t {
    char *range;
    int64_t size;
    int64_t cursor;
};


//  --------------------------------------------------------------------------
//  Create a new range_scan

range_scan_t *
range_scan_new (const char *range)
{
    assert (range);
    range_scan_t *self = (range_scan_t *) zmalloc (sizeof (range_scan_t));
    assert (self);
    //  Initialize class properties here
    self->range = strdup (range);
    const char *p = strchr (range, '/');
    if (p) {
        ++p;
        int prefix = atoi (p);
        if (prefix <= 32) {
            self->size = 1 << (32 - prefix);
        }
        self->cursor = 0;
    }
    return self;
}

//  --------------------------------------------------------------------------
//  report progress in % (0 - 100);

int
range_scan_progress (range_scan_t *self)
{
    return (self->cursor * 100 / self->size);
}

//  --------------------------------------------------------------------------
//  Returns current scanning range (cidr format)

const char *
range_scan_range (range_scan_t *self)
{
    return self->range;
}

//  --------------------------------------------------------------------------
//  Do the scan

void
range_scan_scan (const char *cidr)
{
    CIDRList list;
    list.add (cidr);
    CIDRAddress addr;

    zconfig_t *cfg = zconfig_load ("/etc/default/fty.cfg");
    zactor_t *ds = device_scan_new (cfg);
    while (list.next (addr)) {
        zstr_sendx (ds, "SCAN", addr.toString().c_str (), NULL);
        zmsg_t *result = zmsg_recv (ds);
        zmsg_print (result);
        zmsg_destroy (&result);
    }
}


//  --------------------------------------------------------------------------
//  Destroy the range_scan

void
range_scan_destroy (range_scan_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        range_scan_t *self = *self_p;
        //  Free class properties here
        zstr_free (&self->range);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}

void
range_scan_actor (zsock_t *pipe, void *args)
{
    zsock_signal (pipe, 0);
    range_scan_args_t *params;
    {
        // args check
        params = (range_scan_args_t *)args;
        if (! params || !params->range || !params->config) {
            zsys_error ("Scanning range not defined!");
            zstr_send (pipe, "DONE");
            return;
        }
        CIDRAddress addrcheck (params->range);
        if (!addrcheck.valid ()) {
            zsys_error ("Address range (%s) is not valid!", params->range);
            zstr_send (pipe, "DONE");
            return;
        }
        if (addrcheck.protocol () != 4) {
            zsys_error ("Scanning is not supported for such range (%s)!", params->range);
            zstr_send (pipe, "DONE");
            return;
        }
    }
    range_scan_t *self = range_scan_new (params->range);
    zconfig_t *config = zconfig_load (params->config);
    if (!config) {
        zsys_error ("failed to load config file %s", params->config);
        config = zconfig_new ("root", NULL);
    }
    CIDRList list;
    list.add (range_scan_range (self));
    CIDRAddress addr;

    zactor_t *device_actor = zactor_new (device_scan_actor, config);
    zpoller_t *poller = zpoller_new (pipe, device_actor, NULL);

    bool dosomething = list.next (addr);
    self->cursor = 1;
    if (dosomething) {
        zsys_debug ("scanning %s", addr.toString().c_str());
        zstr_sendx (device_actor, "SCAN", addr.toString().c_str(), NULL);
    }
    while (!zsys_interrupted && dosomething) {
        void *which = zpoller_wait (poller, 1000);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            if (msg) {
                char *cmd = zmsg_popstr (msg);
                if (cmd) {
                    if (streq (cmd, "$TERM")) {
                        zstr_free (&cmd);
                        zactor_destroy (&device_actor);
                        zmsg_destroy (&msg);
                        break;
                    }
                    zstr_free (&cmd);
                }
                zmsg_destroy (&msg);
            }
        }
        else if (which == NULL){
            // timeout
        }
        else {
            // from device actor
            zmsg_t *msg = zmsg_recv (which);
            if (msg) {
                zmsg_print (msg);
                zmsg_send (&msg, pipe);
                zmsg_destroy (&msg);
                dosomething = list.next (addr);
                self->cursor++;
                zstr_sendm (pipe, "PROGRESS");
                zstr_sendf (pipe, "%" PRId32, range_scan_progress (self));
                if (dosomething) {
                    zsys_debug ("scanning %s", addr.toString().c_str());
                    zstr_sendx (device_actor, "SCAN", addr.toString().c_str(), NULL);
                } else {
                    break;
                }
            } else {
                // strange failure
                break;
            }
        }
    }
    zconfig_destroy (&config);
    zactor_destroy (&device_actor);
    zstr_send (pipe, "DONE");
    range_scan_destroy (&self);
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
range_scan_test (bool verbose)
{
    printf (" * range_scan: ");

    //  @selftest
    //  Simple create/destroy test
    range_scan_t *self = range_scan_new ("127.0.0.0/24");
    assert (self);
    assert (self->size == 256);
    self->cursor = 128;
    assert (range_scan_progress (self) == 50);
    range_scan_destroy (&self);
    //  @end
    printf ("OK\n");
}
