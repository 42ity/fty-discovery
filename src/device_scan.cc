/*  =========================================================================
    device_scan - Perform one IP address scan

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
    device_scan - Perform one IP address scan
@discuss
@end
*/

#include "fty_discovery_classes.h"
void device_scan_scan (CIDRList *listAddr, zconfig_t *config, discovered_devices_t *devices, zsock_t *pipe)
{
    zlist_t *args = zlist_new();
    zlist_append(args, listAddr);
    zlist_append(args, config);
    zlist_append(args, devices);
    zactor_t *scan_nut = zactor_new (scan_nut_actor, args);
    zpoller_t *poller = zpoller_new (pipe, scan_nut, NULL);
    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, 5000);
        if(which == scan_nut) {
            zmsg_t *msg = zmsg_recv (scan_nut);
            if (msg) {
                char *cmd = zmsg_popstr (msg);
                if (cmd) {
                    if (streq (cmd, "$TERM") || streq (cmd, "DONE")) {
                        zstr_free (&cmd);
                        zmsg_destroy (&msg);
                        break;
                    } else if(streq (cmd, REQ_FOUND)) {
                        zmsg_t *reply = zmsg_dup(msg);
                        zmsg_pushstr(reply, REQ_FOUND);
                        zmsg_send (&reply, pipe);
                        zstr_free (&cmd);
                    }
                    zstr_free (&cmd);
                }
                zmsg_destroy (&msg);
            }
        } else if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            if(msg) {
                char *cmd = zmsg_popstr (msg);
                if(cmd) {
                    if(streq (cmd, "$TERM")) {
                        zstr_free(&cmd);
                        zmsg_destroy (&msg);
                        break;
                    }
                    zstr_free(&cmd);
                }
                zmsg_destroy (&msg);
            }
        }
    }
    zsys_debug("QUIT device scan scan");
    zpoller_destroy (&poller);
    zactor_destroy (&scan_nut);
}

//  --------------------------------------------------------------------------
//  One device scan actor

void
device_scan_actor (zsock_t *pipe, void *args)
{
    zsock_signal (pipe, 0);
    if (! args ) {
        zsys_error ("dsa: actor created without parameters");
        return;
    }
    
    zlist_t *argv = (zlist_t *)args;
    
    if (!argv || zlist_size(argv) != 3) {
        zsys_error ("dsa: actor created without config");
        zlist_destroy(&argv);
        return;
    }
    CIDRList *listAddr = (CIDRList *) zlist_first(argv);
    zconfig_t *config = (zconfig_t *) zlist_next(argv);
    discovered_devices_t *devices = (discovered_devices_t*) zlist_tail(argv);

    zsys_debug ("dsa: device scan actor created");
    while (!zsys_interrupted) {
        zmsg_t *msg = zmsg_recv (pipe);
        if (msg) {
            char *cmd = zmsg_popstr (msg);
            if (streq (cmd, "$TERM")) {
                zstr_free (&cmd);
                break;
            }
            else if (streq (cmd, "SCAN")) {
                device_scan_scan(listAddr, config, devices, pipe);
                zstr_free (&cmd);
                zmsg_destroy(&msg);
                zmsg_t *end = zmsg_new();
                zmsg_pushstr(end, "DONE");
                zmsg_send(&end, pipe);
                break;
            }
            zmsg_destroy (&msg);
        }
    }
    zsys_debug ("dsa: device scan actor exited");
    zlist_destroy(&argv);
}


//  --------------------------------------------------------------------------
//  Create a new device_scan actor

zactor_t *
device_scan_new (CIDRList *arg0, zconfig_t *arg1, discovered_devices_t *arg2)
{
    zlist_t *args = zlist_new();
    zlist_append(args, arg0);
    zlist_append(args, arg1);
    zlist_append(args, arg2);
    return zactor_new (device_scan_actor, (void *)args);
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
device_scan_test (bool verbose)
{
    printf (" * device_scan: ");

    //  @selftest
    //  Simple create/destroy test

    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase (asert) to make compilers happy.
    const char *SELFTEST_DIR_RO = "src/selftest-ro";
    const char *SELFTEST_DIR_RW = "src/selftest-rw";
    assert (SELFTEST_DIR_RO);
    assert (SELFTEST_DIR_RW);
    // Uncomment these to use C++ strings in C++ selftest code:
    //std::string str_SELFTEST_DIR_RO = std::string(SELFTEST_DIR_RO);
    //std::string str_SELFTEST_DIR_RW = std::string(SELFTEST_DIR_RW);
    //assert ( (str_SELFTEST_DIR_RO != "") );
    //assert ( (str_SELFTEST_DIR_RW != "") );
    // NOTE that for "char*" context you need (str_SELFTEST_DIR_RO + "/myfilename").c_str()

    zactor_t *self = device_scan_new (NULL, NULL, NULL);
    assert (self);

    // zconfig /etc/default/fty.cfg
    // snmp
    //    community
    //        0 = "public"
    zconfig_t *cfg = zconfig_new ("root", NULL);
    zconfig_put (cfg, "/snmp/community/0", "public");
    zconfig_put (cfg, "/snmp/community/1", "private");

    // TODO
    //zmsg_t *msg = device_scan_scan ("10.231.107.40", cfg, NULL);
    //zmsg_destroy (&msg);

    zconfig_destroy (&cfg);
    zactor_destroy (&self);
    //  @end
    printf ("OK\n");
}
