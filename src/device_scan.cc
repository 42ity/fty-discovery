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

zmsg_t * device_scan_scan (const char *addr, zconfig_t *config, discovered_devices_t *devices)
{
    fty_proto_t *asset = fty_proto_new (FTY_PROTO_ASSET);
    bool found = false;
    fty_proto_ext_insert (asset, "ip.1", "%s", addr);

    found |= scan_nut (asset, addr, config, devices);
    scan_dns (asset, addr, config);

    if (found) {
        const char *mfr = fty_proto_ext_string (asset, "manufacturer", NULL);
        const char *model = fty_proto_ext_string (asset, "model", NULL);
        const char *serial = fty_proto_ext_string (asset, "serial_no", NULL);
        if (mfr && model && serial) {
            fty_uuid_t *uuid = fty_uuid_new ();
            fty_proto_ext_insert (asset, "uuid", "%s", fty_uuid_calculate (uuid, mfr, model, serial));
            fty_uuid_destroy (&uuid);
        }
        zmsg_t *result = fty_proto_encode (&asset);
        zmsg_pushstr (result, "FOUND");
        return result;
    } else {
        fty_proto_destroy (&asset);
        zmsg_t *result = zmsg_new ();
        zmsg_pushstr (result, "NOTFOUND");
        return result;
    }
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
    
    if (!argv || zlist_size(argv) != 2) {
        zsys_error ("dsa: actor created without config");
        zlist_destroy(&argv);
        return;
    }
    
    zconfig_t *config = (zconfig_t *) zlist_head(argv);
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
                char *addr = zmsg_popstr (msg);
                zsys_debug ("ds: scan request for %s", addr ? addr : "(null)");
                zmsg_t *reply = device_scan_scan (addr, config, devices);
                zmsg_send (&reply, pipe);
                zstr_free (&addr);
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
device_scan_new (zconfig_t *arg1, discovered_devices_t *arg2)
{
    zlist_t *args = zlist_new();
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

    zactor_t *self = device_scan_new (NULL, NULL);
    assert (self);

    // zconfig /etc/default/fty.cfg
    // snmp
    //    community
    //        0 = "public"
    zconfig_t *cfg = zconfig_new ("root", NULL);
    zconfig_put (cfg, "/snmp/community/0", "public");
    zconfig_put (cfg, "/snmp/community/1", "private");

    zmsg_t *msg = device_scan_scan ("10.231.107.40", cfg, NULL);
    zmsg_destroy (&msg);

    zconfig_destroy (&cfg);
    zactor_destroy (&self);
    //  @end
    printf ("OK\n");
}
