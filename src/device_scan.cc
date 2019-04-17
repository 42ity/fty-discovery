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
#include <algorithm>
bool device_scan_scan (zlist_t *listScans, discovered_devices_t *devices, zsock_t *pipe, const nutcommon::KeyValues *mappings)
{
    CIDRList *listAddr = (CIDRList *) zlist_first(listScans);
    zpoller_t *poller = zpoller_new(pipe, NULL);
    std::vector<zactor_t *> listActor;
    bool term = false;
    while(listAddr != NULL) {
        zlist_t *args = zlist_new();
        zlist_append(args, listAddr);
        zlist_append(args, devices);
        zlist_append(args, const_cast<void*>(static_cast<const void*>(mappings)));
        zactor_t *scan_nut = zactor_new (scan_nut_actor, args);
        zpoller_add(poller, scan_nut);
        listActor.push_back(scan_nut);
        listAddr = (CIDRList *) zlist_next(listScans);
    }

    size_t number_end_actor = 0;

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, 5000);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            if(msg) {
                char *cmd = zmsg_popstr (msg);
                if(cmd) {
                    if(streq (cmd, "$TERM")) {
                        zstr_free(&cmd);
                        zmsg_destroy (&msg);
                        term = true;
                        break;
                    }
                    zstr_free(&cmd);
                }
                zmsg_destroy (&msg);
            }
        } else if (which == NULL) {
            //time out, nothing to do
        }else { //any of scan_nut_actor
            zmsg_t *msg = zmsg_recv (which);
            if (msg) {
                char *cmd = zmsg_popstr (msg);
                if (cmd) {
                    if (streq (cmd, "$TERM")) {
                        zstr_free (&cmd);
                        zmsg_destroy (&msg);
                        break;
                    } else if (streq (cmd, REQ_DONE)) {
                        zstr_free (&cmd);
                        zmsg_destroy (&msg);
                        auto end_actor = std::find(listActor.begin(), listActor.end(), (zactor_t *) which );
                        if (end_actor == listActor.end()) {
                            //ERROR ? Normaly can't happened
                            log_error("%s Error : actor not in the actor list", __FUNCTION__);
                        } else {
                            listActor.erase(end_actor);
                        }
                        zpoller_remove(poller, which);
                        zactor_destroy((zactor_t **)&which);
                        if(listActor.empty())
                            break;
                        else if(number_end_actor >= listActor.size()) {
                            for(auto actor : listActor) {
                                zmsg_t* msg_cont = zmsg_new();
                                zmsg_pushstr(msg_cont, CMD_CONTINUE);
                                zmsg_send(&msg_cont, actor);
                            }
                            number_end_actor = 0;
                        }
                    } else if (streq (cmd, INFO_READY)) {
                        number_end_actor++;
                        if(number_end_actor >= listActor.size()) {
                            for(auto actor : listActor) {
                                zmsg_t* msg_cont = zmsg_new();
                                zmsg_pushstr(msg_cont, CMD_CONTINUE);
                                zmsg_send(&msg_cont, actor);
                            }
                            number_end_actor = 0;
                        }
                        zstr_free (&cmd);
                        zmsg_destroy (&msg);
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
        }
    }

    for(auto actor : listActor) {
        zactor_destroy(&actor);
    }

    listActor.clear();
    zlist_destroy(&listScans);
    log_debug("QUIT device scan scan");
    zpoller_destroy (&poller);
    return term;
}

//  --------------------------------------------------------------------------
//  One device scan actor

void
device_scan_actor (zsock_t *pipe, void *args)
{
    zsock_signal (pipe, 0);
    if (! args ) {
        log_error ("dsa: actor created without parameters");
        return;
    }

    zlist_t *argv = (zlist_t *)args;

    if (!argv || zlist_size(argv) != 3) {
        log_error ("dsa: actor created without config");
        zlist_destroy(&argv);
        return;
    }
    zlist_t *listScans = (zlist_t *) zlist_first(argv);
    if(zlist_size(listScans) < 1) {
        log_error ("dsa: actor created without any scans");
        zlist_destroy(&argv);
        zlist_destroy(&listScans);
        return;
    }
    discovered_devices_t *devices = (discovered_devices_t*) zlist_next(argv);
    const nutcommon::KeyValues *mappings = (const nutcommon::KeyValues*) zlist_next(argv);

    log_debug ("dsa: device scan actor created");
    while (!zsys_interrupted) {
        zmsg_t *msg = zmsg_recv (pipe);
        if (msg) {
            char *cmd = zmsg_popstr (msg);
            if (streq (cmd, "$TERM")) {
                zstr_free (&cmd);
                break;
            }
            else if (streq (cmd, "SCAN")) {
                zstr_free (&cmd);
                zmsg_destroy(&msg);
                zconfig_t *config = zconfig_load(getDiscoveryConfigFile().c_str());
                if(!config) {
                    log_error("failed to load config file %s", getDiscoveryConfigFile().c_str());
                    config = zconfig_new("root", NULL);
                }
                char* strNbPool = zconfig_get(config, CFG_PARAM_MAX_SCANPOOL_NUMBER, DEFAULT_MAX_SCANPOOL_NUMBER);
                const size_t number_max_pool = std::stoi(strNbPool);
                zconfig_destroy(&config);
                bool stopped = false;
                while(!stopped && zlist_size(listScans) > 0) {
                    size_t number_of_scans = 0;
                    zlist_t *scanPool = zlist_new();
                    while(number_of_scans < number_max_pool && zlist_size(listScans) > 0) {
                        zlist_append(scanPool, zlist_pop(listScans));
                        number_of_scans++;
                    }
                    stopped = device_scan_scan(scanPool, devices, pipe, mappings);
                }
                zlist_destroy(&listScans);

                zmsg_t *end = zmsg_new();
                zmsg_pushstr(end, REQ_DONE);
                zmsg_send(&end, pipe);
                break;
            }
            zmsg_destroy (&msg);
        }
    }
    log_debug ("dsa: device scan actor exited");
    zlist_destroy(&argv);
}


//  --------------------------------------------------------------------------
//  Create a new device_scan actor

zactor_t *
device_scan_new (zlist_t *arg0, discovered_devices_t *arg1, const nutcommon::KeyValues *mappings)
{
    zlist_t *args = zlist_new();
    zlist_append(args, arg0);
    zlist_append(args, arg1);
    zlist_append(args, const_cast<void*>(static_cast<const void*>(mappings)));
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

    zactor_t *self = device_scan_new(nullptr, nullptr, nullptr);
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
