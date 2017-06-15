/*  =========================================================================
    ftydiscovery - Manages discovery requests, provides feedback

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
    ftydiscovery - Manages discovery requests, provides feedback
@discuss
@end
*/

#include "fty_discovery_classes.h"

//  Structure of our class

struct _ftydiscovery_t {
    mlm_client_t *mlm;
    zactor_t *scanner;
    assets_t *assets;
};

//  --------------------------------------------------------------------------
//  send create asses if it is new
void
ftydiscovery_create_asset (ftydiscovery_t *self, zmsg_t **msg_p)
{
    if (!self || !msg_p) return;
    if (!is_fty_proto (*msg_p)) return;

    fty_proto_t *asset = fty_proto_decode (msg_p);
    fty_proto_print (asset);
    const char *ip = fty_proto_ext_string (asset, "ip.1", NULL);
    if (!ip) return;

    if (assets_find (self->assets, "ip", ip)) {
        // TODO: check also calculated guid
        zsys_info ("Asset with IP address %s already exists", ip);
        return;
    }

    fty_proto_aux_insert (asset, "status", "%s", "nonactive");

    // set name
    const char *name = fty_proto_ext_string (asset, "hostname", NULL);
    if (!name) name = fty_proto_aux_string (asset, "subtype", NULL);
    if (!name) name = ip; // for admin even IP is better than nothing or uuid
    fty_proto_ext_insert (asset, "name", "%s", name);

    zsys_info ("Found new asset %s with IP address %s", name, ip);
    fty_proto_set_operation (asset, "create");
    zmsg_t *msg = fty_proto_encode (&asset);
    mlm_client_sendto (self->mlm, "asset-agent", "ASSET_MANIPULATION", NULL, 1000, &msg);
}

//  --------------------------------------------------------------------------
//  ftydiscovery actor

void
ftydiscovery_actor (zsock_t *pipe, void *args)
{
    ftydiscovery_t *self = ftydiscovery_new();
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (self->mlm), NULL);
    zactor_t *range_scanner = NULL;
    zsock_signal (pipe, 0);
    range_scan_args_t range_scan_config;
    range_scan_config.config = NULL;
    range_scan_config.range = NULL;
    zmsg_t *range_stack = zmsg_new ();

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, 5000);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            if (msg) {
                char *cmd = zmsg_popstr (msg);
                zsys_debug ("Pipe command %s received", cmd ? cmd : "(null)");
                if (cmd) {
                    if (streq (cmd, "$TERM")) {
                        zstr_free (&cmd);
                        zmsg_destroy (&msg);
                        break;
                    }
                    else if (streq (cmd, "BIND")) {
                        char *endpoint = zmsg_popstr (msg);
                        char *myname = zmsg_popstr (msg);
                        assert (endpoint && myname);
                        mlm_client_connect (self->mlm, endpoint, 5000, myname);
                        zstr_free (&endpoint);
                        zstr_free (&myname);
                    }
                    else if (streq (cmd, "CONSUMER")) {
                        char *stream = zmsg_popstr (msg);
                        char *pattern = zmsg_popstr (msg);
                        assert (stream && pattern);
                        mlm_client_set_consumer (self->mlm, stream, pattern);
                        zstr_free (&stream);
                        zstr_free (&pattern);
                        // ask for assets now
                        zmsg_t *republish = zmsg_new ();
                        zmsg_addstr (republish, "$all");
                        mlm_client_sendto (self->mlm, "asset-agent", "REPUBLISH", NULL, 1000, &republish);
                    }
                    else if (streq (cmd, "CONFIG")) {
                        zstr_free (&range_scan_config.config);
                        range_scan_config.config = zmsg_popstr (msg);
                    }
                    else if (streq (cmd, "SCAN")) {
                        if (range_scanner) {
                            zpoller_remove (poller, range_scanner);
                            zactor_destroy (&range_scanner);
                        }
                        zstr_free (&range_scan_config.range);
                        range_scan_config.range = zmsg_popstr (msg);
                    }
                    zstr_free (&cmd);
                }
                zmsg_destroy (&msg);
            }
        }
        else if (which == mlm_client_msgpipe (self->mlm)) {
            zmsg_t *msg = mlm_client_recv (self->mlm);
            if (is_fty_proto (msg)) {
                fty_proto_t *fmsg = fty_proto_decode (&msg);
                assets_put (self->assets, &fmsg);
                fty_proto_destroy (&fmsg);
            } else {
                // handle REST API requests
                char *cmd = zmsg_popstr (msg);
                if (cmd) {
                    // RUNSCAN
                    // <uuid>
                    // <config> (can be empty - then default config is used)
                    // <range>
                    if (streq (cmd, "RUNSCAN")) {
                        char *zuuid = zmsg_popstr (msg);
                        zmsg_t *reply = zmsg_new ();
                        zmsg_addstr (reply, zuuid);

                        zstr_free (&range_scan_config.config);
                        range_scan_config.config = zmsg_popstr (msg);
                        if (streq (range_scan_config.config, ""))
                            range_scan_config.config = strdup ("/etc/default/fty.cfg");
                        zstr_free (&range_scan_config.range);
                        range_scan_config.range = zmsg_popstr (msg);

                        if (range_scan_config.range) {
                            zsys_debug ("Range scanner requested for %s with config file %s", range_scan_config.range, range_scan_config.config);
                            // create range scanner
                            if (range_scanner) {
                                zpoller_remove (poller, range_scanner);
                                zactor_destroy (&range_scanner);
                            }
                            range_scanner = zactor_new (range_scan_actor, &range_scan_config);
                            zpoller_add (poller, range_scanner);

                            zmsg_addstr (reply, "OK");
                        }
                        else
                            zmsg_addstr (reply, "ERROR");
                        mlm_client_sendto (self->mlm, mlm_client_sender (self->mlm), mlm_client_subject (self->mlm), mlm_client_tracker (self->mlm), 1000, &reply);
                    }
                    zstr_free (&cmd);
                }
            }
            zmsg_destroy (&msg);
        }
        else if (range_scanner && which == range_scanner) {
            zmsg_t *msg = zmsg_recv (range_scanner);
            zsys_debug ("Range scanner message received");
            if (msg) {
                zmsg_print (msg);
                char *cmd = zmsg_popstr (msg);
                zsys_debug ("Range scanner message: %s", cmd);
                if (cmd) {
                    if (streq (cmd, "DONE")) {
                        zstr_send (pipe, "DONE");
                    }
                    else if (streq (cmd, "FOUND")) {
                        ftydiscovery_create_asset (self, &msg);
                    }
                    zstr_free (&cmd);
                }
                zmsg_destroy (&msg);
            }
        }
        // check that scanner is NULL && we have to do scan
        if (range_scan_config.range && !range_scanner) {
            if (zclock_mono () - assets_last_change (self->assets) > 5000) {
                // no asset change for last 5 secs => we can start range scan
                zsys_debug ("Range scanner start for %s with config file %s", range_scan_config.range, range_scan_config.config);
                // create range scanner
                // TODO: send list of IPs to skip
                range_scanner = zactor_new (range_scan_actor, &range_scan_config);
                zpoller_add (poller, range_scanner);
            }
        }
    }

    zstr_free (&range_scan_config.config);
    zstr_free (&range_scan_config.range);
    zmsg_destroy (&range_stack);
    zactor_destroy (&range_scanner);
    ftydiscovery_destroy (&self);
    zpoller_destroy (&poller);
}

//  --------------------------------------------------------------------------
//  Create a new ftydiscovery

ftydiscovery_t *
ftydiscovery_new ()
{
    ftydiscovery_t *self = (ftydiscovery_t *) zmalloc (sizeof (ftydiscovery_t));
    assert (self);
    //  Initialize class properties here
    self->mlm = mlm_client_new ();
    self->scanner = NULL;
    self->assets = assets_new ();
    return self;
}

void
ftydiscovery_destroy (ftydiscovery_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        ftydiscovery_t *self = *self_p;
        //  Free class properties here
        zactor_destroy (&self->scanner);
        mlm_client_destroy (&self->mlm);
        assets_destroy (&self->assets);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
ftydiscovery_test (bool verbose)
{
    printf (" * ftydiscovery: ");

    //  @selftest
    //  Simple create/destroy test
    zactor_t *self = zactor_new (ftydiscovery_actor, NULL);
    assert (self);
    zclock_sleep (500);
    zactor_destroy (&self);
    //  @end
    printf ("OK\n");
}
