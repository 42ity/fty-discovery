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
};

//  --------------------------------------------------------------------------
//  ftydiscovery actor

void
ftydiscovery_actor (zsock_t *pipe, void *args)
{
    ftydiscovery_t *self = ftydiscovery_new();
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (self->mlm), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, -1);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            if (msg) {
                char *cmd = zmsg_popstr (msg);
                if (cmd) {
                    if (streq (cmd, "$TERM")) {
                        zstr_free (&cmd);
                        zmsg_destroy (&msg);
                        break;
                    }
                    zstr_free (&cmd);
                }
                else if (streq (cmd, "BIND")) {
                    char *endpoint = zmsg_popstr (msg);
                    char *myname = zmsg_popstr (msg);
                    assert (endpoint && myname);
                    mlm_client_connect (self->mlm, endpoint, 5000, myname);
                    zstr_free (&endpoint);
                    zstr_free (&myname);
                }
                zmsg_destroy (&msg);
            }
        }
        else if (which == mlm_client_msgpipe (self->mlm)) {
            zmsg_t *msg = mlm_client_recv (self->mlm);
            zmsg_destroy (&msg);
        }
    }

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
    return self;
}

void
ftydiscovery_destroy (ftydiscovery_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        ftydiscovery_t *self = *self_p;
        //  Free class properties here
        mlm_client_destroy (&self->mlm);
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
