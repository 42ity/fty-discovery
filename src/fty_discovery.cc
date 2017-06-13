/*  =========================================================================
    fty_discovery - Agent performing device discovery in network

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
    fty_discovery - Agent performing device discovery in network
@discuss
@end
*/

#include "fty_discovery_classes.h"

static const char *ACTOR_NAME = "fty-discovery";
static const char *ENDPOINT = "ipc://@/malamute";

int main (int argc, char *argv [])
{
    bool verbose = false;
    bool agent = false;
    const char *range = NULL;
    const char *config = "/etc/default/fty.cfg";

    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-discovery [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            puts ("  --agent / -a           stay running, listen to rest api commands");
            puts ("  --range / -r           scan this range (192.168.1.0/24 format)");
            puts ("  --config / -c          config file [/etc/default/fty.cfg]");
            return 0;
        }
        else if (streq (argv [argn], "--verbose") ||  streq (argv [argn], "-v")) {
            verbose = true;
        }
        else if (streq (argv [argn], "--agent") ||  streq (argv [argn], "-a")) {
            agent = true;
        }
        else if (streq (argv [argn], "--range") ||  streq (argv [argn], "-r")) {
            ++argn;
            if (argn < argc) {
                range = argv [argn];
            }
        }
        else if (streq (argv [argn], "--config") ||  streq (argv [argn], "-c")) {
            ++argn;
            if (argn < argc) {
                config = argv [argn];
            }
        }
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    zsys_init ();
    if (verbose) {
        zsys_info ("fty_discovery - Agent performing device discovery in network");
        zsys_debug ("range: %s, agent %i", range ? range : "none", agent);
    }
    if (!agent && !range) {
        zsys_error ("Scanning range not set");
        return 1;
    }

    // configure actor
    zactor_t *discovery = zactor_new (ftydiscovery_actor, NULL);
    if (! agent) {
        zstr_sendx (discovery, "BIND", ENDPOINT, ACTOR_NAME, NULL);
    } else {
        char *name = zsys_sprintf ("%s.%i", ACTOR_NAME, getpid());
        zstr_sendx (discovery, "BIND", ENDPOINT, name, NULL);
        zstr_free (&name);
    }
    zstr_sendx (discovery, "CONFIG", config, NULL);
    if (range) zstr_sendx (discovery, "SCAN", range, NULL);

    // main loop
    while (!zsys_interrupted) {
        zmsg_t *msg = zmsg_recv (discovery);
        if (msg) {
            char *cmd = zmsg_popstr (msg);
            zsys_debug ("main: %s command received", cmd ? cmd : "(null)");
            if (cmd) {
                if (!agent && streq (cmd, "DONE")) {
                    zstr_free (&cmd);
                    zmsg_destroy (&msg);
                    break;
                }
                zstr_free (&cmd);
            }
            zmsg_destroy (&msg);
        }
    }
    zactor_destroy (&discovery);
    return 0;
}
