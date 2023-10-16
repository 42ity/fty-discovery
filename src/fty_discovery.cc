/*  =========================================================================
    fty_discovery - Agent performing device discovery in network

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

#include "fty_discovery_server.h"
#include <fty_common.h>
#include <fty_log.h>

int main(int argc, char* argv[])
{
    bool        verbose = false;
    bool        agent   = false;
    const char* range   = NULL;
    const char* config  = FTY_DISCOVERY_CFG_FILE;
    ManageFtyLog::setInstanceFtylog(FTY_DISCOVERY_ACTOR_NAME);

    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq(argv[argn], "--help") || streq(argv[argn], "-h")) {
            puts("fty-discovery [options] ...");
            puts("  --verbose / -v         verbose output");
            puts("  --help / -h            this information");
            puts("  --agent / -a           stay running, listen to rest api commands");
            puts("  --range / -r           scan this range (192.168.1.0/24 format). If -a and -r are not");
            puts("                         present, scan of attached networks is performed (localscan)");
            printf("  --config / -c         agent config file [%s]\n", FTY_DISCOVERY_CFG_FILE);
            return 0;
        } else if (streq(argv[argn], "--verbose") || streq(argv[argn], "-v")) {
            verbose = true;
        } else if (streq(argv[argn], "--agent") || streq(argv[argn], "-a")) {
            agent = true;
        } else if (streq(argv[argn], "--range") || streq(argv[argn], "-r")) {
            ++argn;
            if (argn < argc) {
                range = argv[argn];
            }
        } else if (streq(argv[argn], "--config") || streq(argv[argn], "-c")) {
            ++argn;
            if (argn < argc) {
                config = argv[argn];
            }
        } else {
            printf("Unknown option: %s\n", argv[argn]);
            return 1;
        }
    }
    std::string logConfigFile;
    zconfig_t*  zconf = zconfig_load(config);
    if (zconf) {
        auto val = std::string(zconfig_get(zconf, "discovery/protocols", "none"));

        if (!val.compare("none")) {
            zconfig_put(zconf, "discovery/protocols", "");
            int result = zconfig_save(zconf, config);
            if (result != 0) {
                log_error("Impossible to save the config file <%s>, error: %i", config, result);
            }
        }

        val = std::string(zconfig_get(zconf, "disabled", "none"));

        if (!val.compare("none")) {
            zconfig_put(zconf, "disabled", "");
            zconfig_put(zconf, "disabled/scans_disabled", "");
            zconfig_put(zconf, "disabled/ips_disabled", "");
            int result = zconfig_save(zconf, config);
            if (result != 0) {
                log_error("Impossible to save the config file <%s>, error: %i", config, result);
            }
        } else {
            val = std::string(zconfig_get(zconf, "disabled/scans_disabled", "none"));
            if (!val.compare("none")) {
                zconfig_put(zconf, "disabled/scans_disabled", "");
                int result = zconfig_save(zconf, config);
                if (result != 0) {
                    log_error("Impossible to save the config file <%s>, error: %i", config, result);
                }
            }
            val = std::string(zconfig_get(zconf, "disabled/ips_disabled", "none"));
            if (!val.compare("none")) {
                zconfig_put(zconf, "disabled/ips_disabled", "");
                int result = zconfig_save(zconf, config);
                if (result != 0) {
                    log_error("Impossible to save the config file <%s>, error: %i", config, result);
                }
            }
        }

        logConfigFile = std::string(zconfig_get(zconf, "log/config", "/etc/fty/ftylog.cfg"));
        if (!logConfigFile.empty()) {
            ManageFtyLog::getInstanceFtylog()->setConfigFile(logConfigFile);
        } else
            log_error("configuration not loaded %s", logConfigFile.c_str());
        zconfig_destroy(&zconf);
    }

    if (verbose)
        ManageFtyLog::getInstanceFtylog()->setVeboseMode();

    zsys_init();
    DBConn::dbpath();
    log_debug("fty_discovery - range: %s, agent %i", range ? range : "none", agent);

    // configure actor
    zactor_t* discovery_server = zactor_new(fty_discovery_server, NULL);
    if (agent) {
        zstr_sendx(discovery_server, REQ_BIND, FTY_DISCOVERY_ENDPOINT, FTY_DISCOVERY_ACTOR_NAME, NULL);
    } else {
        char* name = zsys_sprintf("%s.%i", FTY_DISCOVERY_ACTOR_NAME, getpid());
        zstr_sendx(discovery_server, REQ_BIND, FTY_DISCOVERY_ENDPOINT, name, NULL);
        zstr_free(&name);
    }
    zstr_sendx(discovery_server, REQ_CONFIG, config, NULL);
    zstr_sendx(discovery_server, REQ_CONSUMER, FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    if (range)
        zstr_sendx(discovery_server, REQ_SCAN, range, NULL);
    else if (!agent) {
        zstr_sendx(discovery_server, REQ_LOCALSCAN, NULL);
    }

    // main loop
    while (!zsys_interrupted) {
        zmsg_t* msg = zmsg_recv(discovery_server);
        if (msg) {
            char* cmd = zmsg_popstr(msg);
            log_debug("main: %s command received", cmd ? cmd : "(null)");
            if (cmd) {
                if (!agent && streq(cmd, REQ_DONE)) {
                    zstr_free(&cmd);
                    zmsg_destroy(&msg);
                    break;
                }
                zstr_free(&cmd);
            }
            zmsg_destroy(&msg);
        }
    }
    zactor_destroy(&discovery_server);
    return 0;
}
