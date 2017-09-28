/*  =========================================================================
    scan_nut - collect information from DNS

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
    scan_nut - collect information from DNS
@discuss
@end
*/

#include "fty_discovery_classes.h"

#include <cxxtools/split.h>
#include <cxxtools/regex.h>
#include <algorithm>

bool ip_present(discovered_devices_t *device_discovered, std::string ip);

// parse nut config line (key = "value")
std::pair<std::string, std::string> s_nut_key_and_value (std::string &line)
{
    cxxtools::Regex regname ("[a-zA-Z0-9]+");
    cxxtools::Regex regvalue ("\"[^\"]+\"");
    cxxtools::RegexSMatch match;

    if (! regname.match (line, match, 0)) return std::make_pair ("", "");
    std::string name = line.substr (match.offsetBegin (0), match.offsetEnd(0) - match.offsetBegin (0));

    if (! regvalue.match (line, match, 0)) return  std::make_pair ("", "");
    std::string value = line.substr (match.offsetBegin (0) + 1, match.offsetEnd(0) - match.offsetBegin (0) - 2);

    return std::make_pair (name, value);
}

void s_nut_output_to_fty_messages (std::vector <fty_proto_t *> *assets, std::vector<std::string> output, discovered_devices_t *devices)
{
    bool found = false;
    for (auto it: output) {
        std::vector<std::string> lines;
        fty_proto_t *asset = fty_proto_new(FTY_PROTO_ASSET);

        cxxtools::split("\n", it, std::back_inserter(lines));
        for (auto l: lines) {
            auto parsed = s_nut_key_and_value (l);
            if (parsed.first == "desc") {
                fty_proto_ext_insert (asset, "description", "%s", parsed.second.c_str());
            }
            else if (parsed.first == "port") {
                std::string ip;
                size_t pos = parsed.second.find("://");
                if(pos != std::string::npos)
                    ip = parsed.second.substr(pos+3);
                else
                    ip = parsed.second;
                if(ip_present(devices, ip)) {
                    found = false;
                    break;
                } else {
                    fty_proto_ext_insert (asset, "ip.1", "%s", ip.c_str());
                    fty_proto_aux_insert (asset, "type", "%s", "device");
                    found = true;
                }
            }
        }

        if(!found) {
            fty_proto_destroy(&asset);
        } else {
            assets->push_back(asset);
        }
        found = false;
    }
}

void
s_nut_dumpdata_to_fty_message (fty_proto_t *fmsg, std::map <std::string, std::string> &dump)
{
    if (! fmsg) return;

    static std::map <std::string, std::string> mapping = {
        {"device.model", "model"},
        {"ups.model", "model"},
        {"device.mfr", "manufacturer"},
        {"ups.mfr", "manufacturer"},
        {"device.serial", "serial_no"},
        {"device.description", "device.description"},
        {"device.contact", "device.contact"},
        {"device.location", "device.location"},
        {"device.part", "device.part"},
        {"ups.serial", "serial_no"},
        {"ups.firmware", "firmware"},
        {"battery.type", "battery.type"},
        {"input.phases", "phases.input"},
        {"output.phases", "phases.output"},
        {"outlet.count", "outlet.count"},
    };

    for (auto it: mapping) {
        auto item = dump.find (it.first);
        if (item != dump.end ()) {
            // item found
            fty_proto_ext_insert (fmsg, it.second.c_str (), "%s", item->second.c_str ());
        }
    }
    {
        // get type from dump is safer than parsing driver name
        auto item = dump.find ("device.type");
        if (item != dump.end ()) {
            const char *device = item->second.c_str ();
            if (streq (device, "pdu")) device = "epdu";
            if (streq (device, "ats")) device = "sts";
            fty_proto_aux_insert (fmsg, "subtype", "%s", device);
        }
    }
}

//
bool
ip_present(discovered_devices_t *device_discovered, std::string ip) {
    if(!device_discovered)
        return false;

    device_discovered->mtx_list.lock();
    char* c = (char*) zhash_first( device_discovered->device_list);

    while(c && !streq(c, ip.c_str())) {
        c = (char*) zhash_next( device_discovered->device_list);
    }

    bool present = (c != NULL);
    device_discovered->mtx_list.unlock();

    return present;
}

bool ask_actor_term(zsock_t *pipe) {
    zmsg_t *msg_stop = zmsg_recv_nowait(pipe);
    if(msg_stop) {
        char *cmd = zmsg_popstr (msg_stop);
        if(cmd && streq (cmd, "$TERM")) {
            zstr_free(&cmd);
            zmsg_destroy(&msg_stop);
            return true;
        }
        zstr_free(&cmd);
        zmsg_destroy(&msg_stop);
    }
    return false;
}

//  --------------------------------------------------------------------------
//  Scan IPs addresses using nut-scanner
void
scan_nut_actor(zsock_t *pipe, void *args)
{
    bool stop_now =false;
    zsock_signal (pipe, 0);
    if (! args ) {
        zsys_error ("%s : actor created without parameters", __FUNCTION__);
        return;
    }

    zlist_t *argv = (zlist_t *)args;
    if (!argv || zlist_size(argv) != 3) {
        zsys_error ("%s : actor created without config or devices list", __FUNCTION__);
        zlist_destroy(&argv);
        return;
    }

    CIDRList *listAddr = (CIDRList *) zlist_first(argv);
    zconfig_t *config = (zconfig_t *) zlist_next(argv);
    discovered_devices_t *devices = (discovered_devices_t*) zlist_tail(argv);
    if (!listAddr || !config || !devices) {
        zsys_error ("%s : actor created without config or devices list", __FUNCTION__);
        zlist_destroy(&argv);
        return;
    }

    std::vector<fty_proto_t *> listDiscovered;
    // read community names from cfg
    std::vector <std::string> communities;
    zconfig_t *section = zconfig_locate (config, "/snmp/community");
    if (section) {
        zconfig_t *item = zconfig_child (section);
        while (item) {
            communities.push_back (zconfig_value (item));
            item = zconfig_next (item);
        }
    }

    //take care of have always public community
    if (std::find(communities.begin(), communities.end(), "public") == communities.end()) {
        communities.push_back("public");
    }

    //try communities
    for (auto it:communities) {
        std::vector<std::string> output;
        nut_scan_multi_snmp ("device", listAddr->firstAddress(), listAddr->lastAddress(), it, false, output);
        if (! output.empty()) {
            s_nut_output_to_fty_messages(&listDiscovered , output, devices);

            for (auto asset:listDiscovered) {
                if(ask_actor_term(pipe)) stop_now = true;
                if(zsys_interrupted || stop_now) {
                    fty_proto_destroy(&asset);
                } else {
                    fty_proto_t *msg = asset;
                    std::string addr = fty_proto_ext_string(msg, "ip.1", "");

                    map_string_t nutdata;
                    if (nut_dumpdata_snmp_ups (addr, it,  nutdata) == 0) {
                        s_nut_dumpdata_to_fty_message (msg, nutdata);
                    }

                    zmsg_t *reply = fty_proto_encode (&msg);
                    zmsg_pushstr (reply, "FOUND");
                    zmsg_send (&reply, pipe);
                }
            }
            listDiscovered.clear();

            if(ask_actor_term(pipe)) stop_now = true;
            if(zsys_interrupted || stop_now)
                break;
        }
    }

    // try xml
    if(ask_actor_term(pipe)) stop_now = true;
    if(!zsys_interrupted && !stop_now){
        std::vector<std::string> output;
        nut_scan_multi_xml_http ("device", listAddr->firstAddress(), listAddr->lastAddress(), output);
        if (! output.empty ()) {
            s_nut_output_to_fty_messages (&listDiscovered , output, devices);

            for (auto asset:listDiscovered) {
                if(ask_actor_term(pipe)) stop_now = true;
                if(zsys_interrupted || stop_now) {
                    fty_proto_destroy(&asset);
                } else {
                    fty_proto_t *msg = asset;
                    std::string addr = fty_proto_ext_string(msg, "ip.1", "");

                    map_string_t nutdata;
                    if (nut_dumpdata_netxml_ups ("http://"+addr, nutdata) == 0) {
                        s_nut_dumpdata_to_fty_message (msg, nutdata);
                    }

                    zmsg_t *reply = fty_proto_encode (&msg);
                    zmsg_pushstr(reply, "FOUND");
                    zmsg_send (&reply, pipe);
                }
            }
            listDiscovered.clear();
        }
    }
    zmsg_t *reply = zmsg_new();
    zmsg_pushstr(reply, "DONE");
    zmsg_send (&reply, pipe);
    zlist_destroy(&argv);
    zsys_debug ("scan nut actor exited");
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
scan_nut_test (bool verbose)
{
    printf (" * scan_nut: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
