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
#include <cxxtools/split.h>
#include <cxxtools/regex.h>

std::pair<std::string, std::string> nut_key_and_value (std::string &line)
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

void nut_output_to_fty_message (fty_proto_t *asset, std::vector <std::string> output)
{
    for (auto it: output) {
        std::vector<std::string> lines;
        cxxtools::split("\n", it, std::back_inserter(lines));
        for (auto l: lines) {
            auto parsed = nut_key_and_value (l);
            if (parsed.first == "driver") {
                fty_proto_aux_insert (asset, "type", "%s", "device");
                if (parsed.first.find ("ups") != std::string::npos) {
                    fty_proto_aux_insert (asset, "subtype", "%s", "ups");
                }
                else if (parsed.first.find ("pdu") != std::string::npos) {
                    fty_proto_aux_insert (asset, "subtype", "%s", "epdu");
                }
                else if (parsed.first.find ("sts") != std::string::npos || parsed.first.find ("ats") != std::string::npos) {
                    fty_proto_aux_insert (asset, "subtype", "%s", "sts");
                }
            }
            else if (parsed.first == "desc") {
                fty_proto_ext_insert (asset, "description", "%s", parsed.second.c_str());
            }
        }
    }
}

int nut_scan (fty_proto_t *asset, const char *address, zconfig_t *config)
{
    // check IP address syntax
    CIDRAddress addr(address);
    if (! addr.valid ()) return 0;

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
    if (communities.empty ()) {
        communities.push_back ("public");
    }


    // try communities
    for (auto it: communities) {
        std::vector<std::string> output;
        nut_scan_snmp ("device", addr, it, false, output);
        if (! output.empty ()) {
            nut_output_to_fty_message (asset, output);
            return 1;
        }
    }
    // try xml
    {
        std::vector<std::string> output;
        nut_scan_xml_http ("device", addr, output);
        if (! output.empty ()) {
            nut_output_to_fty_message (asset, output);
            return 1;
        }
    }
    return 0;
}

zmsg_t * device_scan_scan (const char *addr, zconfig_t *config)
{
    zmsg_t *result = zmsg_new ();
    fty_proto_t *asset = fty_proto_new (FTY_PROTO_ASSET);

    nut_scan (asset, addr, config);
    fty_proto_destroy (&asset);
    zmsg_pushstr (result, "NOTFOUND");
    return result;
}

//  --------------------------------------------------------------------------
//  One device scan actor

void
device_scan_actor (zsock_t *pipe, void *args)
{
    zsock_signal (pipe, 0);
    if (! args) return;
    zconfig_t *config = (zconfig_t *)args;

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
                zmsg_t *reply = device_scan_scan (addr, config);
                zmsg_send (&reply, pipe);
                zstr_free (&addr);
            }
            zmsg_destroy (&msg);
        }
    }
}


//  --------------------------------------------------------------------------
//  Create a new device_scan actor

zactor_t *
device_scan_new (zconfig_t *args)
{
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

    zactor_t *self = device_scan_new (NULL);
    assert (self);

    // zconfig /etc/default/fty.cfg
    // snmp
    //    community
    //        0 = "public"
    zconfig_t *cfg = zconfig_new ("root", NULL);
    zconfig_put (cfg, "/snmp/community/0", "public");
    zconfig_put (cfg, "/snmp/community/1", "private");

    zmsg_t *msg = device_scan_scan ("10.231.107.40", cfg);
    zmsg_destroy (&msg);

    zconfig_destroy (&cfg);
    zactor_destroy (&self);
    //  @end
    printf ("OK\n");
}
