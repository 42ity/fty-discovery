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

void s_nut_output_to_fty_message (fty_proto_t *asset, std::vector <std::string> output)
{
    for (auto it: output) {
        std::vector<std::string> lines;
        cxxtools::split("\n", it, std::back_inserter(lines));
        for (auto l: lines) {
            auto parsed = s_nut_key_and_value (l);
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



//  --------------------------------------------------------------------------
//  Scan IP address using nut-scanner

bool
scan_nut (fty_proto_t *msg, const char *address, zconfig_t *config)
{
    if (!msg || !address) return false;

    // check IP address syntax
    CIDRAddress addr(address);
    if (! addr.valid ()) return false;

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
            s_nut_output_to_fty_message (msg, output);
            return true;
        }
    }
    // try xml
    {
        std::vector<std::string> output;
        nut_scan_xml_http ("device", addr, output);
        if (! output.empty ()) {
            s_nut_output_to_fty_message (msg, output);
            return true;
        }
    }
    return false;
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
