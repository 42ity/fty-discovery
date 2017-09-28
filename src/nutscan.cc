/*  =========================================================================
    nutscan - Wrapper around nut-scanner tool

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
    nutscan - Wrapper around nut-scanner tool
@discuss
@end
*/

#include "fty_discovery_classes.h"

#include <string>
#include <sstream>
#include <vector>

/**
 * \brief one read line from istream
 */
static
ssize_t
s_readline(
        std::istream& inp,
        std::string& line)
{
    std::ostringstream buf;
    buf.clear();
    std::size_t ret;
    if (!inp.good() || inp.eof()) {
        return -1;
    }

    for (ret = 0; inp.good() && inp.peek() != '\n'; ret++) {
        char ch = static_cast<char>(inp.get());
        if (inp.eof())
            break;
        buf << ch;
    }
    if (inp.peek() == '\n') {
        buf << static_cast<char>(inp.get());
    }

    line.append(buf.str());
    return ret;
}

/**
 * \brief parse an output of nut-scanner
 *
 * \param name - name of device in the result
 * \param inp  - input stream
 * \param out  - vector of string with output
 */
static
void
s_parse_nut_scanner_output(
        const std::string& name,
        std::istream& inp,
        std::vector<std::string>& out)
{

    if (!inp.good() || inp.eof())
        return;

    std::stringstream buf;

    while (inp.good() && !inp.eof()) {
        std::string line;

        if (s_readline(inp, line) == -1)
            break;

        if (line.size() == 0)
            continue;

        if (line[0] == '[') {
            if (buf.tellp() > 0) {
                out.push_back(buf.str());
                buf.clear();
                buf.str("");
            }
            buf << '[' << name << ']' << std::endl;
        }
        else if (buf.tellp() > 0) {
            buf << line;
        }
    }

    if (buf.tellp() > 0) {
        out.push_back(buf.str());
        buf.clear();
        buf.str("");
    }
}

/**
 * \brief run nut-scanner binary and return the output
 */
static
int
s_run_nut_scaner(
        const Argv& args,
        const std::string& name,
        std::vector<std::string>& out)
{
    std::string o;
    std::string e;
    zsys_debug ("START: nut-scanner with timeout 20 ...");
    int ret = output(args, o, e, 20);
    zsys_debug ("       done with code %d", ret);

    if (ret != 0)
        return -1;

    std::istringstream inp{o};
    s_parse_nut_scanner_output(
            name,
            inp,
            out);

    if (out.empty())
        return -1;

    return 0;
}

int
nut_scan_multi_snmp(
        const std::string& name,
        const CIDRAddress& ip_address_start,
        const CIDRAddress& ip_address_end,
        const std::string community,
        bool use_dmf,
        std::vector<std::string>& out)
{
    std::string comm;
    comm = community;
    if (comm.empty())
        comm = "public";

    int r = -1;
    // DMF enabled and available
    if (use_dmf || ::getenv ("BIOS_NUT_USE_DMF")) {
        zsys_debug("nut-scanner --community %s -z -s %s -e %s",comm.c_str(), ip_address_start.toString(CIDR_WITHOUT_PREFIX).c_str() , ip_address_end.toString(CIDR_WITHOUT_PREFIX).c_str());
        Argv args = {"nut-scanner", "--community", comm, "-z", "-s", ip_address_start.toString(), "-e", ip_address_end.toString()};
        r = s_run_nut_scaner(
                args,
                name,
                out);
        
            return r;
    }

    // DMF not available
    zsys_debug("nut-scanner --community %s -S -s %s -e %s",comm.c_str(), ip_address_start.toString(CIDR_WITHOUT_PREFIX).c_str() , ip_address_end.toString(CIDR_WITHOUT_PREFIX).c_str());
    Argv args = {"nut-scanner", "--community", comm, "-S", "-s", ip_address_start.toString(CIDR_WITHOUT_PREFIX), "-e", ip_address_end.toString(CIDR_WITHOUT_PREFIX)};
    r = s_run_nut_scaner(
            args,
            name,
            out);
    return r;
}


int
nut_scan_multi_xml_http(
        const std::string& name,
        const CIDRAddress& ip_address_start,
        const CIDRAddress& ip_address_end,
        std::vector<std::string>& out)
{
     zsys_debug("nut-scanner -M -s %s -e %s", ip_address_start.toString(CIDR_WITHOUT_PREFIX).c_str() , ip_address_end.toString(CIDR_WITHOUT_PREFIX).c_str());
    Argv args = {"nut-scanner", "-M", "-s", ip_address_start.toString(CIDR_WITHOUT_PREFIX), "-e", ip_address_end.toString(CIDR_WITHOUT_PREFIX)};
    return s_run_nut_scaner(
            args,
            name,
            out);
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
nutscan_test (bool verbose)
{
    printf (" * nutscan: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
