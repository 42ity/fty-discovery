/*  =========================================================================
    scan_dns - collect information from DNS

    Copyright (C) 2014 - 2019 Eaton

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
    scan_dns - collect information from DNS
@discuss
@end
*/

#include "fty_discovery_classes.h"

#include <sys/socket.h>       /* for AF_INET */


bool
scan_dns (fty_proto_t *msg, const char *address, zconfig_t *config)
{
    if (!msg || !address) return false;

    struct sockaddr_in sa_in;
    struct sockaddr *sa = (sockaddr *)&sa_in;    /* input */
    socklen_t len = sizeof (sockaddr_in);        /* input */

    char dns_name[NI_MAXHOST];

    sa_in.sin_family = AF_INET;
    if (! inet_aton (address, &sa_in.sin_addr)) return false;

    if (! getnameinfo(sa, len, dns_name, sizeof(dns_name), NULL, 0, NI_NAMEREQD)) {
        fty_proto_ext_insert (msg, "dns.1", "%s", dns_name);
        log_debug("Retrieved DNS information");
        log_debug("FQDN = '%s'", dns_name);
        char *p = strchr (dns_name, '.');
        if (p) {
            *p = 0;
        }
        fty_proto_ext_insert (msg, "hostname", "%s", dns_name);
        log_debug("Hostname = '%s'", dns_name);
        return true;
    }
    else {
        log_debug("No host information retrieved from DNS");
    }
    return false;
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
scan_dns_test (bool verbose)
{
    printf (" * scan_dns: ");

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
    fty_proto_t *msg = fty_proto_new (FTY_PROTO_ASSET);
    fty_proto_ext_insert (msg, "ip.1", "%s", "127.0.0.1");
    scan_dns (msg, "127.0.0.1", NULL);
    fty_proto_print (msg);
    assert (fty_proto_ext_string (msg, "dns.1", NULL));
    assert (fty_proto_ext_string (msg, "hostname", NULL));
    fty_proto_destroy (&msg);
    //  @end
    printf ("OK\n");
}
