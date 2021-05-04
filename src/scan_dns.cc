/*  =========================================================================
    scan_dns - collect information from DNS

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


#include "scan_dns.h"
#include <fty_log.h>
#include <sys/socket.h> /* for AF_INET */


bool scan_dns(fty_proto_t* msg, const char* address, zconfig_t* /* config */)
{
    if (!msg || !address)
        return false;

    struct sockaddr_in sa_in;
    struct sockaddr*   sa  = reinterpret_cast<sockaddr*>(&sa_in); /* input */
    socklen_t          len = sizeof(sockaddr_in);                 /* input */

    char dns_name[NI_MAXHOST];

    sa_in.sin_family = AF_INET;
    if (!inet_aton(address, &sa_in.sin_addr))
        return false;

    if (!getnameinfo(sa, len, dns_name, sizeof(dns_name), NULL, 0, NI_NAMEREQD)) {
        fty_proto_ext_insert(msg, "dns.1", "%s", dns_name);
        log_debug("Retrieved DNS information:");
        log_debug("FQDN = '%s'", dns_name);
        char* p = strchr(dns_name, '.');
        if (p) {
            *p = 0;
        }
        fty_proto_ext_insert(msg, "hostname", "%s", dns_name);
        log_debug("Hostname = '%s'", dns_name);
        return true;
    } else {
        log_debug("No host information retrieved from DNS");
    }
    return false;
}
