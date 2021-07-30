/*  =========================================================================
    cidr - C++ Wrapper around libcidr

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

/*!
 * \file cidr.cc
 * \author Tomas Halman <TomasHalman@Eaton.com>
 * \author Alena Chernikava <AlenaChernikava@Eaton.com>
 * \author Karol Hrdina <KarolHrdina@Eaton.com>
 * \brief Not yet documented file
 */
#include "cidr.h"
#include <cstdio>
#include <stdlib.h>
#include <string.h>

CIDRAddress::CIDRAddress()
{
    _cidr = NULL;
}

CIDRAddress::CIDRAddress(const std::string& address)
{
    _cidr = NULL;
    set(address);
}

CIDRAddress::CIDRAddress(const std::string& address, const std::string& prefix)
{
    _cidr = NULL;
    set(address + "/" + prefix);
}

CIDRAddress::CIDRAddress(const std::string& address, const unsigned int prefix)
{
    _cidr = NULL;
    set(address + "/" + std::to_string(prefix));
}

CIDRAddress::CIDRAddress(const struct in_addr* address)
{
    _cidr = NULL;
    set(address);
}

CIDRAddress::CIDRAddress(const struct in6_addr* address)
{
    _cidr = NULL;
    set(address);
}

CIDRAddress::CIDRAddress(const struct sockaddr* address)
{
    _cidr = NULL;
    set(address);
}

CIDRAddress::CIDRAddress(const CIDRAddress& address)
{
    _cidr = NULL;
    set(address);
}

CIDRAddress::CIDRAddress(CIDRAddress&& other)
{
    _cidr = NULL;
    setCidrPtr(other._cidr);
    ;
    other._cidr = NULL;
}

CIDRAddress& CIDRAddress::operator++()
{

    if (!valid())
        return *this;

    struct in_addr  inaddr;
    struct in6_addr in6addr;
    unsigned char*  bytes;
    int             i;

    // do nothing for networks?
    if (cidr_get_proto(_cidr) == CIDR_IPV4) {
        cidr_to_inaddr(_cidr, &inaddr);
        bytes = reinterpret_cast<unsigned char*>(&inaddr.s_addr);
        for (i = 3; i >= 0; i--) {
            bytes[i]++;
            if (bytes[i] != 0) {
                break;
            }
        }
        setCidrPtr(cidr_from_inaddr(&inaddr));
    }
    if (cidr_get_proto(_cidr) == CIDR_IPV6) {
        cidr_to_in6addr(_cidr, &in6addr);
        for (i = 15; i >= 0; i--) {
            in6addr.s6_addr[i]++;
            if (in6addr.s6_addr[i] != 0) {
                break;
            }
        }
        setCidrPtr(cidr_from_in6addr(&in6addr));
    }
    return *this;
}

CIDRAddress& CIDRAddress::operator--()
{

    if (!valid())
        return *this;

    struct in_addr  inaddr;
    struct in6_addr in6addr;
    unsigned char*  bytes;
    int             i;

    // do nothing for networks?
    if (cidr_get_proto(_cidr) == CIDR_IPV4) {
        cidr_to_inaddr(_cidr, &inaddr);
        bytes = reinterpret_cast<unsigned char*>(&inaddr.s_addr);
        for (i = 3; i >= 0; i--) {
            bytes[i]--;
            if (bytes[i] != 255) {
                break;
            }
        }
        setCidrPtr(cidr_from_inaddr(&inaddr));
    }
    if (cidr_get_proto(_cidr) == CIDR_IPV6) {
        cidr_to_in6addr(_cidr, &in6addr);
        for (i = 15; i >= 0; i--) {
            in6addr.s6_addr[i]--;
            if (in6addr.s6_addr[i] != 255) {
                break;
            }
        }
        setCidrPtr(cidr_from_in6addr(&in6addr));
    }
    return *this;
}

CIDRAddress CIDRAddress::operator++(int)
{
    CIDRAddress result;

    result.setCidrPtr(_cidr ? cidr_dup(_cidr) : NULL);
    ++(*this);
    return result;
}

CIDRAddress CIDRAddress::operator--(int)
{
    CIDRAddress result;

    result.setCidrPtr(_cidr ? cidr_dup(_cidr) : NULL);
    --(*this);
    return result;
}

void CIDRAddress::setCidrPtr(CIDR* newcidr)
{
    if (_cidr)
        cidr_free(_cidr);
    _cidr = newcidr;
}

int CIDRAddress::protocol() const
{
    if (!valid()) {
        return 0;
    }
    if (cidr_get_proto(_cidr) == CIDR_IPV4) {
        return 4;
    }
    if (cidr_get_proto(_cidr) == CIDR_IPV6) {
        return 6;
    }
    return 0;
}

int CIDRAddress::prefix() const
{
    if (valid()) {
        return cidr_get_pflen(_cidr);
    } else {
        return -1;
    }
}

std::string CIDRAddress::netmask() const
{
    std::string result;

    if (protocol() == 4) { // make sense only for IPv4
        char* cstr = cidr_to_str(_cidr, CIDR_NETMASK);
        if (cstr) {
            char* p = strchr(cstr, '/');
            if (p) {
                result = ++p;
            }
            free(cstr);
        }
    }
    return result;
}

bool CIDRAddress::isNetmask() const
{
    if (protocol() != 4)
        return false; // make sense only for IPv4
    return CIDRAddress("1.1.1.1/" + toString()).valid();
}

void CIDRAddress::invalidate()
{
    setCidrPtr(NULL);
}

bool CIDRAddress::valid() const
{
    if (_cidr == NULL)
        return false;

    in_addr  in_addr4;
    in6_addr in_addr6;

    if (cidr_get_proto(_cidr) == CIDR_IPV4) {
        if (cidr_to_inaddr(_cidr, &in_addr4)) {
            return (in_addr4.s_addr != 0); // 0.0.0.0 address
        } else {
            return false;
        }
    }
    if (cidr_get_proto(_cidr) == CIDR_IPV6) {
        if (cidr_to_in6addr(_cidr, &in_addr6)) {
            for (int i = 0; i < 16; i++) {
                if (in_addr6.s6_addr[i] != 0) {
                    return true;
                }
            }
            return false; // :: address
        } else {
            return false;
        }
    }
    return false;
}

bool CIDRAddress::contains(const CIDRAddress& address) const
{
    if ((!valid()) || (!address.valid()))
        return false;
    return (cidr_contains(_cidr, address._cidr) == 0);
}

bool CIDRAddress::in(const CIDRAddress& address) const
{
    if ((!valid()) || (!address.valid()))
        return false;
    return (cidr_contains(address._cidr, _cidr) == 0);
}

bool CIDRAddress::equals(const CIDRAddress& address) const
{
    if ((!valid()) && (!address.valid()))
        return true;
    if ((!valid()) || (!address.valid()))
        return false;
    return (cidr_equals(address._cidr, _cidr) == 0);
}

CIDRAddress CIDRAddress::hostMin() const
{
    CIDRAddress result;
    if (!valid())
        return result;
    CIDR* host = cidr_addr_hostmin(_cidr);
    result.setCidrPtr(host);
    return result;
}

CIDRAddress CIDRAddress::hostMax() const
{
    CIDRAddress result;
    if (!valid())
        return result;
    CIDR* host = cidr_addr_hostmax(_cidr);
    result.setCidrPtr(host);
    return result;
}

CIDRAddress CIDRAddress::host() const
{

    CIDRAddress result;
    if (!valid())
        return result;

    in_addr  in_addr4;
    in6_addr in_addr6;

    if (cidr_get_proto(_cidr) == CIDR_IPV4) {
        cidr_to_inaddr(_cidr, &in_addr4);
        result.setCidrPtr(cidr_from_inaddr(&in_addr4));
    }
    if (cidr_get_proto(_cidr) == CIDR_IPV6) {
        cidr_to_in6addr(_cidr, &in_addr6);
        result.setCidrPtr(cidr_from_in6addr(&in_addr6));
    }
    return result;
}

CIDRAddress CIDRAddress::network() const
{
    CIDRAddress result;

    if (!valid())
        return result;
    result.setCidrPtr(cidr_addr_network(_cidr));
    return result;
}


CIDRAddress CIDRAddress::broadcast() const
{
    CIDRAddress result;
    if (!valid())
        return result;
    CIDR* host = cidr_addr_broadcast(_cidr);
    result.setCidrPtr(host);
    return result;
}

bool CIDRAddress::set(const std::string& text)
{
    CIDR* newcidr = cidr_from_str(text.c_str());
    setCidrPtr(newcidr);
    return (_cidr != NULL);
}

bool CIDRAddress::set(const CIDRAddress& from)
{
    setCidrPtr(from._cidr ? cidr_dup(from._cidr) : NULL);
    return (_cidr != NULL);
}

bool CIDRAddress::set(const struct in_addr* address)
{
    CIDR* newcidr = cidr_from_inaddr(address);
    setCidrPtr(newcidr);
    return (_cidr != NULL);
}

bool CIDRAddress::set(const struct in6_addr* address)
{
    CIDR* newcidr = cidr_from_in6addr(address);
    setCidrPtr(newcidr);
    return (_cidr != NULL);
}

bool CIDRAddress::set(const struct sockaddr* address)
{
    setCidrPtr(NULL);
    if (!address)
        return false;
    switch (address->sa_family) {
        case AF_INET: {
            auto sin_addr = &(reinterpret_cast<const struct sockaddr_in*>(address))->sin_addr;
            return set(sin_addr);
        }
        case AF_INET6: {
            auto sin6_addr = &(reinterpret_cast<const struct sockaddr_in6*>(address))->sin6_addr;
            return set(sin6_addr);
        }
    }
    return false;
}

std::string CIDRAddress::toString() const
{
    return toString(CIDR_AUTO_PREFIX);
}

std::string CIDRAddress::toString(CIDROptions opt) const
{
    std::string addr       = "";
    bool        showprefix = true;
    char*       cstr;

    if (opt == CIDR_WITHOUT_PREFIX) {
        showprefix = false;
    }
    if (_cidr) {
        if (opt == CIDR_AUTO_PREFIX) {
            if ((cidr_get_proto(_cidr) == CIDR_IPV4) && (prefix() == 32)) {
                showprefix = false;
            }
            if ((cidr_get_proto(_cidr) == CIDR_IPV6) && (prefix() == 128)) {
                showprefix = false;
            }
        }
        if (showprefix) {
            cstr = cidr_to_str(_cidr, CIDR_NOFLAGS);
        } else {
            cstr = cidr_to_str(_cidr, CIDR_ONLYADDR);
        }
        if (cstr) {
            addr = cstr;
            free(cstr);
        }
    }
    return addr;
}

int CIDRAddress::compare(const CIDRAddress& a2) const
{
    struct in_addr  inaddr1, inaddr2;
    struct in6_addr in6addr1, in6addr2;
    unsigned char * bytes1, *bytes2;
    int             i;
    int             proto1, proto2;

    if ((!valid()) && (!a2.valid())) {
        // both are invalid, equal
        return 0;
    }
    if ((!valid()) || (!a2.valid())) {
        if (valid()) {
            // im valid, im bigger
            return 1;
        } else {
            return -1;
        }
    }
    proto1 = cidr_get_proto(_cidr);
    proto2 = cidr_get_proto(a2._cidr);
    if ((proto1 == CIDR_IPV4) && (proto2 == CIDR_IPV4)) {
        cidr_to_inaddr(_cidr, &inaddr1);
        cidr_to_inaddr(a2._cidr, &inaddr2);
        bytes1 = reinterpret_cast<unsigned char*>(&inaddr1.s_addr);
        bytes2 = reinterpret_cast<unsigned char*>(&inaddr2.s_addr);
        for (i = 0; i <= 3; i++) {
            if (bytes1[i] < bytes2[i])
                return -1; // im smaller
            if (bytes1[i] > bytes2[i])
                return +1; // im bigger
        }
        return 0; // we are equal
    }
    if ((proto1 == CIDR_IPV6) && (proto2 == CIDR_IPV6)) {
        cidr_to_in6addr(_cidr, &in6addr1);
        cidr_to_in6addr(a2._cidr, &in6addr2);
        bytes1 = reinterpret_cast<unsigned char*>(&in6addr1.s6_addr);
        bytes2 = reinterpret_cast<unsigned char*>(&in6addr2.s6_addr);
        for (i = 0; i <= 15; i++) {
            if (bytes1[i] < bytes2[i])
                return -1; // im smaller
            if (bytes1[i] > bytes2[i])
                return +1; // im bigger
        }
        return 0; // we are equal
    }
    if ((proto1 == CIDR_IPV6) && (proto2 == CIDR_IPV4)) {
        // i'm IPv6, i'm bigger
        return +1;
    } else {
        // i'm IPv4, i'm smaller
        return -1;
    }
}

CIDRAddress& CIDRAddress::operator=(const std::string& address)
{
    set(address);
    return *this;
}

CIDRAddress& CIDRAddress::operator=(const CIDRAddress& address)
{
    if (this != &address) {
        setCidrPtr(address._cidr ? cidr_dup(address._cidr) : NULL);
    }
    return *this;
}

CIDRAddress& CIDRAddress::operator=(CIDRAddress&& address)
{
    if (this != &address) {
        setCidrPtr(address._cidr);
        address._cidr = NULL;
    }
    return *this;
}


CIDRAddress::~CIDRAddress()
{
    setCidrPtr(NULL);
}

bool CIDRAddress::operator>(const CIDRAddress& a2) const
{
    return (compare(a2) == 1);
}

bool CIDRAddress::operator<(const CIDRAddress& a2) const
{
    return (compare(a2) == -1);
}

bool CIDRAddress::operator==(const CIDRAddress& a2) const
{
    return equals(a2);
}

bool CIDRAddress::operator!=(const CIDRAddress& a2) const
{
    return !equals(a2);
}

bool CIDRAddress::operator==(const std::string& a2) const
{
    CIDRAddress ca2(a2);
    return equals(ca2);
}

bool CIDRAddress::operator!=(const std::string& a2) const
{
    CIDRAddress ca2(a2);
    return !equals(a2);
}

std::ostream& operator<<(std::ostream& os, const CIDRAddress& address)
{
    return os << address.toString();
}

CIDRList::CIDRList()
{
}

bool CIDRList::_nextSimple(CIDRAddress& address)
{
    if (!address.valid()) {
        address.set(firstAddress());
        _last = lastAddress();
        return address.valid();
    }
    ++address;
    if (address > _last) {
        address.invalidate();
    }
    return address.valid();
}

bool CIDRList::next(CIDRAddress& address)
{
    int filtered, iprefix, eprefix;
    do {
        filtered = 0;
        _nextSimple(address);
        if (!address.valid()) {
            break;
        }
        iprefix = bestNetworkPrefixFor(address);
        if (iprefix == -1) {
            // out of scope
            _skipToNextPool(address);
            filtered = 1;
        } else {
            eprefix = bestExcludePrefixFor(address);
            if (eprefix > iprefix) {
                // excluded
                _skipToExcludeEnd(address);
                filtered = 1;
            } else {
                // not excluded, skip net and broadcast
                CIDRAddress net = bestNetworkFor(address);
                // FIXME IPv6
                if (net.prefix() < 31 /* and IPv4? */) {
                    if ((address == net.host()) || (address == net.broadcast())) {
                        filtered = 1;
                    }
                }
            }
        }
    } while (filtered);
    return address.valid();
}

bool CIDRList::add(const std::string& net)
{
    CIDRAddress cnet(net);
    return add(cnet);
}

bool CIDRList::add(const CIDRAddress& net)
{
    if (!net.valid()) {
        return false;
    }
    for (unsigned int i = 0; i < _networks.size(); i++) {
        if (_networks[i].equals(net)) {
            return false;
        }
    }
    _networks.push_back(net);
    return true;
}

bool CIDRList::exclude(const std::string& net)
{
    CIDRAddress cnet(net);
    return exclude(cnet);
}

bool CIDRList::exclude(const CIDRAddress& net)
{
    if (!net.valid())
        return false;
    for (unsigned int i = 0; i < _excludedNetworks.size(); i++) {
        if (_excludedNetworks[i].equals(net))
            return false;
    }
    _excludedNetworks.push_back(net);
    return true;
}

CIDRAddress CIDRList::firstAddress() const
{
    CIDRAddress addr, result;
    if (!_networks.size()) {
        return result;
    }
    result = _networks[0].host();
    for (unsigned int i = 1; i < _networks.size(); i++) {
        addr = _networks[i].host();
        if (addr < result)
            result = addr;
    }
    return result;
}

CIDRAddress CIDRList::lastAddress() const
{
    CIDRAddress addr, result;
    if (!_networks.size()) {
        return result;
    }
    result = _networks[0].hostMax();
    for (unsigned int i = 1; i < _networks.size(); i++) {
        addr = _networks[i].hostMax();
        if (addr > result)
            result = addr;
    }
    return result;
}

CIDRAddress CIDRList::bestNetworkFor(CIDRAddress& address) const
{
    int         prefix, bestprefix = -1;
    CIDRAddress net;

    for (unsigned int i = 0; i < _networks.size(); i++) {
        if (_networks[i].contains(address)) {
            prefix = _networks[i].prefix();
            if (prefix > bestprefix) {
                bestprefix = prefix;
                net        = _networks[i];
            }
        }
    }
    return net;
}

void CIDRList::_skipToNextPool(CIDRAddress& address) const
{
    CIDRAddress selected;
    for (unsigned int i = 0; i < _networks.size(); i++) {
        // we should not walk trough ipv6
        if (_networks[i] > address && (_networks[i].protocol() == 4)) {
            if (selected.valid()) {
                if (_networks[i] < selected) {
                    selected = _networks[i].host();
                }
            } else {
                selected = _networks[i].host();
            }
        }
    }
    --selected;
    address.set(selected);
}

void CIDRList::_skipToExcludeEnd(CIDRAddress& address) const
{
    CIDRAddress currentExclude = bestExcludeFor(address);
    CIDRAddress excludeEnd     = currentExclude.broadcast();
    CIDRAddress selected       = excludeEnd;

    for (unsigned int i = 0; i < _networks.size(); i++) {
        if ((_networks[i] > address) && (_networks[i] < excludeEnd)) {
            if (selected.valid()) {
                if (_networks[i] < selected) {
                    selected = _networks[i].host();
                    --selected;
                }
            } else {
                selected = _networks[i].host();
                --selected;
            }
        }
    }
    address.set(selected);
}

int CIDRList::bestNetworkPrefixFor(CIDRAddress& address) const
{
    CIDRAddress bestnet = bestNetworkFor(address);
    if (bestnet.valid())
        return bestnet.prefix();
    return -1;
}

CIDRAddress CIDRList::bestExcludeFor(CIDRAddress& address) const
{
    int         prefix, bestprefix = -1;
    CIDRAddress net;
    for (unsigned int i = 0; i < _excludedNetworks.size(); i++) {
        if (_excludedNetworks[i].contains(address)) {
            prefix = _excludedNetworks[i].prefix();
            if (prefix > bestprefix) {
                bestprefix = prefix;
                net        = _excludedNetworks[i];
            }
        }
    }
    return net;
}

int CIDRList::bestExcludePrefixFor(CIDRAddress& address) const
{
    CIDRAddress bestnet = bestExcludeFor(address);
    if (bestnet.valid())
        return bestnet.prefix();
    return -1;
}

bool CIDRList::includes(const CIDRAddress& address) const
{
    for (unsigned int i = 0; i < _networks.size(); i++) {
        if (_networks[i].contains(address))
            return true;
    }
    return false;
}

bool CIDRList::excludes(const CIDRAddress& address) const
{
    for (unsigned int i = 0; i < _excludedNetworks.size(); i++) {
        if (_excludedNetworks[i].contains(address)) {
            return true;
        }
    }
    return false;
}

CIDRList::~CIDRList()
{
}
