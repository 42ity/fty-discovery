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

#ifndef NUTSCAN_H_INCLUDED
#define NUTSCAN_H_INCLUDED

#include "src/fty_nut_classes.h"

/**
 * \brief call nut scan over SNMP
 *
 * \param[in] name asset name of device
 * \param[in] ip_address ip address of device
 * \param[in] community string, if empty 'public' will be used 
 * \param[in] use_dmf - true means that snmp-usp-dmf driver will be used
 * \param[out] out resulted string with NUT config snippets
 * \return 0 if success, -1 otherwise
 *
 * Environment variables:
 * BIOS_NUT_USE_DMF - will force usage of snmp-ups-dmf driver regardless
 *                    use_dmf argument
 */
int
nut_scan_snmp(
        const std::string& name,
        const CIDRAddress& ip_address,
        const std::string community,
        bool use_dmf,
        std::vector<std::string>& out);

/**
 * \brief call nut scan over XML HTTP
 *
 * \param[in] name asset name of device
 * \param[in] ip_address ip address of device
 * \param[out] out resulted string with NUT config snippets
 * \return 0 if success, -1 otherwise
 */
int
nut_scan_xml_http(
        const std::string& name,
        const CIDRAddress& ip_address,
        std::vector<std::string>& out);

//  Self test of this class
FTY_NUT_EXPORT void
    nutscan_test (bool verbose);


#endif
