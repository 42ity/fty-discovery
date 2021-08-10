/*  =========================================================================
    scan_nut - collect information from DNS

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

#pragma once

#include <czmq.h>
#include <fty_common_nut.h>
#include <fty_proto.h>

/// Scan IP address using nut-scanner
/// One device scan actor
void scan_nut_actor(zsock_t* pipe, void* args);
bool nut_dumpdata_to_fty_message(std::vector<fty_proto_t*>& assets, const fty::nut::DeviceConfiguration& dump,
    const fty::nut::KeyValues* mappings, const fty::nut::KeyValues* sensorMappings, const std::string& ip,
    const std::string& type);
