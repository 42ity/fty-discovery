/*  =========================================================================
    device_scan - Perform one IP address scan

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

#include "fty_discovery_server.h"
#include <czmq.h>
#include <fty_common_nut.h>
#include <map>
#include <mutex>

/// Create a new device_scan
zactor_t* device_scan_new(zlist_t* arg0, discovered_devices_t* arg1, const fty::nut::KeyValues* mappings,
    const fty::nut::KeyValues* sensorMappings);

/// One device scan actor
void device_scan_actor(zsock_t* pipe, void* args);
