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

#ifndef DEVICE_SCAN_H_INCLUDED
#define DEVICE_SCAN_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

//  @interface

typedef struct _device_scan_args_t {
    zconfig_t *config;
    CIDRAddress addr;
} device_scan_args_t;


//  Create a new device_scan
FTY_DISCOVERY_PRIVATE zactor_t *
    device_scan_new (device_scan_args_t *args);

//  Self test of this class
FTY_DISCOVERY_PRIVATE void
    device_scan_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
