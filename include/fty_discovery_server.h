/*  =========================================================================
    ftydiscovery - Manages discovery requests, provides feedback

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

#ifndef FTYDISCOVERY_H_INCLUDED
#define FTYDISCOVERY_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif
    
#define TYPE_LOCALSCAN 1
#define TYPE_MULTISCAN 2
#define TYPE_IPSCAN    3
    
#define STATUS_STOPPED  1
#define STATUS_FINISHED 2
#define STATUS_PROGESS  3
    

//  @interface
//  Create a new fty_discovery_server
FTY_DISCOVERY_EXPORT fty_discovery_server_t *
    fty_discovery_server_new (void);

//  Destroy the fty_discovery_server
FTY_DISCOVERY_EXPORT void
    fty_discovery_server_destroy (fty_discovery_server_t **self_p);

//  ftydiscovery actor
FTY_DISCOVERY_EXPORT void
    fty_discovery_server (zsock_t *pipe, void *args);

//  Self test of this class
FTY_DISCOVERY_EXPORT void
    fty_discovery_server_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
