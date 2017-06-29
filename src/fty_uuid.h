/*  =========================================================================
    fty_uuid - UUID generating

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

#ifndef FTY_UUID_H_INCLUDED
#define FTY_UUID_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new fty_uuid
FTY_DISCOVERY_PRIVATE fty_uuid_t *
    fty_uuid_new (void);

//  Destroy the fty_uuid
FTY_DISCOVERY_PRIVATE void
    fty_uuid_destroy (fty_uuid_t **self_p);

//  Calculate UUID v5 in EATON namespace base on manufacturer, model and serial number
FTY_DISCOVERY_PRIVATE const char*
    fty_uuid_calculate (fty_uuid_t *self, const char *mfr, const char *model, const char *serial);

//  Generate random UUID
FTY_DISCOVERY_PRIVATE const char*
    fty_uuid_generate (fty_uuid_t *self);

//  Self test of this class
FTY_DISCOVERY_PRIVATE void
    fty_uuid_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
