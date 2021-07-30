/*  =========================================================================
    assets - Cache of assets

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
#include <fty_proto.h>

struct assets_t
{
    zhashx_t* assets;
    int64_t   lastupdate;
};

/// Create a new assets
assets_t* assets_new(void);

/// Destroy the assets
void assets_destroy(assets_t** self_p);

/// Put one asset into cache
void assets_put(assets_t* self, fty_proto_t** msg_p);

/// Find asset by ext attribute
fty_proto_t* assets_find(assets_t* self, const char* key, const char* value);

/// return the zclock_mono time in ms when last change happened (create or delete, not update)
int64_t assets_last_change(assets_t* self);
