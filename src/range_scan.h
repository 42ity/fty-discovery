/*  =========================================================================
    range_scan - Perform one range scan

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
#include <vector>

struct range_scan_t
{
    char*   range;
    int64_t size;
    int64_t cursor;
};

typedef struct _range_scan_args_t
{
    std::vector<std::pair<char*, char*>> ranges;
    char*                                config;
} range_scan_args_t;

/// Create a new range_scan
range_scan_t* range_scan_new(const char* range);

/// Destroy the range_scan
void range_scan_destroy(range_scan_t** self_p);

/// report progress in % (0 - 100);
int range_scan_progress(range_scan_t* self);

/// Actor for range scan
void range_scan_actor(zsock_t* pipe, void* args);
