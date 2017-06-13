/*  =========================================================================
    range_scan - Perform one range scan

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

#ifndef RANGE_SCAN_H_INCLUDED
#define RANGE_SCAN_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _range_scan_args_t {
    char *range;
    char *config;
} range_scan_args_t;

//  @interface
//  Create a new range_scan
FTY_DISCOVERY_PRIVATE range_scan_t *
    range_scan_new (const char* range);

//  Destroy the range_scan
FTY_DISCOVERY_PRIVATE void
    range_scan_destroy (range_scan_t **self_p);

//  report progress in % (0 - 100);
FTY_DISCOVERY_PRIVATE int
    range_scan_progress (range_scan_t *self);

//  Actor for range scan
FTY_DISCOVERY_PRIVATE void
    range_scan_actor (zsock_t *pipe, void *args);

//  Self test of this class
FTY_DISCOVERY_PRIVATE void
    range_scan_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
