/*  =========================================================================
    assets - Cache of assets

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

#ifndef ASSETS_H_INCLUDED
#define ASSETS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new assets
FTY_DISCOVERY_PRIVATE assets_t *
    assets_new (void);

//  Destroy the assets
FTY_DISCOVERY_PRIVATE void
    assets_destroy (assets_t **self_p);

//  Self test of this class
FTY_DISCOVERY_PRIVATE void
    assets_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
