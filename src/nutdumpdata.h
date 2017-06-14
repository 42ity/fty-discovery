/*  =========================================================================
    nutdumpdata - Wrapper around nut --dump-data tool

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

#ifndef NUTDUMPDATA_H_INCLUDED
#define NUTDUMPDATA_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
typedef std::map<std::string, std::string> map_string_t;

/**
 * \brief set number of driver loop to collect data
 * \param[in] loop_nb - number of loop the driver will try to collect data (2 by default)
 * 
 * Environment variables:
 * BIOS_NUT_DUMPDATA - could be used to set this parameter
 **/  
void
set_nut_dumpdata_loop(unsigned int loop_nb);
/**
 * \brief generic entry point to get data from nut
 *
 * \param[in] driver  - name of the nut driver (dummy-ups, snmp-ups, netxml-ups ..)
 * \param[in] extra   - map of extra input arguments
 * \param[in] loop_nb - number of loop the driver will try to collect data
 * \param[out] out    - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata(
        const std::string& driver,
        const map_string_t& extra,
        const unsigned int loop_nb,
        map_string_t& out);

/**
 * \brief helper method to get data from a snmp-ups driver 
 *
 * \param[in] port      - port (ip:port)
 * \param[in] community - community name. If empty, use "public"
 * \param[out] out      - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata_snmp_ups(
        const std::string& port,
        const std::string& community,
        map_string_t& out);

/**
 * \brief helper method to get data from a netxml-ups driver 
 *
 * \param[in] port   - port (ip:port)
 * \param[out] out   - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata_netxml_ups(
        const std::string& port,
        map_string_t& out);

/**
 * \brief helper method to get data from a dummy driver 
 *
 * \param[in] device - dummy file device name (it is supposed to be in /etc/nut)
 * \param[out] out   - map of key/value returned by driver with output
 * \return 0 if success, -1 otherwise
 */
int
nut_dumpdata_dummy_ups(
        const std::string& device,
        map_string_t& out);

void
nutdumpdata_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
