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

#include <mutex>

#ifdef __cplusplus
extern "C" {
#endif

#define CFG_DISCOVERY            "/discovery"    
#define CFG_DISCOVERY_TYPE       CFG_DISCOVERY"/type"
#define CFG_DISCOVERY_SCANS      CFG_DISCOVERY"/scans"
#define CFG_DISCOVERY_IPS        CFG_DISCOVERY"/ips"
#define CFG_DISCOVERY_SCANS_NUM  CFG_DISCOVERY_SCANS"/scanNumber"
#define CFG_DISCOVERY_IPS_NUM    CFG_DISCOVERY_IPS"/ipNumber" 

#define CFG_PARAMETERS                  "/parameters"
#define CFG_PARAM_MAX_DUMPPOOL_NUMBER   CFG_PARAMETERS"/maxDumpPoolNumber"
#define CFG_PARAM_MAX_SCANPOOL_NUMBER   CFG_PARAMETERS"/maxScanPoolNumber"
#define CFG_PARAM_NUTSCAN_TIMEOUT       CFG_PARAMETERS"/nutScannerTimeOut"
#define CFG_PARAM_DUMPDATA_LOOPTIME     CFG_PARAMETERS"/dumpDataLoopTime"

#define DEFAULT_MAX_DUMPPOOL_NUMBER     "15"
#define DEFAULT_MAX_SCANPOOL_NUMBER     "4"
#define DEFAULT_NUTSCAN_TIMEOUT         "20"
#define DEFAULT_DUMPDATA_LOOPTIME       "30"

#define TYPE_LOCALSCAN 1
#define TYPE_MULTISCAN 2
#define TYPE_IPSCAN    3
#define DISCOVERY_TYPE_LOCAL "localscan"    
#define DISCOVERY_TYPE_MULTI "multiscan"
#define DISCOVERY_TYPE_IP    "ipscan"
    
#define STATUS_STOPPED  1
#define STATUS_FINISHED 2
#define STATUS_PROGESS  3
#define STATUS_STOPPING "STOPPING"    
#define STATUS_RUNNING  "RUNNING"

#define REQ_TERM       "$TERM"    
#define REQ_BIND       "BIND"
#define REQ_CONSUMER   "CONSUMER"    
#define REQ_REPUBLISH  "REPUBLISH"   
#define REQ_SCAN       "SCAN"  
#define REQ_LOCALSCAN  "LOCALSCAN"    
#define REQ_SETCONFIG  "SETCONFIG"    
#define REQ_GETCONFIG  "GETCONFIG"   
#define REQ_CONFIG     "CONFIG"
#define REQ_LAUNCHSCAN "LAUNCHSCAN" 
#define REQ_PROGRESS   "PROGRESS"
#define REQ_STOPSCAN   "STOPSCAN" 
#define REQ_DONE       "DONE"  
#define REQ_FOUND      "FOUND"  
#define REQ_PROGRESS   "PROGRESS"

#define STREAM_CMD   "STREAM DELIVER"  
#define MAILBOX_CMD  "MAILBOX DELIVER"
    
#define RESP_OK  "OK"    
#define RESP_ERR "ERROR"

#define INFO_READY      "READY"
#define CMD_CONTINUE    "CONTINUE"

#define FTY_ASSET "asset-agent"
    
#define CREATE_USER "system"
#define CREATE_MODE "3"
    
typedef struct _discovered_devices_t {
    std::mutex mtx_list;
    zhash_t *device_list; 
} discovered_devices_t;
    
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

FTY_DISCOVERY_EXPORT
std::string getDiscoveryConfigFile();

#ifdef __cplusplus
}
#endif

#endif
