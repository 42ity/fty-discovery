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

/*
@header
    ftydiscovery - Manages discovery requests, provides feedback
@discuss
@end
*/

#include <ctime>
#include <vector>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string>
#include "fty_discovery_classes.h"

//  Structure of our class

struct _ftydiscovery_t {
    mlm_client_t *mlm;
    zactor_t *scanner;
    assets_t *assets;
    int64_t nb_discovered;
    int64_t quickscan_size;
    std::vector<std::pair <std::string, int64_t>> quickscan_subnets;
};

int mask_nb_bit(std::string mask)
{
    size_t pos;
    int res = 0;
    std::string part;
    while( (pos = mask.find(".")) != std::string::npos)
    {
        part = mask.substr(0,pos);
        if(part == "255")
            res += 8;
        else if(part == "254")
            return res+7;
        else if(part == "252")
            return res+6;
        else if(part == "248")
            return res+5;
        else if(part == "240")
            return res+4;
        else if(part == "224")
            return res+3;
        else if(part == "192")
            return res+2;
        else if(part == "128")
            return res+1;
        else if(part == "0")
            return res;
        else //error
            return -1;
        
        mask.erase(0, pos +1);
    }
    
    if(mask == "255")
        res += 8;
    else if(mask == "254")
        res += 7;
    else if(mask == "252")
        res += 6;
    else if(mask == "248")
        res += 5;
    else if(mask == "240")
        res += 4;
    else if(mask == "224")
        res += 3;
    else if(mask == "192")
        res += 2;
    else if(mask == "128")
        res += 1;
    else if(mask == "0")
        return res;
    else
        return -1;
    
    return res;
}

void configure_quick_scan(ftydiscovery_t *self)
{
    int s, family, prefix;
    char host[NI_MAXHOST];
    struct ifaddrs *ifaddr, *ifa;
    std::string addr, netm, addrmask;

    self->quickscan_size = 0;
    if(getifaddrs(&ifaddr) != -1)
    {
        for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
            if(streq(ifa->ifa_name,"lo"))
                continue;
            if(ifa->ifa_addr == NULL)
                continue;

            family = ifa->ifa_addr->sa_family;
            if (family != AF_INET)
                continue;

            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if(s != 0)
            {
                zsys_debug("IP address parsing error for %s : %s", ifa->ifa_name, gai_strerror(s));
                continue;
            }
            else
                addr.assign(host);    

            if(ifa->ifa_netmask == NULL)
            {
                zsys_debug("No netmask found for %s", ifa->ifa_name);
                continue;
            }

            family = ifa->ifa_netmask->sa_family;
            if (family != AF_INET)
                continue;

            s = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if(s != 0)
            {
                zsys_debug("Netmask parsing error for %s : %s", ifa->ifa_name, gai_strerror(s));
                continue;
            }
            else
                netm.assign(host);

            prefix = 0;
            addrmask.clear();

            prefix = mask_nb_bit(netm);
                
            self->quickscan_size += (1 << (32 - prefix));
            
            CIDRAddress addrCidr(addr, prefix);

            addrmask.clear();
            addrmask.assign(addrCidr.network().toString());  
            
            self->quickscan_subnets.push_back(std::make_pair(addrmask,(1 << (32 - prefix))));            
            zsys_info("Quickscan subnet found for %s : %s",ifa->ifa_name, addrmask.c_str());
            
        }

        freeifaddrs(ifaddr);
    }
}


//  --------------------------------------------------------------------------
//  send create asses if it is new
void
ftydiscovery_create_asset (ftydiscovery_t *self, zmsg_t **msg_p)
{
    if (!self || !msg_p) return;
    if (!is_fty_proto (*msg_p)) return;

    fty_proto_t *asset = fty_proto_decode (msg_p);
    const char *ip = fty_proto_ext_string (asset, "ip.1", NULL);
    if (!ip) return;

    if (assets_find (self->assets, "ip", ip)) {
        zsys_info ("Asset with IP address %s already exists", ip);
        return;
    }

    const char *uuid = fty_proto_ext_string (asset, "uuid", NULL);
    if (uuid && assets_find (self->assets, "uuid", uuid)) {
        zsys_info ("Asset with uuid %s already exists", uuid);
        return;
    }

    fty_proto_aux_insert (asset, "status", "%s", "nonactive");

    // set name
    const char *name = fty_proto_ext_string (asset, "hostname", NULL);
    if (name) {
        fty_proto_ext_insert (asset, "name", "%s", name);
    } else {
        name = fty_proto_aux_string (asset, "subtype", NULL);
        if (name) {
            fty_proto_ext_insert (asset, "name", "%s (%s)", name, ip);
        } else {
            fty_proto_ext_insert (asset, "name", "%s", ip);
        }
    }

    std::time_t timestamp = std::time(NULL);
    char mbstr[100];
    if(std::strftime(mbstr, sizeof(mbstr), "%FT%T%z", std::localtime(&timestamp))) {
        fty_proto_ext_insert(asset, "discovered_ts", "%s", mbstr);
    }

    fty_proto_print (asset);

    zsys_info ("Found new asset %s with IP address %s", fty_proto_ext_string(asset, "name", ""), ip);
    fty_proto_set_operation (asset, "create");
    zmsg_t *msg = fty_proto_encode (&asset);
    zsys_debug ("about to send create message");
    int rv = mlm_client_sendto (self->mlm, "asset-agent", "ASSET_MANIPULATION", NULL, 10, &msg);
    if (rv == -1) {
        zsys_error ("Failed to send ASSET_MANIPULATION message to asset-agent");
    } else {
        zsys_info ("Create message has been sent to asset-agent (rv = %i)", rv);
        self->nb_discovered++;
    }
}

//  --------------------------------------------------------------------------
//  ftydiscovery actor

void
ftydiscovery_actor (zsock_t *pipe, void *args)
{
    ftydiscovery_t *self = ftydiscovery_new();
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (self->mlm), NULL);
    zactor_t *range_scanner = NULL;
    zsock_signal (pipe, 0);
    range_scan_args_t range_scan_config;
    range_scan_config.config = NULL;
    range_scan_config.range = NULL;
    zmsg_t *range_stack = zmsg_new ();
    char *percent = NULL;

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, 5000);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            if (msg) {
                char *cmd = zmsg_popstr (msg);
                zsys_debug ("Pipe command %s received", cmd ? cmd : "(null)");
                if (cmd) {
                    if (streq (cmd, "$TERM")) {
                        zstr_free (&cmd);
                        zmsg_destroy (&msg);
                        break;
                    }
                    else if (streq (cmd, "BIND")) {
                        char *endpoint = zmsg_popstr (msg);
                        char *myname = zmsg_popstr (msg);
                        assert (endpoint && myname);
                        mlm_client_connect (self->mlm, endpoint, 5000, myname);
                        zstr_free (&endpoint);
                        zstr_free (&myname);
                    }
                    else if (streq (cmd, "CONSUMER")) {
                        char *stream = zmsg_popstr (msg);
                        char *pattern = zmsg_popstr (msg);
                        assert (stream && pattern);
                        mlm_client_set_consumer (self->mlm, stream, pattern);
                        zstr_free (&stream);
                        zstr_free (&pattern);
                        // ask for assets now
                        zmsg_t *republish = zmsg_new ();
                        zmsg_addstr (republish, "$all");
                        mlm_client_sendto (self->mlm, "asset-agent", "REPUBLISH", NULL, 1000, &republish);
                    }
                    else if (streq (cmd, "CONFIG")) {
                        zstr_free (&range_scan_config.config);
                        range_scan_config.config = zmsg_popstr (msg);
                    }
                    else if (streq (cmd, "SCAN")) {
                        if (range_scanner) {
                            self->nb_discovered = 0;
                            zpoller_remove (poller, range_scanner);
                            zactor_destroy (&range_scanner);
                        }
                        
                        self->quickscan_subnets.clear();
                        self->quickscan_size = 0;
                        zstr_free (&range_scan_config.range);
                        range_scan_config.range = zmsg_popstr (msg);
                    }
                    else if (streq (cmd, "QUICKSCAN")) {
                        if (range_scanner) {
                            self->nb_discovered = 0;
                            zpoller_remove (poller, range_scanner);
                            zactor_destroy (&range_scanner);
                        }
                        
                        self->quickscan_subnets.clear();
                        self->quickscan_size = 0;
                        
                        configure_quick_scan(self);
                        
                        if(self->quickscan_size > 0)
                        {
                            zstr_free (&range_scan_config.range);
                            
                            zmsg_t *zmfalse = zmsg_new ();
                            zmsg_addstr(zmfalse, self->quickscan_subnets.back().first.c_str());                            
                            range_scan_config.range = zmsg_popstr(zmfalse);
                            
                            self->nb_discovered = 0;                           
                            zmsg_destroy (&zmfalse);
                        }
                        
                    }
                    zstr_free (&cmd);
                }
                zmsg_destroy (&msg);
            }
        }
        else if (which == mlm_client_msgpipe (self->mlm)) {
            zmsg_t *msg = mlm_client_recv (self->mlm);
            if (is_fty_proto (msg)) {
                fty_proto_t *fmsg = fty_proto_decode (&msg);
                assets_put (self->assets, &fmsg);
                fty_proto_destroy (&fmsg);
            } else {
                // handle REST API requests
                char *cmd = zmsg_popstr (msg);
                if (cmd) {
                    // RUNSCAN
                    // <uuid>
                    // <config> (can be empty - then default config is used)
                    // <range>
                    if (streq (cmd, "RUNSCAN")) {
                        if (percent)
                            zstr_free (&percent);
                        percent = strdup ("0");
                        char *zuuid = zmsg_popstr (msg);
                        zmsg_t *reply = zmsg_new ();
                        zmsg_addstr (reply, zuuid);

                        self->quickscan_subnets.clear();
                        self->quickscan_size = 0;
                        
                        zstr_free (&range_scan_config.config);
                        range_scan_config.config = zmsg_popstr (msg);
                        if (streq (range_scan_config.config, ""))
                            range_scan_config.config = strdup ("/etc/default/fty.cfg");
                        zstr_free (&range_scan_config.range);
                        range_scan_config.range = zmsg_popstr (msg);

                        if (range_scan_config.range) {
                            zsys_debug ("Range scanner requested for %s with config file %s", range_scan_config.range, range_scan_config.config);
                            // create range scanner
                            if (range_scanner) {
                                zpoller_remove (poller, range_scanner);
                                zactor_destroy (&range_scanner);
                            }
                            self->nb_discovered = 0;
                            range_scanner = zactor_new (range_scan_actor, &range_scan_config);
                            zpoller_add (poller, range_scanner);

                            zmsg_addstr (reply, "OK");
                        }
                        else
                            zmsg_addstr (reply, "ERROR");
                        mlm_client_sendto (self->mlm, mlm_client_sender (self->mlm), mlm_client_subject (self->mlm), mlm_client_tracker (self->mlm), 1000, &reply);
                    }
                    else if (streq (cmd, "PROGRESS")) {
                        char *zuuid = zmsg_popstr (msg);
                        zmsg_t *reply = zmsg_new ();
                        zmsg_addstr (reply, zuuid);
                        if (percent) {
                            zmsg_addstr (reply, "OK");
                            zmsg_addstr (reply, percent);
                            zmsg_addstrf(reply, "%" PRIi64, self->nb_discovered);
                        }
                        else
                            zmsg_addstr (reply, "ERROR");
                        mlm_client_sendto (self->mlm, mlm_client_sender (self->mlm), mlm_client_subject (self->mlm), mlm_client_tracker (self->mlm), 1000, &reply);
                    }
                    else if(streq (cmd, "STOPSCAN")) {
                            if (range_scanner) {
                                zpoller_remove (poller, range_scanner);
                                zactor_destroy (&range_scanner);
                            }

                        zstr_free (&range_scan_config.config);
                        zstr_free (&range_scan_config.range);

                        self->quickscan_subnets.clear();
                        self->quickscan_size = 0;
                        
                        char *zuuid = zmsg_popstr (msg);
                        zmsg_t *reply = zmsg_new ();
                        zmsg_addstr (reply, zuuid);
                        zmsg_addstr (reply, "OK");
                        mlm_client_sendto (self->mlm, mlm_client_sender (self->mlm), mlm_client_subject (self->mlm), mlm_client_tracker (self->mlm), 1000, &reply);

                    }
                    else if(streq (cmd, "QUICKSCAN")) {
                        
                        if (percent)
                            zstr_free (&percent);
                        percent = strdup ("0");
                        
                        char *zuuid = zmsg_popstr (msg);
                        zmsg_t *reply = zmsg_new ();
                        zmsg_addstr (reply, zuuid);
                        
                        self->quickscan_subnets.clear();
                        self->quickscan_size = 0;
                        
                        zstr_free (&range_scan_config.config);
                        range_scan_config.config = zmsg_popstr (msg);
                        if (streq (range_scan_config.config, ""))
                            range_scan_config.config = strdup ("/etc/default/fty.cfg");
                        
                        configure_quick_scan(self);
                        
                        if(self->quickscan_size > 0)
                        {
                            zstr_free (&range_scan_config.range);
                            
                            zmsg_t *zmfalse = zmsg_new ();
                            zmsg_addstr(zmfalse, self->quickscan_subnets.back().first.c_str());                            
                            range_scan_config.range = zmsg_popstr(zmfalse);
                            
                            zsys_debug ("Range scanner requested for %s with config file %s %s", range_scan_config.range, range_scan_config.config);
                           
                            // create range scanner
                            if (range_scanner) {
                                zpoller_remove (poller, range_scanner);
                                zactor_destroy (&range_scanner);
                            }
                            self->nb_discovered = 0;
                            range_scanner = zactor_new (range_scan_actor, &range_scan_config);
                            zpoller_add (poller, range_scanner);
                            
                            zmsg_destroy (&zmfalse);
                            zmsg_addstr (reply, "OK");
                        }
                        else
                            zmsg_addstr (reply, "ERROR");
                        
                        
                        mlm_client_sendto (self->mlm, mlm_client_sender (self->mlm), mlm_client_subject (self->mlm), mlm_client_tracker (self->mlm), 1000, &reply);
                    }
                    zstr_free (&cmd);
                }
            }
            zmsg_destroy (&msg);
        }
        else if (range_scanner && which == range_scanner) {
            zmsg_t *msg = zmsg_recv (range_scanner);
            zsys_debug ("Range scanner message received");
            if (msg) {
                zmsg_print (msg);
                char *cmd = zmsg_popstr (msg);
                zsys_debug ("Range scanner message: %s", cmd);
                if (cmd) {
                    if (streq (cmd, "DONE")) {
                        if(self->quickscan_subnets.size() > 1)
                        {
                            //not done yet, still the others subnets to do
                            
                            //remove the done subnet
                            self->quickscan_subnets.pop_back();
                            
                            //start another one
                            zstr_free (&range_scan_config.range);
                            zmsg_t *zmfalse = zmsg_new ();
                            zmsg_addstr(zmfalse, self->quickscan_subnets.back().first.c_str());                            
                            range_scan_config.range = zmsg_popstr(zmfalse);
                            
                            zsys_debug ("Range scanner requested for %s with config file %s", range_scan_config.range, range_scan_config.config);
                           
                            // create range scanner
                            if (range_scanner) {
                                zpoller_remove (poller, range_scanner);
                                zactor_destroy (&range_scanner);
                            }
                            
                            range_scanner = zactor_new (range_scan_actor, &range_scan_config);
                            zpoller_add (poller, range_scanner); 
                            
                            zmsg_destroy(&zmfalse);
                        }
                        else
                            zstr_send (pipe, "DONE");
                    }
                    else if (streq (cmd, "FOUND")) {
                        ftydiscovery_create_asset (self, &msg);
                    }
                    else if (streq (cmd, "PROGRESS")) {                            
                        if (percent)
                            zstr_free (&percent);
                        
                        percent = zmsg_popstr (msg);
                        
                        if(self->quickscan_subnets.size() > 0)
                        {
                            std::string percentstr = std::to_string( (atoi(percent) * self->quickscan_subnets.back().second) / self->quickscan_size);
                                 
                            zstr_free (&percent);
                            
                            zmsg_t *zmfalse = zmsg_new ();
                            zmsg_addstr(zmfalse, percentstr.c_str());                            
                            percent = zmsg_popstr(zmfalse);     
                            zmsg_destroy(&zmfalse);
                        }   
                    }
                    zstr_free (&cmd);
                }
                zmsg_destroy (&msg);
            }
        }
        // check that scanner is NULL && we have to do scan
        if (range_scan_config.range && !range_scanner) {
            if (zclock_mono () - assets_last_change (self->assets) > 5000) {
                // no asset change for last 5 secs => we can start range scan
                zsys_debug ("Range scanner start for %s with config file %s", range_scan_config.range, range_scan_config.config);
                // create range scanner
                // TODO: send list of IPs to skip
                self->nb_discovered = 0;
                if(percent)
                    zstr_free (&percent);
                range_scanner = zactor_new (range_scan_actor, &range_scan_config);
                zpoller_add (poller, range_scanner);
            }
        }
    }

    zstr_free (&percent);
    zstr_free (&range_scan_config.config);
    zstr_free (&range_scan_config.range);
    zmsg_destroy (&range_stack);
    zactor_destroy (&range_scanner);
    ftydiscovery_destroy (&self);
    zpoller_destroy (&poller);
}

//  --------------------------------------------------------------------------
//  Create a new ftydiscovery

ftydiscovery_t *
ftydiscovery_new ()
{
    ftydiscovery_t *self = (ftydiscovery_t *) zmalloc (sizeof (ftydiscovery_t));
    assert (self);
    //  Initialize class properties here
    self->mlm = mlm_client_new ();
    self->scanner = NULL;
    self->assets = assets_new ();
    self->nb_discovered = 0;
    self->quickscan_size = 0;
    return self;
}

void
ftydiscovery_destroy (ftydiscovery_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        ftydiscovery_t *self = *self_p;
        //  Free class properties here
        zactor_destroy (&self->scanner);
        mlm_client_destroy (&self->mlm);
        assets_destroy (&self->assets);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
ftydiscovery_test (bool verbose)
{
    printf (" * ftydiscovery: ");

    //  @selftest
    //  Simple create/destroy test
    zactor_t *self = zactor_new (ftydiscovery_actor, NULL);
    assert (self);
    zclock_sleep (500);
    zactor_destroy (&self);
    //  @end
    printf ("OK\n");
}
