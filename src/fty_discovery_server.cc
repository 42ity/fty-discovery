/*  =========================================================================
    fty_discovery_server - Manages discovery requests, provides feedback

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
    fty_discovery_server - Manages discovery requests, provides feedback
@discuss
@end
 */

#include <ctime>
#include <vector>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string>
#include <cxxtools/jsonserializer.h>
#include <cxxtools/serializationinfo.h>
#include "fty_discovery_classes.h"

//  Structure of our class
typedef struct _configuration_scan_t {
    std::vector<std::string> scan_list;
    int64_t scan_size;
    uint8_t type;
} configuration_scan_t;

struct _fty_discovery_server_t {
    mlm_client_t *mlm;
    zactor_t *scanner;
    assets_t *assets;
    int64_t nb_percent;
    int64_t nb_discovered;
    int64_t scan_size;
    int64_t nb_ups_discovered;
    int64_t nb_epdu_discovered;
    int64_t nb_sts_discovered;
    int32_t status_scan;
    bool ongoing_stop;
    std::vector<std::string> localscan_subscan;
    range_scan_args_t range_scan_config;
    configuration_scan_t configuration_scan;
    zactor_t *range_scanner;
    char *percent;
};

void reset_nb_discovered(fty_discovery_server_t *self) {
    self->nb_discovered = 0;
    self->nb_epdu_discovered = 0;
    self->nb_sts_discovered = 0;
    self->nb_ups_discovered = 0; 
}

bool compute_ip_list(std::vector<std::string>* listIp) {
    for (unsigned int iPosIp = 0; iPosIp < listIp->size(); iPosIp++) {
        std::string ips = listIp->at(iPosIp);
        CIDRAddress addrCIDR(ips, 32);
        if (addrCIDR.prefix() != -1) {
            zsys_debug("valid ip %s", ips.c_str());
            listIp->at(iPosIp) = addrCIDR.toString();
        } else {
            //not a valid address
            zsys_error("Address (%s) is not valid!", ips.c_str());
            return false;
        }
    }

    return true;
}

bool compute_scans_size(std::vector<std::string>* list_scan, int64_t* scan_size) {
    *scan_size = 0;
    for (unsigned int iPosScan = 0; iPosScan < list_scan->size(); iPosScan++) {
        std::string scan = list_scan->at(iPosScan);
        int pos = scan.find("-");

        //if subnet
        if (pos == -1) {
            CIDRAddress addrCIDR(scan);

            if (addrCIDR.prefix() != -1) {
                zsys_debug("valid subnet %s", scan.c_str());
                //all the subnet (1 << (32- prefix) ) minus subnet and broadcast address
                if (addrCIDR.prefix() <= 30)
                    (*scan_size) += ((1 << (32 - addrCIDR.prefix())) - 2);
                else //31/32 prefix special management
                    (*scan_size) += (1 << (32 - addrCIDR.prefix()));
            } else {
                //not a valid range
                zsys_error("Address subnet (%s) is not valid!", scan.c_str());
                return false;
            }
        }// else : range
        else {
            std::string rangeStart = scan.substr(0, pos);
            std::string rangeEnd = scan.substr(pos + 1);
            CIDRAddress addrStart(rangeStart);
            CIDRAddress addrEnd(rangeEnd);

            if (!addrStart.valid() || !addrEnd.valid() || (addrStart > addrEnd)) {
                zsys_error("(%s) is not a valid range!", scan.c_str());
                return false;
            }

            int posC = rangeStart.find_last_of(".");
            int64_t size1 = 0;
            std::string startOfAddr = rangeStart.substr(0, posC);
            size1 += atoi(rangeStart.substr(posC + 1).c_str());

            posC = startOfAddr.find_last_of(".");
            size1 += atoi(startOfAddr.substr(posC + 1).c_str())*256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size1 += atoi(startOfAddr.substr(posC + 1).c_str())*256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size1 += atoi(startOfAddr.substr(posC + 1).c_str())*256 * 256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = rangeEnd.find_last_of(".");
            int64_t size2 = 0;
            startOfAddr = rangeEnd.substr(0, posC);
            size2 += atoi(rangeEnd.substr(posC + 1).c_str());

            posC = startOfAddr.find_last_of(".");
            size2 += atoi(startOfAddr.substr(posC + 1).c_str())*256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size2 += atoi(startOfAddr.substr(posC + 1).c_str())*256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size2 += atoi(startOfAddr.substr(posC + 1).c_str())*256 * 256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            (*scan_size) += (size2 - size1) + 1;

            pos = rangeStart.find("/");
            if (pos != -1) {
                rangeStart = rangeStart.substr(0, pos);
            }

            pos = rangeEnd.find("/");
            if (pos != -1) {
                rangeEnd = rangeEnd.substr(0, pos);
            }
            std::string correct_range = rangeStart + "/0-" + rangeEnd + "/0";
            list_scan->at(iPosScan) = correct_range;

            zsys_debug("valid range (%s-%s). Size: %" PRIi64, rangeStart.c_str(), rangeEnd.c_str(), (size2 - size1) + 1);
        }
    }

    return true;
}

std::string form_config_reply(const char* configFile) {
    try {

        zconfig_t *config = zconfig_load(configFile);
        if (!config) {
            zsys_error("failed to load config file %s", configFile);
            config = zconfig_new("root", NULL);
        }

        char* strType = zconfig_get(config, "/discovery/type", "localscan");

        std::vector<std::string> scan_list, listIp;

        zconfig_t *section = zconfig_locate(config, "/discovery/scans");
        if (section) {
            zconfig_t *item = zconfig_child(section);
            while (item) {
                //FIXME : can't delete item in cfg for now...
                if (streq(zconfig_value(item), ""))
                    break;
                scan_list.push_back(zconfig_value(item));
                item = zconfig_next(item);
            }
        }

        section = zconfig_locate(config, "/discovery/ips");
        if (section) {
            zconfig_t *item = zconfig_child(section);
            while (item) {
                //FIXME : can't delete item in cfg for now...
                if (streq(zconfig_value(item), ""))
                    break;
                listIp.push_back(zconfig_value(item));
                item = zconfig_next(item);
            }
        }

        cxxtools::SerializationInfo si;
        si.addMember("scan_type") <<= strType;

        cxxtools::SerializationInfo& si_multiscan = si.addMember("multiscan");
        cxxtools::SerializationInfo& si_liste1 = si_multiscan.addMember("subnet");
        si_liste1.setCategory(cxxtools::SerializationInfo::Array);
        std::vector<std::string> listsubnet, listfromto;
        for (unsigned int i = 0; i < scan_list.size(); i++) {
            std::string scan = scan_list.at(i);
            size_t pos = scan.find("-");
            if (pos != std::string::npos) {
                std::string rangeStart = scan.substr(0, pos);
                std::string rangeEnd = scan.substr(pos + 1);
                rangeStart = rangeStart.substr(0, rangeStart.find("/"));
                rangeEnd = rangeEnd.substr(0, rangeEnd.find("/"));
                scan = rangeStart;
                scan.append("-");
                scan.append(rangeEnd);
                listfromto.push_back(scan);
            } else {
                listsubnet.push_back(scan);
            }
        }

        for (unsigned int i = 0; i < listsubnet.size(); i++) {
            si_liste1.addMember("") <<= listsubnet.at(i);
        }

        cxxtools::SerializationInfo& si_liste2 = si_multiscan.addMember("from_to");
        si_liste2.setCategory(cxxtools::SerializationInfo::Array);
        for (unsigned int i = 0; i < listfromto.size(); i++) {
            si_liste2.addMember("") <<= listfromto.at(i);
        }

        cxxtools::SerializationInfo& si_listip = si.addMember("ips");
        si_listip.setCategory(cxxtools::SerializationInfo::Array);
        for (unsigned int i = 0; i < listIp.size(); i++) {
            si_listip.addMember("") <<= listIp.at(i).substr(0, listIp.at(i).find("/"));
        }

        // serialize to json
        std::ostringstream result;
        cxxtools::JsonSerializer serializer(result);

        serializer.serialize(si).finish();
        return result.str();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    return "";
}

int mask_nb_bit(std::string mask) {
    size_t pos;
    int res = 0;
    std::string part;
    while ((pos = mask.find(".")) != std::string::npos) {
        part = mask.substr(0, pos);
        if (part == "255")
            res += 8;
        else if (part == "254")
            return res + 7;
        else if (part == "252")
            return res + 6;
        else if (part == "248")
            return res + 5;
        else if (part == "240")
            return res + 4;
        else if (part == "224")
            return res + 3;
        else if (part == "192")
            return res + 2;
        else if (part == "128")
            return res + 1;
        else if (part == "0")
            return res;
        else //error
            return -1;

        mask.erase(0, pos + 1);
    }

    if (mask == "255")
        res += 8;
    else if (mask == "254")
        res += 7;
    else if (mask == "252")
        res += 6;
    else if (mask == "248")
        res += 5;
    else if (mask == "240")
        res += 4;
    else if (mask == "224")
        res += 3;
    else if (mask == "192")
        res += 2;
    else if (mask == "128")
        res += 1;
    else if (mask == "0")
        return res;
    else
        return -1;

    return res;
}

void configure_local_scan(fty_discovery_server_t *self) {
    int s, family, prefix;
    char host[NI_MAXHOST];
    struct ifaddrs *ifaddr, *ifa;
    std::string addr, netm, addrmask;

    self->scan_size = 0;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (streq(ifa->ifa_name, "lo"))
                continue;
            if (ifa->ifa_addr == NULL)
                continue;

            family = ifa->ifa_addr->sa_family;
            if (family != AF_INET)
                continue;

            s = getnameinfo(ifa->ifa_addr, sizeof (struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                zsys_debug("IP address parsing error for %s : %s", ifa->ifa_name, gai_strerror(s));
                continue;
            } else
                addr.assign(host);

            if (ifa->ifa_netmask == NULL) {
                zsys_debug("No netmask found for %s", ifa->ifa_name);
                continue;
            }

            family = ifa->ifa_netmask->sa_family;
            if (family != AF_INET)
                continue;

            s = getnameinfo(ifa->ifa_netmask, sizeof (struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                zsys_debug("Netmask parsing error for %s : %s", ifa->ifa_name, gai_strerror(s));
                continue;
            } else
                netm.assign(host);

            prefix = 0;
            addrmask.clear();

            prefix = mask_nb_bit(netm);

            //all the subnet (1 << (32- prefix) ) minus subnet and broadcast address
            if (prefix <= 30)
                self->scan_size += ((1 << (32 - prefix)) - 2);
            else //31/32 prefix special management
                self->scan_size += (1 << (32 - prefix));


            CIDRAddress addrCidr(addr, prefix);

            addrmask.clear();
            addrmask.assign(addrCidr.network().toString());

            self->localscan_subscan.push_back(addrmask);
            zsys_info("Localscan subnet found for %s : %s", ifa->ifa_name, addrmask.c_str());

        }

        freeifaddrs(ifaddr);
    }
}


//  --------------------------------------------------------------------------
//  send create asses if it is new

void
ftydiscovery_create_asset(fty_discovery_server_t *self, zmsg_t **msg_p) {
    if (!self || !msg_p) return;
    if (!is_fty_proto(*msg_p)) return;

    fty_proto_t *asset = fty_proto_decode(msg_p);
    const char *ip = fty_proto_ext_string(asset, "ip.1", NULL);
    if (!ip) return;

    if (assets_find(self->assets, "ip", ip)) {
        zsys_info("Asset with IP address %s already exists", ip);
        return;
    }

    const char *uuid = fty_proto_ext_string(asset, "uuid", NULL);
    if (uuid && assets_find(self->assets, "uuid", uuid)) {
        zsys_info("Asset with uuid %s already exists", uuid);
        return;
    }

    fty_proto_aux_insert(asset, "status", "%s", "nonactive");

    // set name
    const char *name = fty_proto_ext_string(asset, "hostname", NULL);
    if (name) {
        fty_proto_ext_insert(asset, "name", "%s", name);
    } else {
        name = fty_proto_aux_string(asset, "subtype", NULL);
        if (name) {
            fty_proto_ext_insert(asset, "name", "%s (%s)", name, ip);
        } else {
            fty_proto_ext_insert(asset, "name", "%s", ip);
        }
    }

    std::time_t timestamp = std::time(NULL);
    char mbstr[100];
    if (std::strftime(mbstr, sizeof (mbstr), "%FT%T%z", std::localtime(&timestamp))) {
        fty_proto_ext_insert(asset, "discovered_ts", "%s", mbstr);
    }

    fty_proto_print(asset);
    zsys_info("Found new asset %s with IP address %s", fty_proto_ext_string(asset, "name", ""), ip);
    fty_proto_set_operation(asset, "create");

    fty_proto_t *assetDup = fty_proto_dup(asset);
    zmsg_t *msg = fty_proto_encode(&assetDup);
    zsys_debug("about to send create message");
    int rv = mlm_client_sendto(self->mlm, "asset-agent", "ASSET_MANIPULATION", NULL, 10, &msg);
    if (rv == -1) {
        zsys_error("Failed to send ASSET_MANIPULATION message to asset-agent");
    } else {
        zsys_info("Create message has been sent to asset-agent (rv = %i)", rv);

        name = fty_proto_aux_string(asset, "subtype", NULL);
        if (streq(name, "ups")) self->nb_ups_discovered++;
        else if (streq(name, "epdu")) self->nb_epdu_discovered++;
        else if (streq(name, "sts")) self->nb_sts_discovered++;
        self->nb_discovered++;
    }
    fty_proto_destroy(&asset);
}

//  --------------------------------------------------------------------------
//  process pipe message
//  return true means continue, false means TERM
//  * $TERM
//  * BIND
//  * CONFIG
//  * SCAN
//  * LOCALSCAN

bool static
s_handle_pipe(fty_discovery_server_t* self, zmsg_t *message, zpoller_t *poller) {
    if (!message)
        return true;
    char *command = zmsg_popstr(message);
    if (!command) {
        zmsg_destroy(&message);
        zsys_warning("Empty command.");
        return true;
    }
    zsys_debug("s_handle_pipe DO %s", command);
    if (streq(command, "$TERM")) {
        zsys_info("Got $TERM");
        zmsg_destroy(&message);
        zstr_free(&command);
        return false;
    } else if (streq(command, "BIND")) {
        char *endpoint = zmsg_popstr(message);
        char *myname = zmsg_popstr(message);
        assert(endpoint && myname);
        mlm_client_connect(self->mlm, endpoint, 5000, myname);
        zstr_free(&endpoint);
        zstr_free(&myname);
    } else if (streq(command, "CONSUMER")) {
        char *stream = zmsg_popstr(message);
        char *pattern = zmsg_popstr(message);
        assert(stream && pattern);
        mlm_client_set_consumer(self->mlm, stream, pattern);
        zstr_free(&stream);
        zstr_free(&pattern);
        // ask for assets now
        zmsg_t *republish = zmsg_new();
        zmsg_addstr(republish, "$all");
        mlm_client_sendto(self->mlm, "asset-agent", "REPUBLISH", NULL, 1000, &republish);
    } else if (streq(command, "CONFIG")) {
        zstr_free(&self->range_scan_config.config);
        self->range_scan_config.config = zmsg_popstr(message);
        zconfig_t *config = zconfig_load(self->range_scan_config.config);
        if (!config) {
            zsys_error("failed to load config file %s", self->range_scan_config.config);
            config = zconfig_new("root", NULL);
        }
        char* strType = zconfig_get(config, "/discovery/type", "localscan");
        std::vector<std::string> list_scans, listIp;
        bool valid = true;
        zconfig_t *section = zconfig_locate(config, "/discovery/scans");
        if (section) {
            zconfig_t *item = zconfig_child(section);
            while (item) {
                //FIXME : can't delete item in cfg for now...
                if (streq(zconfig_value(item), ""))
                    break;
                list_scans.push_back(zconfig_value(item));
                item = zconfig_next(item);
            }
        }
        section = zconfig_locate(config, "/discovery/ips");
        if (section) {
            zconfig_t *item = zconfig_child(section);
            while (item) {
                //FIXME : can't delete item in cfg for now...
                if (streq(zconfig_value(item), ""))
                    break;
                listIp.push_back(zconfig_value(item));
                item = zconfig_next(item);
            }
        }
        if (list_scans.empty() && streq(strType, "multiscan")) {
            valid = false;
            zsys_error("error in config file %s : can't have rangescan without range", self->range_scan_config.config);
        } else if (listIp.empty() && streq(strType, "ipscan")) {
            valid = false;
            zsys_error("error in config file %s : can't have ipscan without ip list", self->range_scan_config.config);
        } else {
            int64_t sizeTemp = 0;
            if (compute_scans_size(&list_scans, &sizeTemp) && compute_ip_list(&listIp)) {
                //ok, validate the config
                if (streq(strType, "multiscan"))
                    self->configuration_scan.type = TYPE_MULTISCAN;
                else if (streq(strType, "localscan"))
                    self->configuration_scan.type = TYPE_LOCALSCAN;
                else
                    self->configuration_scan.type = TYPE_IPSCAN;
                self->configuration_scan.scan_size = sizeTemp;
                self->configuration_scan.scan_list.clear();
                self->configuration_scan.scan_list = list_scans;

                if (self->configuration_scan.type == TYPE_IPSCAN) {
                    self->configuration_scan.scan_size = listIp.size();
                    self->configuration_scan.scan_list.clear();
                    self->configuration_scan.scan_list = listIp;
                }

            } else {
                valid = false;
                zsys_error("error in config file %s: error in scans", self->range_scan_config.config);
            }
        }

        if (valid)
            zsys_debug("config file %s applied successfully", self->range_scan_config.config);
    } else if (streq(command, "SCAN")) {
        if (self->range_scanner) {
            reset_nb_discovered(self);
            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        }
        self->ongoing_stop = false;
        self->localscan_subscan.clear();
        self->scan_size = 0;
        zstr_free(&self->range_scan_config.range);
        zstr_free(&self->range_scan_config.range_dest);
        self->range_scan_config.range = zmsg_popstr(message);
        if (self->range_scan_config.range) {
            CIDRAddress addrCIDR(self->range_scan_config.range);

            if (addrCIDR.prefix() != -1) {
                //all the subnet (1 << (32- prefix) ) minus subnet and broadcast address
                if (addrCIDR.prefix() <= 30)
                    self->scan_size = ((1 << (32 - addrCIDR.prefix())) - 2);
                else //31/32 prefix special management
                    self->scan_size = (1 << (32 - addrCIDR.prefix()));
            } else {
                //not a valid range
                zsys_error("Address range (%s) is not valid!", self->range_scan_config.range);
                zstr_free(&self->range_scan_config.range);
            }

        }
    } else if (streq(command, "LOCALSCAN")) {
        if (self->range_scanner) {
            reset_nb_discovered(self);
            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        }
        
        self->ongoing_stop = false;
        self->localscan_subscan.clear();
        self->scan_size = 0;
        configure_local_scan(self);
        if (self->scan_size > 0) {
            zstr_free(&self->range_scan_config.range);
            zstr_free(&self->range_scan_config.range_dest);

            zmsg_t *zmfalse = zmsg_new();
            zmsg_addstr(zmfalse, self->localscan_subscan.back().c_str());
            self->range_scan_config.range = zmsg_popstr(zmfalse);

            reset_nb_discovered(self);
            zmsg_destroy(&zmfalse);
        }

    } else
        zsys_error("s_handle_pipe: Unknown command: %s.\n", command);
    zstr_free(&command);
    zmsg_destroy(&message);
    return true;
}

//  --------------------------------------------------------------------------
//  process message from MAILBOX DELIVER 
//  * SETCONFIG, 
//       REQ : <uuid> <type_of_scan><nb_of_scan><scan1><scan2>..
//  * GETCONFIG
//       REQ : <uuid>
//  * LAUNCHSCAN
//       REQ : <uuid>
//  * PROGRESS
//       REQ : <uuid>
//  * STOPSCAN
//       REQ : <uuid>

void static
s_handle_mailbox(fty_discovery_server_t* self, zmsg_t *msg, zpoller_t *poller) {
    if (is_fty_proto(msg)) {
        fty_proto_t *fmsg = fty_proto_decode(&msg);
        assets_put(self->assets, &fmsg);
        fty_proto_destroy(&fmsg);
    } else {
        // handle REST API requests
        char *cmd = zmsg_popstr(msg);
        if (!cmd) {
            zmsg_destroy(&msg);
            zsys_warning("s_handle_mailbox Empty command.");
            return;
        }
        zsys_debug("s_handle_mailbox DO : %s", cmd);
        if (streq(cmd, "SETCONFIG")) {
            // SETCONFIG 
            // REQ <uuid> <type_of_scan><nb_of_scan><scan1><scan2>...
            char *zuuid = zmsg_popstr(msg);
            zmsg_t *reply = zmsg_new();
            zmsg_addstr(reply, zuuid);

            bool config_valid = true;
            char *scanType = zmsg_popstr(msg);
            if (streq(scanType, "multiscan") || streq(scanType, "localscan") || streq(scanType, "ipscan")) {
                char *scanNumber = zmsg_popstr(msg);
                char *configValue;
                int nbScan = atoi(scanNumber);
                int64_t sizeTemp = 0;
                std::vector<std::string> list_scans;
                zstr_free(&scanNumber);
                for (int i = 0; i < nbScan; i++) {
                    configValue = zmsg_popstr(msg);
                    if (configValue) {
                        std::string str(configValue);
                        list_scans.push_back(str);
                        zstr_free(&configValue);
                    } else {
                        zsys_error("error in config : error in rangesNot enough \"range\"");
                        config_valid = false;
                        break;
                    }
                }
                //IPs list
                scanNumber = zmsg_popstr(msg);
                nbScan = atoi(scanNumber);
                std::vector<std::string> listIp;
                zstr_free(&scanNumber);
                for (int i = 0; i < nbScan; i++) {
                    configValue = zmsg_popstr(msg);
                    if (configValue) {
                        std::string str(configValue);
                        listIp.push_back(str);
                        zstr_free(&configValue);
                    } else {
                        zsys_error("error in config : error in IPs. Not enough IPs.");
                        config_valid = false;
                        break;
                    }
                }

                if (config_valid && compute_scans_size(&list_scans, &sizeTemp) && compute_ip_list(&listIp)) {
                    //ok, validate the config
                    if (streq(scanType, "multiscan"))
                        self->configuration_scan.type = TYPE_MULTISCAN;
                    else if (streq(scanType, "localscan"))
                        self->configuration_scan.type = TYPE_LOCALSCAN;
                    else
                        self->configuration_scan.type = TYPE_IPSCAN;
                    self->configuration_scan.scan_size = sizeTemp;
                    self->configuration_scan.scan_list.clear();
                    self->configuration_scan.scan_list = list_scans;

                    if (self->configuration_scan.type == TYPE_IPSCAN) {
                        self->configuration_scan.scan_size = listIp.size();
                        self->configuration_scan.scan_list.clear();
                        self->configuration_scan.scan_list = listIp;
                    }
                    if (config_valid) {
                        zconfig_t *config = zconfig_load(self->range_scan_config.config);
                        if (!config) {
                            zsys_error("failed to load config file %s", self->range_scan_config.config);
                            config = zconfig_new("root", NULL);
                        }
                        //FIXME : we need to delete old informations...
                        //zconfig_t *section_discovery = zconfig_locate (config, "/discovery");
                        //zconfig_destroy(&section_discovery);
                        //section_discovery = zconfig_new("discovery", config);

                        zconfig_t *section = zconfig_locate(config, "/discovery/scans");
                        if (section) {
                            zconfig_t *item = zconfig_child(section);
                            while (item) {
                                //FIXME : can't delete item in cfg for now...
                                if (streq(zconfig_value(item), ""))
                                    break;
                                zconfig_set_value(item, NULL);
                                item = zconfig_next(item);
                            }
                        }
                        section = zconfig_locate(config, "/discovery/ips");
                        if (section) {
                            zconfig_t *item = zconfig_child(section);
                            while (item) {
                                //FIXME : can't delete item in cfg for now...
                                if (streq(zconfig_value(item), ""))
                                    break;
                                zconfig_set_value(item, NULL);
                                item = zconfig_next(item);
                            }
                        }
                        //add new informations
                        zconfig_put(config, "/discovery/type", scanType);
                        std::ostringstream oss;
                        for (unsigned int i = 0; i < list_scans.size(); i++) {
                            oss.str("");
                            oss << "/discovery/scans/scanNumber" << i;
                            zconfig_put(config, oss.str().c_str(), list_scans.at(i).c_str());
                        }

                        for (unsigned int i = 0; i < listIp.size(); i++) {
                            oss.str("");
                            oss << "/discovery/ips/ipNumber" << i;
                            zconfig_put(config, oss.str().c_str(), listIp.at(i).c_str());
                        }

                        section = zconfig_locate(config, "/discovery/scans");
                        if(section)
                            zconfig_set_value(section, NULL);
                        section = zconfig_locate(config, "/discovery/ips");
                        if(section)
                            zconfig_set_value(section, NULL);
                        if(section)
                            section = zconfig_locate(config, "/discovery");
                        zconfig_set_value(section, NULL);

                        zconfig_save(config, self->range_scan_config.config);
                        zconfig_destroy(&config);
                    }

                } else {
                    config_valid = false;
                    zsys_error("error in config : error in scans");
                }
            } else {
                config_valid = false;
                zsys_error("error in config : not a valid scan type");
            }

            if (config_valid) {
                zmsg_addstr(reply, "OK");
            } else {
                zmsg_addstr(reply, "ERROR");
            }

            mlm_client_sendto(self->mlm, mlm_client_sender(self->mlm), 
                    mlm_client_subject(self->mlm), 
                    mlm_client_tracker(self->mlm), 
                    1000, &reply);
        } else if (streq(cmd, "GETCONFIG")) {
            // GETCONFIG
            // REQ <uuid>
            char *zuuid = zmsg_popstr(msg);
            zmsg_t *reply = zmsg_new();
            zmsg_addstr(reply, zuuid);

            std::string content_reply = form_config_reply(self->range_scan_config.config);
            zmsg_addstr(reply, "OK");
            zmsg_addstr(reply, content_reply.c_str());

            mlm_client_sendto(self->mlm, mlm_client_sender(self->mlm), 
                    mlm_client_subject(self->mlm), 
                    mlm_client_tracker(self->mlm), 
                    1000, &reply);
        } else if (streq(cmd, "LAUNCHSCAN")) {
            // LAUNCHSCAN
            // REQ <uuid>
            char *zuuid = zmsg_popstr(msg);
            zmsg_t *reply = zmsg_new();
            zmsg_addstr(reply, zuuid);

            if (self->range_scanner) {
                if (self->ongoing_stop)
                    zmsg_addstr(reply, "STOPPING");
                else
                    zmsg_addstr(reply, "RUNNING");
            } else {
                self->ongoing_stop = false;

                if (self->percent)
                    zstr_free(&self->percent);
                self->percent = strdup("0");

                self->localscan_subscan.clear();
                self->scan_size = 0;
                self->nb_percent = 0;

                zstr_free(&self->range_scan_config.range);
                zstr_free(&self->range_scan_config.range_dest);

                if (self->configuration_scan.type == TYPE_LOCALSCAN) {
                    //Launch localScan
                    configure_local_scan(self);

                    if (self->scan_size > 0) {
                        zmsg_t *zmfalse = zmsg_new();
                        zmsg_addstr(zmfalse, self->localscan_subscan.back().c_str());
                        self->range_scan_config.range = zmsg_popstr(zmfalse);

                        zsys_debug("Range scanner requested for %s with config file %s", 
                                self->range_scan_config.range,
                                self->range_scan_config.config);

                        // create range scanner
                        if (self->range_scanner) {
                            zpoller_remove(poller, self->range_scanner);
                            zactor_destroy(&self->range_scanner);
                        }
                        reset_nb_discovered(self);
                        self->range_scanner = zactor_new(range_scan_actor, &self->range_scan_config);
                        zpoller_add(poller, self->range_scanner);
                        self->status_scan = STATUS_PROGESS;

                        zmsg_destroy(&zmfalse);
                        zmsg_addstr(reply, "OK");
                    } else
                        zmsg_addstr(reply, "ERROR");

                } else if ((self->configuration_scan.type == TYPE_MULTISCAN) || (self->configuration_scan.type == TYPE_IPSCAN)) {
                    //Launch rangeScan
                    self->localscan_subscan = self->configuration_scan.scan_list;
                    self->scan_size = self->configuration_scan.scan_size;

                    zmsg_t *zmfalse = zmsg_new();
                    std::string next_scan = self->localscan_subscan.back();

                    int ms_range_pos = next_scan.find("-");
                    if (ms_range_pos == -1) {
                        //Subnet
                        zmsg_addstr(zmfalse, next_scan.c_str());
                        self->range_scan_config.range = zmsg_popstr(zmfalse);
                    } else {
                        //range

                        zmsg_addstr(zmfalse, next_scan.substr(0, ms_range_pos).c_str());
                        self->range_scan_config.range = zmsg_popstr(zmfalse);

                        zmsg_addstr(zmfalse, next_scan.substr(ms_range_pos + 1).c_str());
                        self->range_scan_config.range_dest = zmsg_popstr(zmfalse);
                    }

                    zsys_debug("Range scanner requested for %s with config file %s", 
                            next_scan.c_str(), 
                            self->range_scan_config.config);

                    // create range scanner
                    if (self->range_scanner) {
                        zpoller_remove(poller, self->range_scanner);
                        zactor_destroy(&self->range_scanner);
                    }
                    reset_nb_discovered(self);
                    self->range_scanner = zactor_new(range_scan_actor, &self->range_scan_config);
                    zpoller_add(poller, self->range_scanner);

                    self->status_scan = STATUS_PROGESS;
                    zmsg_destroy(&zmfalse);
                    zmsg_addstr(reply, "OK");
                } else {
                    zmsg_addstr(reply, "ERROR");
                }
            }
            mlm_client_sendto(self->mlm, mlm_client_sender(self->mlm), 
                    mlm_client_subject(self->mlm), 
                    mlm_client_tracker(self->mlm), 
                    1000, &reply);
        } else if (streq(cmd, "PROGRESS")) {
            // PROGRESS
            // REQ <uuid>
            char *zuuid = zmsg_popstr(msg);
            zmsg_t *reply = zmsg_new();
            zmsg_addstr(reply, zuuid);
            if (self->percent) {
                zmsg_addstr(reply, "OK");
                zmsg_addstrf(reply, "%" PRIi32, self->status_scan);
                zmsg_addstr(reply, self->percent);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_discovered);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_ups_discovered);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_epdu_discovered);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_sts_discovered);
            } else {
                zmsg_addstr(reply, "OK");
                zmsg_addstrf(reply, "%" PRIi32, -1);
            }
            mlm_client_sendto(self->mlm, mlm_client_sender(self->mlm), 
                    mlm_client_subject(self->mlm), 
                    mlm_client_tracker(self->mlm), 
                    1000, &reply);
        } else if (streq(cmd, "STOPSCAN")) {
            // STOPSCAN
            // REQ <uuid>
            char *zuuid = zmsg_popstr(msg);
            zmsg_t *reply = zmsg_new();
            zmsg_addstr(reply, zuuid);
            zmsg_addstr(reply, "OK");

            mlm_client_sendto(self->mlm, mlm_client_sender(self->mlm), 
                    mlm_client_subject(self->mlm), 
                    mlm_client_tracker(self->mlm), 
                    1000, &reply);
            if (self->range_scanner && !self->ongoing_stop) {
                self->status_scan = STATUS_STOPPED;
                self->ongoing_stop = true;
                zstr_send(self->range_scanner, "$TERM");
            }

            zstr_free(&self->range_scan_config.range);
            zstr_free(&self->range_scan_config.range_dest);

            self->localscan_subscan.clear();
            self->scan_size = 0;
        } else
            zsys_error("s_handle_pipe: Unknown actor command: %s.\n", cmd);
        zstr_free(&cmd);
    }
    zmsg_destroy(&msg);
}

//  --------------------------------------------------------------------------
//  process message stream

void static
s_handle_stream(fty_discovery_server_t* self, zmsg_t *message) {
    zmsg_destroy(&message);
    zsys_error("s_handle_stream: not implemented");
}

//  --------------------------------------------------------------------------
//  process message stream
//  * DONE
//  * FOUND
//  * POOGRESS

void static
s_handle_range_scanner(fty_discovery_server_t* self,
        zmsg_t *msg, zpoller_t *poller, zsock_t *pipe) {
    zmsg_print(msg);
    char *cmd = zmsg_popstr(msg);
    if (!cmd) {
        zmsg_destroy(&msg);
        zsys_warning("s_handle_range_scanner Empty command.");
        return;
    }
    zsys_debug("s_handle_range_scanner DO : %s", cmd);
    if (streq(cmd, "DONE")) {
        if (self->ongoing_stop && self->range_scanner) {
            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        } else if (self->localscan_subscan.size() > 1) {
            //not done yet, still the others subnets to do

            //remove the done subnet
            self->localscan_subscan.pop_back();

            //start another one
            zstr_free(&self->range_scan_config.range);
            zstr_free(&self->range_scan_config.range_dest);

            zmsg_t *zmfalse = zmsg_new();
            std::string next_scan = self->localscan_subscan.back();
            int ms_range_pos = next_scan.find("-");

            if (ms_range_pos == -1) {
                //Subnet
                zmsg_addstr(zmfalse, next_scan.c_str());
                self->range_scan_config.range = zmsg_popstr(zmfalse);
            } else {
                //range
                zmsg_addstr(zmfalse, next_scan.substr(0, ms_range_pos).c_str());
                self->range_scan_config.range = zmsg_popstr(zmfalse);

                zmsg_addstr(zmfalse, next_scan.substr(ms_range_pos + 1).c_str());
                self->range_scan_config.range_dest = zmsg_popstr(zmfalse);
            }

            zsys_debug("Range scanner requested for %s with config file %s",
                    next_scan.c_str(), 
                    self->range_scan_config.config);

            // create range scanner
            if (self->range_scanner) {
                zpoller_remove(poller, self->range_scanner);
                zactor_destroy(&self->range_scanner);
            }

            self->range_scanner = zactor_new(range_scan_actor, &self->range_scan_config);
            zpoller_add(poller, self->range_scanner);

            zmsg_destroy(&zmfalse);
        } else {
            zstr_send(pipe, "DONE");
            if (!self->localscan_subscan.empty())
                self->localscan_subscan.clear();

            self->status_scan = STATUS_FINISHED;
            zstr_free(&self->range_scan_config.range);
            zstr_free(&self->range_scan_config.range_dest);

            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        }
    } else if (streq(cmd, "FOUND")) {
        ftydiscovery_create_asset(self, &msg);
    } else if (streq(cmd, "PROGRESS")) {
        self->nb_percent++;

        std::string percentstr = std::to_string(self->nb_percent * 100 / self->scan_size);

        if (self->percent)
            zstr_free(&self->percent);

        zmsg_t *zmfalse = zmsg_new();
        zmsg_addstr(zmfalse, percentstr.c_str());
        self->percent = zmsg_popstr(zmfalse);
        zmsg_destroy(&zmfalse);
    } else
        zsys_error("s_handle_range_scanner: Unknown  command: %s.\n", cmd);
    zstr_free(&cmd);
    zmsg_destroy(&msg);
}

//  --------------------------------------------------------------------------
//  fty_discovery_server actor

void
fty_discovery_server(zsock_t *pipe, void *args) {
    fty_discovery_server_t *self = fty_discovery_server_new();
    zpoller_t *poller = zpoller_new(pipe, mlm_client_msgpipe(self->mlm), NULL);
    zsock_signal(pipe, 0);
    zmsg_t *range_stack = zmsg_new();

    while (!zsys_interrupted) {
        void *which = zpoller_wait(poller, 5000);
        if (which == pipe) {
            if (!s_handle_pipe(self, zmsg_recv(pipe), poller))
                break; //TERM
            else continue;
        } else if (which == mlm_client_msgpipe(self->mlm)) {
            zmsg_t *message = mlm_client_recv(self->mlm);
            if (!message)
                continue;
            const char *command = mlm_client_command(self->mlm);
            if (streq(command, "STREAM DELIVER")) {
                s_handle_stream(self, message);
            } else
                if (streq(command, "MAILBOX DELIVER")) {
                s_handle_mailbox(self, message, poller);
            }
        } else if (self->range_scanner && which == self->range_scanner) {
            zmsg_t *message = zmsg_recv(self->range_scanner);
            if (!message)
                continue;
            s_handle_range_scanner(self, message, poller, pipe);
        }
    }
    // check that scanner is NULL && we have to do scan
    if (self->range_scan_config.range && !self->range_scanner) {
        if (zclock_mono() - assets_last_change(self->assets) > 5000) {
            // no asset change for last 5 secs => we can start range scan
            zsys_debug("Range scanner start for %s with config file %s", 
                    self->range_scan_config.range, 
                    self->range_scan_config.config);
            // create range scanner
            // TODO: send list of IPs to skip
            reset_nb_discovered(self);
            self->nb_percent = 0;
            if (self->percent)
                zstr_free(&self->percent);
            self->range_scanner = zactor_new(range_scan_actor, 
                    &self->range_scan_config);
            zpoller_add(poller, self->range_scanner);
        }
    }
    zmsg_destroy(&range_stack);
    fty_discovery_server_destroy(&self);
    zpoller_destroy(&poller);
}

//  --------------------------------------------------------------------------
//  Create a new fty_discovery_server

fty_discovery_server_t *
fty_discovery_server_new() {
    fty_discovery_server_t *self = (fty_discovery_server_t *) zmalloc(sizeof (fty_discovery_server_t));
    assert(self);
    //  Initialize class properties here
    self->mlm = mlm_client_new();
    self->scanner = NULL;
    self->assets = assets_new();
    self->nb_discovered = 0;
    self->nb_epdu_discovered = 0;
    self->nb_sts_discovered = 0;
    self->nb_ups_discovered = 0; 
    self->scan_size = 0;
    self->ongoing_stop = false;
    self->status_scan = -1;
    self->range_scan_config.config = strdup("/etc/fty-discovery/fty-discovery.cfg");
    self->range_scan_config.range = NULL;
    self->range_scan_config.range_dest = NULL;
    self->configuration_scan.type = TYPE_LOCALSCAN;
    self->configuration_scan.scan_size = 0;
    self->percent = NULL;
    return self;
}

void
fty_discovery_server_destroy(fty_discovery_server_t **self_p) {
    assert(self_p);
    if (*self_p) {
        fty_discovery_server_t *self = *self_p;
        //  Free class properties here
        zactor_destroy(&self->scanner);
        mlm_client_destroy(&self->mlm);
        assets_destroy(&self->assets);
        if (self->range_scan_config.config)
            zstr_free(&self->range_scan_config.config);
        if (self->range_scan_config.range)
            zstr_free(&self->range_scan_config.range);
        if (self->range_scan_config.range_dest)
            zstr_free(&self->range_scan_config.range_dest);
        if (self->percent)
            zstr_free(&self->percent);
        if (self->range_scanner)
            zactor_destroy(&self->range_scanner);
        //  Free object itself
        free(self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
fty_discovery_server_test(bool verbose) {
    printf(" * ftydiscovery: ");

    //  @selftest
    //  Simple create/destroy test
    zactor_t *self = zactor_new(fty_discovery_server, NULL);
    assert(self);
    zclock_sleep(500);
    zactor_destroy(&self);
    //  @end
    printf("OK\n");
}
