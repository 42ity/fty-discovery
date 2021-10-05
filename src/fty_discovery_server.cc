/*  =========================================================================
    fty_discovery_server - Manages discovery requests, provides feedback

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

/*
@header
    fty_discovery_server - Manages discovery requests, provides feedback
@discuss
@end
 */

#include "fty_discovery_server.h"
#include "cidr.h"
#include <ctime>
#include <cxxtools/jsonserializer.h>
#include <cxxtools/serializationinfo.h>
#include <czmq.h>
#include <fty/expected.h>
#include <fty_common_nut.h>
#include <fty_log.h>
#include <ifaddrs.h>
#include <malamute.h>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>
#include <bits/stl_vector.h>


static std::string discovery_config_file = FTY_DISCOVERY_CFG_FILE;

std::string getDiscoveryConfigFile()
{
    return discovery_config_file;
}

zactor_t* range_scanner_new(fty_discovery_server_t* self)
{
    zlist_t* args = zlist_new();
    zlist_append(args, &self->range_scan_config);
    zlist_append(args, &self->devices_discovered);
    zlist_append(args, &self->nut_mapping_inventory);
    zlist_append(args, &self->nut_sensor_mapping_inventory);
    return zactor_new(range_scan_actor, args);
}

void reset_nb_discovered(fty_discovery_server_t* self)
{
    self->nb_discovered        = 0;
    self->nb_epdu_discovered   = 0;
    self->nb_sts_discovered    = 0;
    self->nb_ups_discovered    = 0;
    self->nb_sensor_discovered = 0;
}

bool compute_ip_list(std::vector<std::string>* listIp)
{
    for (unsigned int iPosIp = 0; iPosIp < listIp->size(); iPosIp++) {
        std::string ips = listIp->at(iPosIp);
        CIDRAddress addrCIDR(ips, 32);
        if (addrCIDR.prefix() != -1) {
            log_debug("valid ip %s", ips.c_str());
            listIp->at(iPosIp) = addrCIDR.toString();
        } else {
            // not a valid address
            log_error("Address (%s) is not valid!", ips.c_str());
            return false;
        }
    }

    return true;
}

bool compute_scans_size(std::vector<std::string>* list_scan, int64_t* scan_size)
{
    *scan_size = 0;
    for (unsigned int iPosScan = 0; iPosScan < list_scan->size(); iPosScan++) {
        std::string scan = list_scan->at(iPosScan);
        size_t      pos  = scan.find("-");

        // if subnet
        if (pos == std::string::npos) {
            CIDRAddress addrCIDR(scan);

            if (addrCIDR.prefix() != -1) {
                log_debug("valid subnet %s", scan.c_str());
                // all the subnet (1 << (32- prefix) ) minus subnet and broadcast address
                if (addrCIDR.prefix() <= 30)
                    (*scan_size) += ((1 << (32 - addrCIDR.prefix())) - 2);
                else // 31/32 prefix special management
                    (*scan_size) += (1 << (32 - addrCIDR.prefix()));
            } else {
                // not a valid range
                log_error("Address subnet (%s) is not valid!", scan.c_str());
                return false;
            }
        } // else : range
        else {
            std::string rangeStart = scan.substr(0, pos);
            std::string rangeEnd   = scan.substr(pos + 1);
            CIDRAddress addrStart(rangeStart);
            CIDRAddress addrEnd(rangeEnd);

            if (!addrStart.valid() || !addrEnd.valid() || (addrStart > addrEnd)) {
                log_error("(%s) is not a valid range!", scan.c_str());
                return false;
            }

            size_t      posC        = rangeStart.find_last_of(".");
            int64_t     size1       = 0;
            std::string startOfAddr = rangeStart.substr(0, posC);
            size1 += atoi(rangeStart.substr(posC + 1).c_str());

            posC = startOfAddr.find_last_of(".");
            size1 += atoi(startOfAddr.substr(posC + 1).c_str()) * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size1 += atoi(startOfAddr.substr(posC + 1).c_str()) * 256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size1 += atoi(startOfAddr.substr(posC + 1).c_str()) * 256 * 256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC          = rangeEnd.find_last_of(".");
            int64_t size2 = 0;
            startOfAddr   = rangeEnd.substr(0, posC);
            size2 += atoi(rangeEnd.substr(posC + 1).c_str());

            posC = startOfAddr.find_last_of(".");
            size2 += atoi(startOfAddr.substr(posC + 1).c_str()) * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size2 += atoi(startOfAddr.substr(posC + 1).c_str()) * 256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            posC = startOfAddr.find_last_of(".");
            size2 += atoi(startOfAddr.substr(posC + 1).c_str()) * 256 * 256 * 256;
            startOfAddr = startOfAddr.substr(0, posC);

            (*scan_size) += (size2 - size1) + 1;

            pos = rangeStart.find("/");
            if (pos != std::string::npos) {
                rangeStart = rangeStart.substr(0, pos);
            }

            pos = rangeEnd.find("/");
            if (pos != std::string::npos) {
                rangeEnd = rangeEnd.substr(0, pos);
            }
            std::string correct_range = rangeStart + "/0-" + rangeEnd + "/0";
            list_scan->at(iPosScan)   = correct_range;

            log_debug("valid range (%s-%s). Size: %" PRIi64, rangeStart.c_str(), rangeEnd.c_str(), (size2 - size1) + 1);
        }
    }

    return true;
}

int mask_nb_bit(std::string mask)
{
    size_t      pos;
    int         res = 0;
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
        else // error
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

void configure_local_scan(fty_discovery_server_t* self)
{
    int             s, family, prefix;
    char            host[NI_MAXHOST];
    struct ifaddrs *ifaddr, *ifa;
    std::string     addr, netm, addrmask;

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

            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                log_debug("IP address parsing error for %s : %s", ifa->ifa_name, gai_strerror(s));
                continue;
            } else
                addr.assign(host);

            if (ifa->ifa_netmask == NULL) {
                log_debug("No netmask found for %s", ifa->ifa_name);
                continue;
            }

            family = ifa->ifa_netmask->sa_family;
            if (family != AF_INET)
                continue;

            s = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                log_debug("Netmask parsing error for %s : %s", ifa->ifa_name, gai_strerror(s));
                continue;
            } else
                netm.assign(host);

            prefix = 0;
            addrmask.clear();

            prefix = mask_nb_bit(netm);

            // all the subnet (1 << (32- prefix) ) minus subnet and broadcast address
            if (prefix <= 30)
                self->scan_size += ((1 << (32 - prefix)) - 2);
            else // 31/32 prefix special management
                self->scan_size += (1 << (32 - prefix));


            CIDRAddress addrCidr(addr, fty::convert<unsigned int>(prefix));

            addrmask.clear();
            addrmask.assign(addrCidr.network().toString());

            self->localscan_subscan.push_back(addrmask);
            log_info("Localscan subnet found for %s : %s", ifa->ifa_name, addrmask.c_str());
        }

        freeifaddrs(ifaddr);
    }
}

bool compute_configuration_file(fty_discovery_server_t* self)
{
    zconfig_t* config = zconfig_load(self->range_scan_config.config);
    if (!config) {
        log_error("failed to load config file %s", self->range_scan_config.config);
        config = zconfig_new("root", NULL);
    }

    char*                    strType = zconfig_get(config, CFG_DISCOVERY_TYPE, DISCOVERY_TYPE_LOCAL);
    std::vector<std::string> list_scans, listIp;
    bool                     valid   = true;
    zconfig_t*               section = zconfig_locate(config, CFG_DISCOVERY_SCANS);
    if (section) {
        zconfig_t* item = zconfig_child(section);
        while (item) {
            // FIXME : can't delete item in cfg for now...
            if (streq(zconfig_value(item), ""))
                break;
            list_scans.push_back(zconfig_value(item));
            item = zconfig_next(item);
        }
    }
    section = zconfig_locate(config, CFG_DISCOVERY_IPS);
    if (section) {
        zconfig_t* item = zconfig_child(section);
        while (item) {
            // FIXME : can't delete item in cfg for now...
            if (streq(zconfig_value(item), ""))
                break;
            listIp.push_back(zconfig_value(item));
            item = zconfig_next(item);
        }
    }
    self->default_values_aux.clear();
    section = zconfig_locate(config, CFG_DISCOVERY_DEFAULT_VALUES_AUX);
    if (section) {
        for (zconfig_t* item = zconfig_child(section); item; item = zconfig_next(item)) {
            std::string configName(zconfig_name(item));
            // the config API call returns the parent internal name, while fty-proto-t needs to carry the database ID
            if (configName == "parent") {
                std::string parentIname(zconfig_value(item));
                if (parentIname == "0" || parentIname == "") {
                    self->default_values_aux[zconfig_name(item)] = "0";
                    self->device_centric                         = false;
                } else {
                    self->default_values_aux[zconfig_name(item)] = std::to_string(DBAssets::name_to_asset_id(parentIname)).c_str();
                    self->device_centric                         = true;
                }
            } else {
                self->default_values_aux[zconfig_name(item)] = zconfig_value(item);
            }
        }
    }
    self->default_values_ext.clear();
    section = zconfig_locate(config, CFG_DISCOVERY_DEFAULT_VALUES_EXT);
    if (section) {
        for (zconfig_t* item = zconfig_child(section); item; item = zconfig_next(item)) {
            self->default_values_ext[zconfig_name(item)] = zconfig_value(item);
        }
    }
    self->default_values_links.clear();
    section = zconfig_locate(config, CFG_DISCOVERY_DEFAULT_VALUES_LINKS);
    if (section) {
        for (zconfig_t* link = zconfig_child(section); link; link = zconfig_next(link)) {

            std::string iname(zconfig_get(link, "src", ""));

            link_t l;

            // when link to no source, the file will have "0"
            l.src     = (iname == "0") ? 0 : fty::convert<uint32_t>(DBAssets::name_to_asset_id(iname));
            l.dest    = 0;
            l.src_out = nullptr;
            l.dest_in = nullptr;
            l.type    = fty::convert<uint16_t>(std::stoul(zconfig_get(link, "type", "1")));

            if (l.src > 0) {
                self->default_values_links.emplace_back(l);
            }
        }
    }

    // check we have all the params we need to launch the scan
    int64_t sizeTemp = 0;

    // check for multiscan
    if (streq(strType, DISCOVERY_TYPE_MULTI)) {
        if (list_scans.empty()) { // nothing to scan
            log_error("error in config file %s : can't have rangescan without range", self->range_scan_config.config);
            zconfig_destroy(&config);
            return false;
        } else if (!compute_scans_size(&list_scans, &sizeTemp)) { // error in the range
            log_error("Error in config file %s: error in range or subnet", self->range_scan_config.config);
            zconfig_destroy(&config);
            return false;
        }
    }

    // check for ipscans
    if (streq(strType, DISCOVERY_TYPE_IP)) {
        if (listIp.empty()) {
            log_error("error in config file %s : can't have ipscan without ip list", self->range_scan_config.config);
            zconfig_destroy(&config);
            return false;
        } else if (!compute_ip_list(&listIp)) { // bad format in list
            log_error("Error in config file %s: error in ip list", self->range_scan_config.config);
            zconfig_destroy(&config);
            return false;
        }
    }

    // check for ipscans
    if (streq(strType, DISCOVERY_TYPE_FULL)) {
        if (listIp.empty() && list_scans.empty()) {
            log_error("error in config file %s : can't have fullscan without ip list or without range", self->range_scan_config.config);
            zconfig_destroy(&config);
            return false;
        } else if ((!listIp.empty()) && (!compute_ip_list(&listIp))) { // bad format in list
            log_error("Error in config file %s: error in ip list", self->range_scan_config.config);
            zconfig_destroy(&config);
            return false;
        } else if ((!list_scans.empty()) && (!compute_scans_size(&list_scans, &sizeTemp))) { // error in the range
            log_error("Error in config file %s: error in range or subnet", self->range_scan_config.config);
            zconfig_destroy(&config);
            return false;
        }
    }

    // get ready to launch
    if (streq(strType, DISCOVERY_TYPE_MULTI)) {
        self->configuration_scan.type      = TYPE_MULTISCAN;
        self->configuration_scan.scan_size = sizeTemp;
        self->configuration_scan.scan_list.clear();
        self->configuration_scan.scan_list = list_scans;

    } else if (streq(strType, DISCOVERY_TYPE_IP)) {

        self->configuration_scan.type      = TYPE_IPSCAN;
        self->configuration_scan.scan_size = fty::convert<int64_t>(listIp.size());
        self->configuration_scan.scan_list.clear();
        self->configuration_scan.scan_list = listIp;

    } else if (streq(strType, DISCOVERY_TYPE_FULL)) {
        std::vector<std::string> fullList(listIp);
        fullList.insert(fullList.end(), list_scans.begin(), list_scans.end());

        self->configuration_scan.type      = TYPE_FULLSCAN;
        self->configuration_scan.scan_size = fty::convert<int64_t>(listIp.size()) + sizeTemp;
        self->configuration_scan.scan_list.clear();
        self->configuration_scan.scan_list = fullList;

    } else if (streq(strType, DISCOVERY_TYPE_LOCAL)) {
        self->configuration_scan.type = TYPE_LOCALSCAN;
    } else {
        log_debug("unknown command type %s", strType);
        zconfig_destroy(&config);
        return false;
    }

    log_debug("config file %s applied successfully", self->range_scan_config.config);

    zconfig_destroy(&config);

    return valid;
}


//  --------------------------------------------------------------------------
//  send create asset if it is new

static bool s_skip_nmc_netxml(fty_proto_t* asset)
{
    if (streq(fty_proto_ext_string(asset, "device.type", ""), "ups") &&
        streq(fty_proto_ext_string(asset, "endpoint.1.protocol", ""), "nut_snmp")) {
        /**
         * We don't want to use a nut_snmp endpoint configuration for NMC cards if NetXML works.
         * Very hackish, but fty-discovery should eventually be replaced by fty-discovery-ng.
         * Hopefully this doesn't cause more problems than it tries to fix...
         */
        if (!fty::nut::scanDevice(fty::nut::ScanProtocol::SCAN_PROTOCOL_NETXML, fty_proto_ext_string(asset, "ip.1", "xxx"), 5).empty()) {
            log_warning("Skipping SNMP dump for NMC card!");
            return true;
        }
    }
    return false;
}

static std::string operation(fty_discovery_server_t* self, fty_proto_t* asset)
{
    const char*       serial           = fty_proto_ext_string(asset, "serial_no", NULL);
    const char*       ip               = fty_proto_ext_string(asset, "ip.1", NULL);
    const std::string deviceIdentifier = (serial ? serial : ip);

    std::lock_guard<std::mutex> lock(self->devices_discovered.mtx_list);

    logDebug("Check {}", deviceIdentifier);
    // to identify a device, use serial number (if available), otherwise the IP:
    auto found = self->devices_discovered.device_list.find(deviceIdentifier);

    if (found != self->devices_discovered.device_list.end()) {
        logDebug("{} found in existing devices", deviceIdentifier);
        if (found->second.existing) {
            logInfo("Asset with identifier {} already exists and cannot be updated", deviceIdentifier);
            return {};
        } else {
            const char* protocol = fty_proto_ext_string(asset, "endpoint.1.protocol", NULL);
            if (!protocol) {
                if (const char* parent = fty_proto_aux_string(asset, "parent", nullptr); parent) {
                    if (self->devices_discovered.device_list.count(parent)) {
                        protocol = self->devices_discovered.device_list.at(parent).protocol.c_str();
                    }
                }
            }
            logDebug("check protocol {} == {}", protocol ? protocol : "null", found->second.protocol);

            if (protocol && protocol == found->second.protocol) {
                logInfo("Asset with identifier {} already exists and has same protocol ({})", serial, protocol);
                return {};
            } else if (protocol && streq(protocol, "nut_powercom")) {
                logInfo("Asset with identifier {} already exists but should be updated to new protocol {}", serial, protocol);
                fty_proto_set_name(asset, "%s", found->second.name.c_str());
                zhash_t* ext = fty_proto_ext(asset);
                zhash_t* extCopy = zhash_dup(ext);
                zhash_delete(extCopy, "endpoint.1.nut_snmp.secw_credential_id");
                fty_proto_set_ext(asset, &extCopy);
                return "update";
            }
            return {};
        }
    } else {
        logDebug("Not found in '{}'", deviceIdentifier);
        for (const auto& [uuid, info] : self->devices_discovered.device_list) {
            logDebug("Exising device {} - uuid:'{}' ({}) in discovered list, origin: {}", info.name, uuid, info.protocol, info.existing);
        }
    }
    return "create-force";
}

void ftydiscovery_create_asset(fty_discovery_server_t* self, zmsg_t** msg_p)
{
    if (!self || !msg_p)
        return;
    if (!fty_proto_is(*msg_p))
        return;

    // DEBUG: list discovered devices
    {
        std::lock_guard<std::mutex> lock(self->devices_discovered.mtx_list);
        for (const auto& [uuid, info] : self->devices_discovered.device_list) {
            logDebug("Found device {} - {} ({}) in discovered list, origin: {}", info.name, uuid, info.protocol, info.existing);
        }
    }

    fty_proto_t* asset = fty_proto_decode(msg_p);
    fty_proto_print(asset);

    bool sensor = streq(fty_proto_aux_string(asset, "subtype", "unknown"), "sensor");

    if (!sensor) {
        // standard device

        const char* serial = fty_proto_ext_string(asset, "serial_no", NULL);
        const char* ip     = fty_proto_ext_string(asset, "ip.1", NULL);

        // IP address is mandatory for discovered devices (except for sensors)
        if (!ip) {
            log_error("IP address is available for the current device");
            return;
        }
        // to identify a device, use serial number (if available), otherwise the IP:
        const std::string deviceIdentifier = (serial && !streq(serial, "") ? serial : ip);
        if (deviceIdentifier.empty()) {
            log_info("Asset with empty identifier");
            fty_proto_destroy(&asset);
            return;
        }

        bool daisy_chain = fty_proto_ext_string(asset, "daisy_chain", NULL) != NULL;

        if (auto op = operation(self, asset); !op.empty()) {
            fty_proto_set_operation(asset, op.c_str());
        } else {
            fty_proto_destroy(&asset);
            return;
        }

        if (!daisy_chain && assets_find(self->assets, "ip.1", ip)) {
            log_info("Asset with IP %s already exists", ip);
            fty_proto_destroy(&asset);
            return;
        }

        const char* uuid = fty_proto_ext_string(asset, "uuid", NULL);
        if (uuid && assets_find(self->assets, "uuid", uuid)) {
            log_info("Asset with uuid %s already exists", uuid);
            fty_proto_destroy(&asset);
            return;
        }

        // set external name
        const char* name = fty_proto_ext_string(asset, "hostname", NULL);
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

        if (daisy_chain) {
            const char* dc_number = fty_proto_ext_string(asset, "daisy_chain", NULL);
            name                  = fty_proto_ext_string(asset, "name", NULL);

            if (streq(dc_number, "1"))
                fty_proto_ext_insert(asset, "name", "%s Host", name);
            else {
                int dc_numberI = atoi(dc_number);
                fty_proto_ext_insert(asset, "name", "%s Device%i", name, dc_numberI - 1);
            }
        }

        std::time_t timestamp = std::time(NULL);
        char        mbstr[100];
        if (std::strftime(mbstr, sizeof(mbstr), "%FT%T%z", std::localtime(&timestamp))) {
            fty_proto_ext_insert(asset, "create_ts", "%s", mbstr);
        }

        for (const auto& property : self->default_values_aux) {
            if (!fty_proto_aux_string(asset, property.first.c_str(), nullptr)) {
                fty_proto_aux_insert(asset, property.first.c_str(), property.second.c_str());
            }
        }
        for (const auto& property : self->default_values_ext) {
            if (!fty_proto_ext_string(asset, property.first.c_str(), nullptr)) {
                fty_proto_ext_insert(asset, property.first.c_str(), property.second.c_str());
            }
        }

        log_info("Found new asset %s with IP address %s", fty_proto_ext_string(asset, "name", ""), ip);

        if (!s_skip_nmc_netxml(asset)) {
            fty_proto_t* assetDup = fty_proto_dup(asset);
            zmsg_t*      msg      = fty_proto_encode(&assetDup);
            zmsg_pushstrf(msg, "%s", "READONLY");
            log_debug("Sending create message");
            int rv = mlm_client_sendto(self->mlmCreate, "asset-agent", "ASSET_MANIPULATION", NULL, 10, &msg);
            if (rv == -1) {
                log_error("Failed to send ASSET_MANIPULATION message to asset-agent");
            } else {
                log_info("Create message has been sent to asset-agent (rv = %i)", rv);

                zmsg_t* response = mlm_client_recv(self->mlmCreate);
                if (!response) {
                    fty_proto_destroy(&asset);
                    return;
                }

                char* str_resp = zmsg_popstr(response);

                if (!str_resp || !streq(str_resp, "OK")) {
                    logError("Error during asset creation. error: {}", str_resp ? str_resp : "empty");
                    fty_proto_destroy(&asset);
                    return;
                }

                zstr_free(&str_resp);
                str_resp = zmsg_popstr(response);
                if (!str_resp) {
                    log_error("Error during asset creation.");
                    fty_proto_destroy(&asset);
                    return;
                }

                std::string iname(str_resp);

                // create asset links
                for (auto& link : self->default_values_links) {

                    link.dest = fty::convert<uint32_t>(DBAssets::name_to_asset_id(iname));
                }
                auto conn = tntdb::connectCached(DBConn::url);
                DBAssetsInsert::insert_into_asset_links(conn, self->default_values_links);

                const char* prot = fty_proto_ext_string(asset, "endpoint.1.protocol", NULL);

                logDebug("Added device {} {} ({})", str_resp, deviceIdentifier, prot ? prot : "nut_snmp");
                self->devices_discovered.device_list[deviceIdentifier] = {false, prot ? prot : "nut_snmp", str_resp};
                zstr_free(&str_resp);

                name = fty_proto_aux_string(asset, "subtype", "error");
                if (streq(name, "ups"))
                    self->nb_ups_discovered++;
                else if (streq(name, "epdu"))
                    self->nb_epdu_discovered++;
                else if (streq(name, "sts"))
                    self->nb_sts_discovered++;
                if (!streq(name, "error")) {
                    self->nb_discovered++;
                }
            }
        }
    } else {
        // sensor
        std::string serialNo(fty_proto_ext_string(asset, "serial_no", ""));
        std::string parent(fty_proto_aux_string(asset, "parent", ""));
        std::string model(fty_proto_ext_string(asset, "model", ""));
        std::string port;
        if (model.compare("EMPDT1H1C2") == 0) {
            port = std::string(fty_proto_ext_string(asset, "endpoint.1.sub_address", ""));
        } else {
            log_info("Model %s is not supported for autodiscovery", model.c_str());
            fty_proto_destroy(&asset);
            return;
        }

        if (serialNo.empty() || parent.empty() || port.empty()) {
            log_info("Missing info for new sensor");
            fty_proto_destroy(&asset);
            return;
        }

        // add generic external name, if not available
        if (!fty_proto_ext_string(asset, "name", NULL)) {
            fty_proto_ext_insert(asset, "name", "sensor %s (%s)", model.c_str(), serialNo.c_str());
        }

        if (auto op = operation(self, asset); !op.empty()) {
            fty_proto_set_operation(asset, op.c_str());
            logDebug("Sensor operation is {}", op);
        } else {
            fty_proto_destroy(&asset);
            return;
        }


        // add timestamp
        std::time_t timestamp = std::time(NULL);
        char        mbstr[100];
        if (std::strftime(mbstr, sizeof(mbstr), "%FT%T%z", std::localtime(&timestamp))) {
            fty_proto_ext_insert(asset, "create_ts", "%s", mbstr);
        }

        // check if parent of the sensor exists already (the internal name is needed to create the asset properly)
        auto found = self->devices_discovered.device_list.find(parent);

        if (found == self->devices_discovered.device_list.end()) {
            log_info("Could not find parent of sensor %s", serialNo.c_str());
            fty_proto_destroy(&asset);
            return;
        }
        std::string parentName = found->second.name;

        // add default properties properties (defined in discovery configuration)
        for (const auto& property : self->default_values_aux) {
            fty_proto_aux_insert(asset, property.first.c_str(), property.second.c_str());
        }
        for (const auto& property : self->default_values_ext) {
            fty_proto_ext_insert(asset, property.first.c_str(), property.second.c_str());
        }

        // update parent name
        fty_proto_ext_insert(asset, "parent_name.1", parentName.c_str());

        // add logical asset (sensor location) if in device centric mode
        if (self->device_centric) {
            auto              logicalAssetId = fty::convert<uint32_t>(self->default_values_aux.at("parent"));
            const std::string logicalAsset(DBAssets::id_to_name_ext_name(logicalAssetId).first);
            fty_proto_ext_insert(asset, "logical_asset", logicalAsset.c_str());
        }

        // update parent ID (overwrite default)
        logDebug("Sensor parentname is {}", !parentName.empty() ? parentName : "null");
        auto parentId = DBAssets::name_to_asset_id(parentName);
        if (parentId < 0) {
            log_info("Could not query parent ID of sensor %s", serialNo.c_str());
            fty_proto_destroy(&asset);
            return;
        }
        fty_proto_aux_insert(asset, "parent", fty::convert<std::string>(parentId).c_str());
        log_info("Found new sensor %s with parent %s", serialNo.c_str(), parentName.c_str());

        // send create message
        fty_proto_t* assetDup = fty_proto_dup(asset);
        zmsg_t*      msg      = fty_proto_encode(&assetDup);
        zmsg_pushstrf(msg, "%s", "READONLY");
        log_debug("Sending create message");
        int rv = mlm_client_sendto(self->mlmCreate, "asset-agent", "ASSET_MANIPULATION", NULL, 10, &msg);

        if (rv == -1) {
            log_error("Failed to send ASSET_MANIPULATION message to asset-agent");
        } else {
            log_info("Create message has been sent to asset-agent (rv = %i)", rv);

            zmsg_t* response = mlm_client_recv(self->mlmCreate);
            if (!response) {
                fty_proto_destroy(&asset);
                return;
            }

            char* str_resp = zmsg_popstr(response);

            if (!str_resp || !streq(str_resp, "OK")) {
                log_error("Error during asset creation.");
                fty_proto_destroy(&asset);
                return;
            }

            zstr_free(&str_resp);
            str_resp = zmsg_popstr(response);
            if (!str_resp) {
                log_error("Error during asset creation.");
                fty_proto_destroy(&asset);
                return;
            }

            std::string iname(str_resp);

            auto conn = tntdb::connectCached(DBConn::url);

            // Add link between sensor and its parent
            std::vector<link_t> sensor_links {
              {
                fty::convert<uint32_t>(DBAssets::name_to_asset_id(parentName)), // src = parent id
                fty::convert<uint32_t>(DBAssets::name_to_asset_id(iname)), // dest = sensor id
                nullptr, // src_out
                nullptr, // dest_in
                1        // power type
              }
            };
            DBAssetsInsert::insert_into_asset_links(conn, sensor_links);

            logDebug("Added sensor {} {} ({})", str_resp, serialNo, found->second.protocol);
            self->devices_discovered.device_list[serialNo] = {false, found->second.protocol, str_resp};
            zstr_free(&str_resp);

            self->nb_sensor_discovered++;
        }
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

bool static s_handle_pipe(fty_discovery_server_t* self, zmsg_t* message, zpoller_t* poller)
{
    if (!message)
        return true;
    char* command = zmsg_popstr(message);
    if (!command) {
        zmsg_destroy(&message);
        log_warning("Empty command.");
        return true;
    }
    log_debug("s_handle_pipe DO %s", command);
    if (streq(command, REQ_TERM)) {
        log_info("Got $TERM");
        zmsg_destroy(&message);
        zstr_free(&command);
        return false;
    } else if (streq(command, REQ_BIND)) {
        char* endpoint = zmsg_popstr(message);
        char* myname   = zmsg_popstr(message);
        assert(endpoint && myname);
        mlm_client_connect(self->mlm, endpoint, 5000, myname);
        char* nameadd = zsys_sprintf("%s.create", myname);
        mlm_client_connect(self->mlmCreate, endpoint, 5000, nameadd);
        zstr_free(&nameadd);
        zstr_free(&endpoint);
        zstr_free(&myname);
    } else if (streq(command, REQ_CONSUMER)) {
        char* stream  = zmsg_popstr(message);
        char* pattern = zmsg_popstr(message);
        assert(stream && pattern);
        mlm_client_set_consumer(self->mlm, stream, pattern);
        zstr_free(&stream);
        zstr_free(&pattern);
        // ask for assets now
        zmsg_t* republish = zmsg_new();
        zmsg_addstr(republish, "$all");
        mlm_client_sendto(self->mlm, FTY_ASSET, REQ_REPUBLISH, NULL, 1000, &republish);
    } else if (streq(command, REQ_CONFIG)) {
        zstr_free(&self->range_scan_config.config);
        self->range_scan_config.config = zmsg_popstr(message);
        discovery_config_file          = self->range_scan_config.config;
        zconfig_t* config              = zconfig_load(self->range_scan_config.config);
        if (!config) {
            log_error("failed to load config file %s", self->range_scan_config.config);
            config = zconfig_new("root", NULL);
        }
        char*                    strType = zconfig_get(config, CFG_DISCOVERY_TYPE, DISCOVERY_TYPE_LOCAL);
        std::vector<std::string> list_scans, listIp;
        bool                     valid   = true;
        zconfig_t*               section = zconfig_locate(config, CFG_DISCOVERY_SCANS);
        if (section) {
            zconfig_t* item = zconfig_child(section);
            while (item) {
                // FIXME : can't delete item in cfg for now...
                if (streq(zconfig_value(item), ""))
                    break;
                list_scans.push_back(zconfig_value(item));
                item = zconfig_next(item);
            }
        }
        section = zconfig_locate(config, CFG_DISCOVERY_IPS);
        if (section) {
            zconfig_t* item = zconfig_child(section);
            while (item) {
                // FIXME : can't delete item in cfg for now...
                if (streq(zconfig_value(item), ""))
                    break;
                listIp.push_back(zconfig_value(item));
                item = zconfig_next(item);
            }
        }
        if (list_scans.empty() && streq(strType, DISCOVERY_TYPE_MULTI)) {
            valid = false;
            log_error("error in config file %s : can't have rangescan without range", self->range_scan_config.config);
        } else if (listIp.empty() && streq(strType, DISCOVERY_TYPE_IP)) {
            valid = false;
            log_error("error in config file %s : can't have ipscan without ip list", self->range_scan_config.config);
        } else if ((listIp.empty() && listIp.empty()) && streq(strType, DISCOVERY_TYPE_FULL)) {
            valid = false;
            log_error("error in config file %s : can't have fullscan without ip list or range", self->range_scan_config.config);
        } else {
            int64_t sizeTemp = 0;
            if (compute_scans_size(&list_scans, &sizeTemp) && compute_ip_list(&listIp)) {
                // ok, validate the config

                self->configuration_scan.type = TYPE_LOCALSCAN;
                self->configuration_scan.scan_list.clear();
                self->configuration_scan.scan_size = 0;

                if (streq(strType, DISCOVERY_TYPE_MULTI)) {
                    self->configuration_scan.type      = TYPE_MULTISCAN;
                    self->configuration_scan.scan_list = list_scans;
                    self->configuration_scan.scan_size = sizeTemp;

                } else if (streq(strType, DISCOVERY_TYPE_IP)) {
                    self->configuration_scan.type      = TYPE_IPSCAN;
                    self->configuration_scan.scan_size = fty::convert<int64_t>(listIp.size());
                    self->configuration_scan.scan_list = listIp;

                } else if (streq(strType, DISCOVERY_TYPE_FULL)) {
                    std::vector<std::string> fullList(listIp);
                    fullList.insert(fullList.end(), list_scans.begin(), list_scans.end());

                    self->configuration_scan.type      = TYPE_FULLSCAN;
                    self->configuration_scan.scan_size = fty::convert<int64_t>(listIp.size()) + sizeTemp;
                    self->configuration_scan.scan_list = fullList;
                }

                listIp.clear();
                list_scans.clear();
            } else {
                valid = false;
                log_error("error in config file %s: error in scans", self->range_scan_config.config);
            }
        }

        const char* mappingPath = zconfig_get(config, CFG_PARAM_MAPPING_FILE, "none");
        if (streq(mappingPath, "none")) {
            log_error("No mapping file declared under config key '%s'", CFG_PARAM_MAPPING_FILE);
            valid = false;
        } else {
            // Load general mapping
            try {
                self->nut_mapping_inventory = fty::nut::loadMapping(mappingPath, "inventoryMapping");
                log_info("Mapping file '%s' loaded, %d inventory mappings", mappingPath, self->nut_mapping_inventory.size());
            } catch (std::exception& e) {
                log_error("Couldn't load mapping file '%s': %s", mappingPath, e.what());
                valid = false;
            }
            // Load sensor specific mapping
            try {
                self->nut_sensor_mapping_inventory = fty::nut::loadMapping(mappingPath, "sensorInventoryMapping");
                log_info(
                    "Sensor mapping file '%s' loaded, %d sensor inventory mappings", mappingPath,
                    self->nut_sensor_mapping_inventory.size());
            } catch (std::exception& e) {
                log_error("Couldn't load sensor mapping file '%s': %s", mappingPath, e.what());
                valid = false;
            }
        }

        if (valid)
            log_debug("config file %s applied successfully", self->range_scan_config.config);
        zconfig_destroy(&config);
    } else if (streq(command, REQ_SCAN)) {
        if (self->range_scanner) {
            reset_nb_discovered(self);
            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        }
        self->ongoing_stop = false;
        self->localscan_subscan.clear();
        self->scan_size = 0;

        for (auto range : self->range_scan_config.ranges) {
            zstr_free(&(range.first));
            zstr_free(&(range.second));
        }
        self->range_scan_config.ranges.clear();

        char* secondNull = NULL;
        self->range_scan_config.ranges.push_back(std::make_pair(zmsg_popstr(message), secondNull));
        if ((self->range_scan_config.ranges[0]).first) {
            CIDRAddress addrCIDR((self->range_scan_config.ranges[0]).first);

            if (addrCIDR.prefix() != -1) {
                // all the subnet (1 << (32- prefix) ) minus subnet and broadcast address
                if (addrCIDR.prefix() <= 30)
                    self->scan_size = ((1 << (32 - addrCIDR.prefix())) - 2);
                else // 31/32 prefix special management
                    self->scan_size = (1 << (32 - addrCIDR.prefix()));
            } else {
                // not a valid range
                log_error("Address range (%s) is not valid!", (self->range_scan_config.ranges[0]).first);
                zstr_free(&((self->range_scan_config.ranges[0]).first));
                self->range_scan_config.ranges.clear();
            }
        }
    } else if (streq(command, REQ_LOCALSCAN)) {
        if (self->range_scanner) {
            reset_nb_discovered(self);
            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        }

        self->ongoing_stop = false;
        self->localscan_subscan.clear();
        self->scan_size = 0;
        configure_local_scan(self);

        for (auto range : self->range_scan_config.ranges) {
            zstr_free(&(range.first));
            zstr_free(&(range.second));
        }
        self->range_scan_config.ranges.clear();
        if (self->scan_size > 0) {
            while (self->localscan_subscan.size() > 0) {
                zmsg_t* zmfalse = zmsg_new();
                zmsg_addstr(zmfalse, self->localscan_subscan.back().c_str());

                char* secondNull = NULL;
                self->range_scan_config.ranges.push_back(std::make_pair(zmsg_popstr(zmfalse), secondNull));
                self->localscan_subscan.pop_back();
                zmsg_destroy(&zmfalse);
            }

            reset_nb_discovered(self);
        }

    } else
        log_error("s_handle_pipe: Unknown command: %s.\n", command);
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

void static s_handle_mailbox(fty_discovery_server_t* self, zmsg_t* msg, zpoller_t* poller)
{
    if (fty_proto_is(msg)) {
        fty_proto_t* fmsg = fty_proto_decode(&msg);
        log_debug("Adding asset to self->assets");
        assets_put(self->assets, &fmsg);
        fty_proto_destroy(&fmsg);
    } else {
        // handle REST API requests
        char* cmd = zmsg_popstr(msg);
        if (!cmd) {
            zmsg_destroy(&msg);
            log_warning("s_handle_mailbox Empty command.");
            return;
        }
        log_debug("s_handle_mailbox DO : %s", cmd);
        if (streq(cmd, REQ_LAUNCHSCAN)) {
            // LAUNCHSCAN
            // REQ <uuid>
            char*   zuuid = zmsg_popstr(msg);
            zmsg_t* reply = zmsg_new();
            zmsg_addstr(reply, zuuid);

            if (self->range_scanner) {
                if (self->ongoing_stop)
                    zmsg_addstr(reply, STATUS_STOPPING);
                else
                    zmsg_addstr(reply, STATUS_RUNNING);
            } else {
                self->ongoing_stop = false;

                if (self->percent)
                    zstr_free(&self->percent);
                self->percent = strdup("0");

                self->localscan_subscan.clear();
                self->scan_size  = 0;
                self->nb_percent = 0;

                for (auto range : self->range_scan_config.ranges) {
                    zstr_free(&(range.first));
                    zstr_free(&(range.second));
                }
                self->range_scan_config.ranges.clear();

                if (compute_configuration_file(self)) {
                    if (self->configuration_scan.type == TYPE_LOCALSCAN) {
                        // Launch localScan
                        log_debug("Configuring localscan...");
                        configure_local_scan(self);

                        if (self->scan_size > 0) {
                            while (self->localscan_subscan.size() > 0) {
                                zmsg_t* zmfalse = zmsg_new();
                                zmsg_addstr(zmfalse, self->localscan_subscan.back().c_str());
                                char* secondNull = NULL;
                                self->range_scan_config.ranges.push_back(std::make_pair(zmsg_popstr(zmfalse), secondNull));

                                log_debug(
                                    "Range scanner requested for %s with config file %s", self->range_scan_config.ranges.back().first,
                                    self->range_scan_config.config);
                                zmsg_destroy(&zmfalse);
                                self->localscan_subscan.pop_back();
                            }
                            // create range scanner
                            if (self->range_scanner) {
                                zpoller_remove(poller, self->range_scanner);
                                zactor_destroy(&self->range_scanner);
                            }
                            reset_nb_discovered(self);
                            self->range_scanner = range_scanner_new(self);
                            zpoller_add(poller, self->range_scanner);
                            self->status_scan = STATUS_PROGESS;

                            zmsg_addstr(reply, RESP_OK);
                        } else {
                            zmsg_addstr(reply, RESP_ERR);
                        }


                    } else if (
                        (self->configuration_scan.type == TYPE_MULTISCAN) || (self->configuration_scan.type == TYPE_IPSCAN) ||
                        (self->configuration_scan.type == TYPE_FULLSCAN)) {

                        log_debug("Configuring rangeScan...");
                        // Launch rangeScan
                        self->localscan_subscan = self->configuration_scan.scan_list;
                        self->scan_size         = self->configuration_scan.scan_size;

                        while (self->localscan_subscan.size() > 0) {
                            zmsg_t*     zmfalse   = zmsg_new();
                            std::string next_scan = self->localscan_subscan.back();

                            int ms_range_pos = fty::convert<int>(next_scan.find("-"));
                            if (ms_range_pos == -1) {
                                // Subnet
                                zmsg_addstr(zmfalse, next_scan.c_str());
                                char* secondNull = NULL;
                                self->range_scan_config.ranges.push_back(std::make_pair(zmsg_popstr(zmfalse), secondNull));
                            } else {
                                // range

                                zmsg_addstr(zmfalse, next_scan.substr(0, fty::convert<size_t>(ms_range_pos)).c_str());
                                char* firstIP = zmsg_popstr(zmfalse);

                                zmsg_addstr(zmfalse, next_scan.substr(fty::convert<size_t>(ms_range_pos) + 1).c_str());
                                self->range_scan_config.ranges.push_back(std::make_pair(firstIP, zmsg_popstr(zmfalse)));
                            }

                            log_debug("Range scanner requested for %s with config file %s", next_scan.c_str(), self->range_scan_config.config);

                            zmsg_destroy(&zmfalse);
                            self->localscan_subscan.pop_back();
                        }
                        // create range scanner
                        if (self->range_scanner) {
                            zpoller_remove(poller, self->range_scanner);
                            zactor_destroy(&self->range_scanner);
                        }
                        reset_nb_discovered(self);
                        self->range_scanner = range_scanner_new(self);
                        zpoller_add(poller, self->range_scanner);

                        self->status_scan = STATUS_PROGESS;
                        zmsg_addstr(reply, RESP_OK);
                    } else {
                        zmsg_addstr(reply, RESP_ERR);
                    }
                } else {
                    log_error("compute_configuration_file: Error");
                    zmsg_addstr(reply, RESP_ERR);
                }
            }
            mlm_client_sendto(
                self->mlm, mlm_client_sender(self->mlm), mlm_client_subject(self->mlm), mlm_client_tracker(self->mlm), 1000, &reply);
            zstr_free(&zuuid);
        } else if (streq(cmd, REQ_PROGRESS)) {
            // PROGRESS
            // REQ <uuid>
            char*   zuuid = zmsg_popstr(msg);
            zmsg_t* reply = zmsg_new();
            zmsg_addstr(reply, zuuid);
            if (self->percent) {
                zmsg_addstr(reply, RESP_OK);
                zmsg_addstrf(reply, "%" PRIi32, self->status_scan);
                zmsg_addstr(reply, self->percent);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_discovered);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_ups_discovered);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_epdu_discovered);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_sts_discovered);
                zmsg_addstrf(reply, "%" PRIi64, self->nb_sensor_discovered);
            } else {
                zmsg_addstr(reply, RESP_OK);
                zmsg_addstrf(reply, "%" PRIi32, -1);
            }
            mlm_client_sendto(
                self->mlm, mlm_client_sender(self->mlm), mlm_client_subject(self->mlm), mlm_client_tracker(self->mlm), 1000, &reply);
            zstr_free(&zuuid);
        } else if (streq(cmd, REQ_STOPSCAN)) {
            // STOPSCAN
            // REQ <uuid>
            char*   zuuid = zmsg_popstr(msg);
            zmsg_t* reply = zmsg_new();
            zmsg_addstr(reply, zuuid);
            zmsg_addstr(reply, RESP_OK);

            mlm_client_sendto(
                self->mlm, mlm_client_sender(self->mlm), mlm_client_subject(self->mlm), mlm_client_tracker(self->mlm), 1000, &reply);
            if (self->range_scanner && !self->ongoing_stop) {
                self->status_scan  = STATUS_STOPPED;
                self->ongoing_stop = true;
                zstr_send(self->range_scanner, REQ_TERM);
            }

            zstr_free(&zuuid);

            self->localscan_subscan.clear();
            self->scan_size = 0;
        } else
            log_error("s_handle_mailbox: Unknown actor command: %s.\n", cmd);
        zstr_free(&cmd);
    }
    zmsg_destroy(&msg);
}

//  --------------------------------------------------------------------------
//  process message stream

void static s_handle_stream(fty_discovery_server_t* self, zmsg_t* message)
{
    if (fty_proto_is(message)) {
        // handle fty_proto protocol here
        fty_proto_t* fmsg = fty_proto_decode(&message);

        if (fmsg && (fty_proto_id(fmsg) == FTY_PROTO_ASSET)) {

            const char* operation = fty_proto_operation(fmsg);

            // TODO : Remove as soon as we can this ugly hack of "_no_not_really"
            if (streq(operation, FTY_PROTO_ASSET_OP_DELETE) && !zhash_lookup(fty_proto_aux(fmsg), "_no_not_really")) {
                const char*                 serial_no = fty_proto_ext_string(fmsg, "serial_no", NULL);
                const char*                 ip        = fty_proto_ext_string(fmsg, "ip.1", NULL);
                std::lock_guard<std::mutex> lock(self->devices_discovered.mtx_list);
                if (serial_no) {
                    self->devices_discovered.device_list.erase(serial_no);
                } else if (ip) {
                    logWarn("Removing by ip {}", ip);
                    self->devices_discovered.device_list.erase(ip);
                } else {
                    if (const char* iname = fty_proto_name(fmsg); iname) {
                        logWarn("Removing {} with no serial or ip address", iname);

                        auto found = std::find_if(
                            self->devices_discovered.device_list.begin(), self->devices_discovered.device_list.end(), [&](const auto& it) {
                                return it.second.name == iname;
                            });
                        if (found != self->devices_discovered.device_list.end()) {
                            self->devices_discovered.device_list.erase(found);
                        }
                    }
                }
            } else if (streq(operation, FTY_PROTO_ASSET_OP_CREATE) || streq(operation, FTY_PROTO_ASSET_OP_UPDATE)) {
                const char* serial_no = fty_proto_ext_string(fmsg, "serial_no", NULL);
                const char* prot      = fty_proto_ext_string(fmsg, "endpoint.1.protocol", NULL);
                const char* ip        = fty_proto_ext_string(fmsg, "ip.1", NULL);
                const char* iname     = fty_proto_name(fmsg);
                if (serial_no) {
                    if (self->devices_discovered.device_list.count(serial_no)) {
                        return;
                    }

                    if (!prot) {
                        if (const char* parent = fty_proto_aux_string(fmsg, "parent_name.1", nullptr); parent) {
                            auto found = std::find_if(
                                self->devices_discovered.device_list.begin(), self->devices_discovered.device_list.end(),
                                [&](const auto& it) {
                                    return it.second.name == parent;
                                });
                            if (found != self->devices_discovered.device_list.end()) {
                                prot = found->second.protocol.c_str();
                            }
                        }
                    }

                    std::lock_guard<std::mutex> lock(self->devices_discovered.mtx_list);
                    self->devices_discovered.device_list[serial_no] = {true, prot ? prot : "nut_snmp", iname};
                } else if (ip) {
                    std::lock_guard<std::mutex> lock(self->devices_discovered.mtx_list);
                    self->devices_discovered.device_list[ip] = {true, prot ? prot : "nut_snmp", iname};
                } else {
                    log_warning("Neither serial nor IP address are available for asset %s: may be duplicated during discovery", iname);
                }
            }
        }

        fty_proto_destroy(&fmsg);
    }
    zmsg_destroy(&message);
}

//  --------------------------------------------------------------------------
//  process message stream
//  * DONE
//  * FOUND
//  * POOGRESS

void static s_handle_range_scanner(fty_discovery_server_t* self, zmsg_t* msg, zpoller_t* poller, zsock_t* pipe)
{
    zmsg_print(msg);
    char* cmd = zmsg_popstr(msg);
    if (!cmd) {
        zmsg_destroy(&msg);
        log_warning("s_handle_range_scanner Empty command.");
        return;
    }
    log_debug("s_handle_range_scanner DO : %s", cmd);
    if (streq(cmd, REQ_DONE)) {
        if (self->ongoing_stop && self->range_scanner) {
            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        } else {
            zstr_send(pipe, REQ_DONE);
            if (!self->localscan_subscan.empty())
                self->localscan_subscan.clear();

            self->status_scan = STATUS_FINISHED;
            for (auto range : self->range_scan_config.ranges) {
                zstr_free(&(range.first));
                zstr_free(&(range.second));
            }
            self->range_scan_config.ranges.clear();

            zpoller_remove(poller, self->range_scanner);
            zactor_destroy(&self->range_scanner);
        }
    } else if (streq(cmd, REQ_FOUND)) {
        ftydiscovery_create_asset(self, &msg);
    } else if (streq(cmd, REQ_PROGRESS)) {
        self->nb_percent++;

        std::string percentstr = std::to_string(self->nb_percent * 100 / self->scan_size);

        if (self->percent)
            zstr_free(&self->percent);

        zmsg_t* zmfalse = zmsg_new();
        zmsg_addstr(zmfalse, percentstr.c_str());
        self->percent = zmsg_popstr(zmfalse);
        zmsg_destroy(&zmfalse);
        // other cmd. NOTFOUND must not be treated
    } else if (!streq(cmd, "NOTFOUND"))
        log_error("s_handle_range_scanner: Unknown  command: %s.\n", cmd);
    zstr_free(&cmd);
    zmsg_destroy(&msg);
}

//  --------------------------------------------------------------------------
//  fty_discovery_server actor

void fty_discovery_server(zsock_t* pipe, void* /* args */)
{
    fty_discovery_server_t* self   = fty_discovery_server_new();
    zpoller_t*              poller = zpoller_new(pipe, mlm_client_msgpipe(self->mlm), NULL);
    zsock_signal(pipe, 0);
    zmsg_t* range_stack = zmsg_new();

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, 5000);
        if (which == pipe) {
            if (!s_handle_pipe(self, zmsg_recv(pipe), poller))
                break; // TERM
        } else if (which == mlm_client_msgpipe(self->mlm)) {
            zmsg_t* message = mlm_client_recv(self->mlm);
            if (!message)
                continue;
            const char* command = mlm_client_command(self->mlm);
            if (streq(command, STREAM_CMD)) {
                s_handle_stream(self, message);
            } else if (streq(command, MAILBOX_CMD)) {
                s_handle_mailbox(self, message, poller);
            }
        } else if (self->range_scanner && which == self->range_scanner) {
            zmsg_t* message = zmsg_recv(self->range_scanner);
            if (!message)
                continue;
            s_handle_range_scanner(self, message, poller, pipe);
        }
        // check that scanner is NULL && we have to do scan
        if (self->range_scan_config.ranges.size() > 0 && !self->range_scanner) {
            if (zclock_mono() - assets_last_change(self->assets) > 5000) {
                // no asset change for last 5 secs => we can start range scan
                log_debug(
                    "Range scanner start for %s with config file %s", self->range_scan_config.ranges.front().first,
                    self->range_scan_config.config);
                // create range scanner
                // TODO: send list of IPs to skip
                reset_nb_discovered(self);
                self->nb_percent = 0;
                if (self->percent)
                    zstr_free(&self->percent);
                self->range_scanner = range_scanner_new(self);
                zpoller_add(poller, self->range_scanner);
            }
        }
    }
    zmsg_destroy(&range_stack);
    fty_discovery_server_destroy(&self);
    zpoller_destroy(&poller);
}

//  --------------------------------------------------------------------------
//  Create a new fty_discovery_server

fty_discovery_server_t* fty_discovery_server_new()
{
    fty_discovery_server_t* self = static_cast<fty_discovery_server_t*>(zmalloc(sizeof(fty_discovery_server_t)));
    assert(self);
    //  Initialize class properties here
    self->mlm                            = mlm_client_new();
    self->mlmCreate                      = mlm_client_new();
    self->scanner                        = NULL;
    self->assets                         = assets_new();
    self->nb_discovered                  = 0;
    self->nb_epdu_discovered             = 0;
    self->nb_sts_discovered              = 0;
    self->nb_ups_discovered              = 0;
    self->nb_sensor_discovered           = 0;
    self->scan_size                      = 0;
    self->device_centric                 = false;
    self->ongoing_stop                   = false;
    self->status_scan                    = -1;
    self->range_scan_config.config       = strdup(FTY_DISCOVERY_CFG_FILE);
    self->configuration_scan.type        = TYPE_LOCALSCAN;
    self->configuration_scan.scan_size   = 0;
    self->percent                        = NULL;
    self->devices_discovered.device_list = std::map<std::string, _discovered_devices_t::DevInfo>();
    self->nut_mapping_inventory          = fty::nut::KeyValues();
    self->nut_sensor_mapping_inventory   = fty::nut::KeyValues();
    self->default_values_aux             = std::map<std::string, std::string>();
    self->default_values_ext             = std::map<std::string, std::string>();
    self->default_values_links           = std::vector<link_t>();
    return self;
}

void fty_discovery_server_destroy(fty_discovery_server_t** self_p)
{
    assert(self_p);
    if (*self_p) {
        fty_discovery_server_t* self = *self_p;
        //  Free class properties here
        zactor_destroy(&self->scanner);
        mlm_client_destroy(&self->mlm);
        mlm_client_destroy(&self->mlmCreate);
        assets_destroy(&self->assets);
        if (self->range_scan_config.config)
            zstr_free(&self->range_scan_config.config);
        if (self->range_scan_config.ranges.size() > 0) {
            for (auto range : self->range_scan_config.ranges) {
                zstr_free(&(range.first));
                zstr_free(&(range.second));
            }
            self->range_scan_config.ranges.clear();
        }
        self->range_scan_config.ranges.shrink_to_fit();
        if (self->percent)
            zstr_free(&self->percent);
        self->devices_discovered.device_list.~map();
        if (self->range_scanner)
            zactor_destroy(&self->range_scanner);
        // FIXME: I, feel something so wrong / Doing the right thing...
        self->configuration_scan.scan_list.~vector();
        self->localscan_subscan.~vector();
        self->nut_mapping_inventory.~map();
        self->nut_sensor_mapping_inventory.~map();
        self->default_values_aux.~map();
        self->default_values_ext.~map();
        self->default_values_links.~vector();
        //  Free object itself
        free(self);
        *self_p = NULL;
    }
}
