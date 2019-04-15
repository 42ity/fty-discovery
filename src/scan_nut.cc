/*  =========================================================================
    scan_nut - collect information from DNS

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
    scan_nut - collect information from DNS
@discuss
@end
*/

#include "fty_discovery_classes.h"

#include <cxxtools/split.h>
#include <cxxtools/regex.h>
#include <algorithm>

enum DeviceCredentialsProtocols {
    DCP_NETXML,
    DCP_SNMPV1,
    DCP_SNMPV3
};

struct CredentialProtocolScanResult {
    CredentialProtocolScanResult() :
        protoCredsType(DCP_NETXML),
        protoCredsPtr(nullptr) {}

    CredentialProtocolScanResult(const nutcommon::CredentialsSNMPv1& creds) :
        protoCredsType(DCP_SNMPV1),
        protoCredsPtr(&creds) {}

    CredentialProtocolScanResult(const nutcommon::CredentialsSNMPv3& creds) :
        protoCredsType(DCP_SNMPV3),
        protoCredsPtr(&creds) {}

    DeviceCredentialsProtocols protoCredsType;
    const void* protoCredsPtr;
    nutcommon::DeviceConfigurations deviceConfigs;
};

bool ip_present(discovered_devices_t *device_discovered, std::string ip);

// parse nut config line (key = "value")
std::pair<std::string, std::string> s_nut_key_and_value (std::string &line)
{
    cxxtools::Regex regname ("[a-zA-Z0-9]+");
    cxxtools::Regex regvalue ("\"[^\"]+\"");
    cxxtools::RegexSMatch match;

    if (! regname.match (line, match, 0)) return std::make_pair ("", "");
    std::string name = line.substr (match.offsetBegin (0), match.offsetEnd(0) - match.offsetBegin (0));

    if (! regvalue.match (line, match, 0)) return  std::make_pair ("", "");
    std::string value = line.substr (match.offsetBegin (0) + 1, match.offsetEnd(0) - match.offsetBegin (0) - 2);

    return std::make_pair (name, value);
}

void s_nut_output_to_fty_messages(std::vector <fty_proto_t *>& assets, const nutcommon::DeviceConfigurations& output, discovered_devices_t *devices)
{
    for (const auto& device: output) {
        bool found = false;
        fty_proto_t *asset = fty_proto_new(FTY_PROTO_ASSET);

        const auto itDesc = device.find("desc");
        const auto itPort = device.find("port");
        if (itDesc != device.end()) {
            fty_proto_ext_insert(asset, "description", "%s", itDesc->second.c_str());
        }
        if (itPort != device.end()) {
            std::string ip;
            size_t pos = itPort->second.find("://");
            if(pos != std::string::npos)
                ip = itPort->second.substr(pos+3);
            else
                ip = itPort->second;
            if(ip_present(devices, ip)) {
                found = false;
                break;
            } else {
                fty_proto_ext_insert (asset, "ip.1", "%s", ip.c_str());
                fty_proto_aux_insert (asset, "type", "%s", "device");
                //temporarily save real "port" here to keep trace of protocol (http, https,...)
                fty_proto_ext_insert (asset, "name", "%s", itPort->second.c_str());
                found = true;
            }
        }

        if(!found) {
            fty_proto_destroy(&asset);
        } else {
            assets.push_back(asset);
        }
    }
}

void
s_nut_dumpdata_to_fty_message (fty_proto_t *fmsg, const nutcommon::DeviceConfiguration& dump)
{
    if (! fmsg) return;

    static nutcommon::DeviceConfiguration mapping = {
        {"device.model", "model"},
        {"ups.model", "model"},
        {"device.mfr", "manufacturer"},
        {"ups.mfr", "manufacturer"},
        {"device.serial", "serial_no"},
        {"device.description", "device.description"},
        {"device.contact", "device.contact"},
        {"device.location", "device.location"},
        {"device.part", "device.part"},
        {"ups.serial", "serial_no"},
        {"ups.firmware", "firmware"},
        {"battery.type", "battery.type"},
        {"input.phases", "phases.input"},
        {"output.phases", "phases.output"},
        {"outlet.count", "outlet.count"},
    };

    for (auto it: mapping) {
        auto item = dump.find (it.first);
        if (item != dump.end ()) {
            // item found
            fty_proto_ext_insert (fmsg, it.second.c_str (), "%s", item->second.c_str ());
        }
    }
    {
        // get type from dump is safer than parsing driver name
        auto item = dump.find ("device.type");
        if (item != dump.end ()) {
            const char *device = item->second.c_str ();
            if (streq (device, "pdu")) device = "epdu";
            if (streq (device, "ats")) device = "sts";
            fty_proto_aux_insert (fmsg, "subtype", "%s", device);
        }
    }
}
bool
s_valid_dumpdata (const nutcommon::DeviceConfiguration &dump)
{
  if(dump.find("device.type") == dump.end()) {
    log_error("No subtype for this device");
    return false;
  }

  if(dump.find("device.model") == dump.end() && dump.find("ups.model") == dump.end() &&
          dump.find("device.1.model") == dump.end() && dump.find("device.1.ups.model") == dump.end()) {
    log_error("No model for this device");
    return false;
  }

  if(dump.find("device.mfr") == dump.end() && dump.find("ups.mfr") == dump.end() &&
          dump.find("device.1.mfr") == dump.end() && dump.find("device.1.ups.mfr") == dump.end()) {
    log_error("No subtype for this device");
    return false;
  }

  return true;
}


void
s_nut_dumpdata_daisychain_to_fty_message (fty_proto_t *asset, const nutcommon::DeviceConfiguration &dump, zsock_t* pipe)
{
    if(! asset) return;

    auto item = dump.find ("device.count");
    if(item == dump.end () || streq(item->second.c_str(), "1")) {
        s_nut_dumpdata_to_fty_message(asset, dump);
        return;
    }
    int nbDevice = std::stoi(item->second);

    for(int i= 1; i <= nbDevice; i++) {
        std::string first_part = "device." + std::to_string(i);
        std::map <std::string, std::string> mapping = {
            {first_part + ".model", "model"},
            {first_part + ".ups.model", "model"},
            {first_part + ".mfr", "manufacturer"},
            {first_part + ".ups.mfr", "manufacturer"},
            {first_part + ".serial", "serial_no"},
            {first_part + ".description", "device.description"},
            {"device.contact", "device.contact"},
            {"device.location", "device.location"},
            {first_part + ".part", "device.part"},
            {first_part + ".ups.serial", "serial_no"},
            {first_part + ".ups.firmware", "firmware"},
            {first_part + ".input.phases", "phases.input"},
            {first_part + ".outlet.count", "outlet.count"}
        };

        if(dump.find(first_part+".mfr") == dump.end() && dump.find(first_part+".ups.mfr") == dump.end() &&
          dump.find(first_part+".model") == dump.end() && dump.find(first_part+".ups.model") == dump.end()) {
          log_error("No manufacturer or model for the  %i th device ", i);
          break;
        }

        fty_proto_t *fmsg;
        if(i != 1) {
            fmsg = fty_proto_new(FTY_PROTO_ASSET);

            fty_proto_ext_insert (fmsg, "ip.1", "%s", fty_proto_ext_string(asset,"ip.1", ""));
            fty_proto_aux_insert (fmsg, "type", "%s", fty_proto_aux_string(asset,"type", ""));
        } else
            fmsg = asset;
        for (auto it: mapping) {
            auto item = dump.find (it.first);
            if (item != dump.end ()) {
                // item found
                fty_proto_ext_insert (fmsg, it.second.c_str (), "%s", item->second.c_str ());
            }
        }
        {
            // get type from dump is safer than parsing driver name
            auto item = dump.find ("device.type");
            if (item != dump.end ()) {
                const char *device = item->second.c_str ();
                if (streq (device, "pdu")) device = "epdu";
                if (streq (device, "ats")) device = "sts";
                fty_proto_aux_insert (fmsg, "subtype", "%s", device);
            }
        }
        fty_proto_ext_insert(fmsg, "daisy_chain", "%" PRIi32, i);

        if(i != 1) {
            zmsg_t *reply = fty_proto_encode (&fmsg);
            zmsg_pushstr (reply, "FOUND_DC");
            zmsg_send (&reply, pipe);
        }
    }
}

//
bool
ip_present(discovered_devices_t *device_discovered, std::string ip) {
    if(!device_discovered)
        return false;

    device_discovered->mtx_list.lock();
    char* c = (char*) zhash_first( device_discovered->device_list);

    while(c && !streq(c, ip.c_str())) {
        c = (char*) zhash_next( device_discovered->device_list);
    }

    bool present = (c != NULL);
    device_discovered->mtx_list.unlock();

    return present;
}

bool ask_actor_term(zsock_t *pipe) {
    zmsg_t *msg_stop = zmsg_recv_nowait(pipe);
    if(msg_stop) {
        char *cmd = zmsg_popstr (msg_stop);
        if(cmd && streq (cmd, "$TERM")) {
            zstr_free(&cmd);
            zmsg_destroy(&msg_stop);
            return true;
        }
        zstr_free(&cmd);
        zmsg_destroy(&msg_stop);
    }
    return false;
}

bool inform_and_wait(zsock_t* pipe) {
    bool stop_now = true;
    zmsg_t *msg_ready = zmsg_new();
    zmsg_pushstr(msg_ready, INFO_READY);
    zmsg_send (&msg_ready, pipe);

    zmsg_t *msg_run = zmsg_recv(pipe);
    if(msg_run) {
        char *cmd = zmsg_popstr(msg_run);
        if(cmd && streq (cmd, CMD_CONTINUE)) {
            stop_now = false;
        }
        zstr_free(&cmd);
        zmsg_destroy(&msg_run);
    }

    if(zsys_interrupted) stop_now = true;

    return stop_now;
}

#define BIOS_NUT_DUMPDATA_ENV "BIOS_NUT_DUMPDATA"

void
dump_data_actor(zsock_t *pipe, void *args) {
    zsock_signal (pipe, 0);
    zlist_t *argv = (zlist_t *)args;
    bool valid = true;
    fty_proto_t *asset;
    const CredentialProtocolScanResult *cpsr;

    int loop_nb = -1;
    if (::getenv(BIOS_NUT_DUMPDATA_ENV)) {
        loop_nb = std::stoi(::getenv(BIOS_NUT_DUMPDATA_ENV));
    }
    if (loop_nb <= 0) {
        loop_nb = std::stoi(DEFAULT_DUMPDATA_LOOP);
    }

    int loop_iter_time = std::stoi(DEFAULT_DUMPDATA_LOOPTIME);
    zconfig_t *config = zconfig_load(getDiscoveryConfigFile().c_str());
    if (config) {
        loop_iter_time = std::stoi(zconfig_get(config, CFG_PARAM_DUMPDATA_LOOPTIME, DEFAULT_DUMPDATA_LOOPTIME));
        zconfig_destroy(&config);
    }

    zmsg_t *reply;
    if (!argv || zlist_size(argv) != 2) {
        valid = false;
    } else {
       asset = reinterpret_cast<fty_proto_t*>(zlist_first(argv));
       cpsr = reinterpret_cast<const CredentialProtocolScanResult*>(zlist_next(argv));
    }

    if(!valid) {
        //ERROR
        log_error("Dump data actor error: not enough args");
        reply = zmsg_new();
        zmsg_pushstr(reply, "ERROR");
    } else {
        //waiting message from caller
        //it avoid Assertion failed: pfd.revents & POLLIN (signaler.cpp:242) on zpoller_wait for
        // a pool of zactor who use Subprocess
        if(inform_and_wait(pipe)) {
            zlist_destroy(&argv);
            return;
        }

        int r = -1;
        const std::string addr = fty_proto_ext_string(asset, "name", "");
        std::string deviceType = "unknown";
        nutcommon::DeviceConfiguration nutdata;

        switch (cpsr->protoCredsType) {
        case DCP_SNMPV3:
            deviceType = "SNMPv3 securityName='" + reinterpret_cast<const nutcommon::CredentialsSNMPv3*>(cpsr->protoCredsPtr)->secName + "'";
            r = nutcommon::dumpDeviceSNMPv3(addr, *reinterpret_cast<const nutcommon::CredentialsSNMPv3*>(cpsr->protoCredsPtr), loop_nb, loop_iter_time, nutdata);
            break;
        case DCP_SNMPV1:
            deviceType = "SNMPv1 community='" + reinterpret_cast<const nutcommon::CredentialsSNMPv1*>(cpsr->protoCredsPtr)->community + "'";
            r = nutcommon::dumpDeviceSNMPv1(addr, *reinterpret_cast<const nutcommon::CredentialsSNMPv1*>(cpsr->protoCredsPtr), loop_nb, loop_iter_time, nutdata);
            break;
        case DCP_NETXML:
            deviceType = "NetXML";
            r = nutcommon::dumpDeviceNetXML(addr, loop_nb, loop_iter_time, nutdata);
            break;
        }

        if (r == 0) {
            if (s_valid_dumpdata(nutdata)) {
                log_debug("Dump data for %s (%s) succeeded.", addr.c_str(), deviceType.c_str());

                s_nut_dumpdata_daisychain_to_fty_message (asset, nutdata, pipe);
                reply = fty_proto_encode (&asset);
                zmsg_pushstr (reply, "FOUND");
            }
            else {
                log_debug("Dump data for %s (%s) failed: invalid data.", addr.c_str(), deviceType.c_str());

                fty_proto_destroy(&asset);
                reply = zmsg_new();
                zmsg_pushstr(reply, "FAILED");
            }
        }
        else {
            log_debug("Dump data for %s (%s) failed: failed to dump data.", addr.c_str(), deviceType.c_str());

            fty_proto_destroy(&asset);
            reply = zmsg_new();
            zmsg_pushstr(reply, "FAILED");
        }
    }

    zmsg_send (&reply, pipe);

    bool stop  = false;
    while(!stop && !zsys_interrupted) {
        zmsg_t *msg_stop = zmsg_recv(pipe);
        if(msg_stop) {
            char *cmd = zmsg_popstr (msg_stop);
            if(cmd && streq (cmd, "$TERM")) {
                stop = true;
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg_stop);
        }
    }
    zlist_destroy(&argv);
}

bool
create_pool_dumpdata(const CredentialProtocolScanResult &result, discovered_devices_t *devices, zsock_t *pipe)
{
    bool stop_now =false;
    std::vector<fty_proto_t *> listDiscovered;
    std::vector<zactor_t *> listActor;
    zpoller_t *poller = zpoller_new(pipe, NULL);

    zconfig_t *config = zconfig_load(getDiscoveryConfigFile().c_str());
    if (!config) {
        log_error("failed to load config file %s", getDiscoveryConfigFile().c_str());
        config = zconfig_new("root", NULL);
    }

    char* strNbPool = zconfig_get(config, CFG_PARAM_MAX_DUMPPOOL_NUMBER, DEFAULT_MAX_DUMPPOOL_NUMBER);
    const size_t number_max_pool = std::stoi(strNbPool);

    s_nut_output_to_fty_messages(listDiscovered, result.deviceConfigs, devices);
    size_t number_asset_view = 0;
    while(number_asset_view < listDiscovered.size()) {
        if(ask_actor_term(pipe)) stop_now = true;
        if(zsys_interrupted || stop_now)
            break;
        size_t number_pool = 0;
        while(number_pool < number_max_pool && number_asset_view < listDiscovered.size()) {
            fty_proto_t *asset = listDiscovered.at(number_asset_view);
            number_asset_view++;
            zlist_t *listarg = zlist_new();
            zlist_append(listarg, asset);
            zlist_append(listarg, const_cast<void*>(reinterpret_cast<const void*>(&result)));
            zactor_t *actor = zactor_new (dump_data_actor, listarg);

            zmsg_t *msg_ready = zmsg_recv(actor);
            if(msg_ready) {
                char *cmd = zmsg_popstr(msg_ready);
                if(cmd && streq (cmd, INFO_READY)) {
                    number_pool++;
                    listActor.push_back(actor);
                    zpoller_add(poller,actor);
                } else {
                    zactor_destroy(&actor);
                }
                zstr_free(&cmd);
                zmsg_destroy(&msg_ready);
            }
        }

        //All subactor createdfor this one, inform and wait
        zmsg_t *msg_ready = zmsg_new();
        zmsg_pushstr(msg_ready, INFO_READY);
        zmsg_send (&msg_ready, pipe);
        //wait
        stop_now = true;
        zmsg_t *msg_run = zmsg_recv(pipe);
        if(msg_run) {
            char *cmd = zmsg_popstr(msg_run);
            if(cmd && streq (cmd, CMD_CONTINUE)) {
                stop_now = false;
                //All subactor created, they can continue
                for(auto actor : listActor) {
                    zmsg_t *msg_cont = zmsg_new();
                    zmsg_pushstr(msg_cont, CMD_CONTINUE);
                    zmsg_send (&msg_cont, actor);
                }
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg_run);
        }

        size_t count = 0;
        while (count < number_pool) {
            if(zsys_interrupted || stop_now) {
                stop_now = true;
                break;
            }
            void *which = zpoller_wait(poller, -1);
            if(which != NULL) {
                zmsg_t *msg_rec = zmsg_recv(which);
                if(msg_rec) {
                    char *cmd = zmsg_popstr (msg_rec);
                    if(which == pipe) {
                        if(cmd && streq (cmd, "$TERM")) {
                            zstr_free(&cmd);
                            zmsg_destroy(&msg_rec);
                            stop_now = true;
                        }
                    } else if (which != NULL) {
                        count++;
                        if(cmd && streq (cmd, "FOUND")) {
                            zpoller_remove(poller, which);
                            zmsg_pushstr(msg_rec, "FOUND");
                            zmsg_send (&msg_rec, pipe);
                        } else if (cmd && streq (cmd, "FOUND_DC")) {
                            zmsg_pushstr(msg_rec, "FOUND");
                            zmsg_send(&msg_rec, pipe);
                            count--;
                        } else { //Dump failed
                            zpoller_remove(poller, which);
                            zmsg_destroy(&msg_rec);
                        }
                        zstr_free(&cmd);
                    }
                }
            } else {
                log_debug("Error on create_pool_dumpdata");
                stop_now = true;
                break;
            }
        }

        for(auto actor : listActor) {
            zactor_destroy(&actor);
        }

        listActor.clear();
    }

    while(number_asset_view < listDiscovered.size()) {
        fty_proto_t *asset = listDiscovered.at(number_asset_view);
        fty_proto_destroy(&asset);
        number_asset_view++;
    }

    listDiscovered.clear();
    zpoller_destroy(&poller);
    zconfig_destroy(&config);
    return stop_now;
}

//  --------------------------------------------------------------------------
//  Scan IPs addresses using nut-scanner
void
scan_nut_actor(zsock_t *pipe, void *args)
{
    bool stop_now =false;
    zsock_signal (pipe, 0);
    if (! args ) {
        log_error ("%s : actor created without parameters", __FUNCTION__);
        zmsg_t *reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send (&reply, pipe);
        return;
    }

    zlist_t *argv = (zlist_t *)args;
    if (!argv || zlist_size(argv) != 2) {
        log_error ("%s : actor created without config or devices list", __FUNCTION__);
        zlist_destroy(&argv);
        zmsg_t *reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send (&reply, pipe);
        return;
    }

    CIDRList *listAddr = (CIDRList *) zlist_first(argv);
    discovered_devices_t *devices = (discovered_devices_t*) zlist_tail(argv);
    if (!listAddr || !devices) {
        log_error ("%s : actor created without config or devices list", __FUNCTION__);
        zlist_destroy(&argv);
        zmsg_t *reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send (&reply, pipe);
        if(listAddr)
            delete listAddr;
        return;
    }

    std::vector<CredentialProtocolScanResult> results;
    const auto credentialsV3 = nutcommon::getCredentialsSNMPv3();
    const auto credentialsV1 = nutcommon::getCredentialsSNMPv1();

    // Grab timeout.
    int timeout;
    {
        std::string strTimeout = DEFAULT_NUTSCAN_TIMEOUT;
        zconfig_t *config = zconfig_load(getDiscoveryConfigFile().c_str());
        if (config) {
            strTimeout = zconfig_get(config, CFG_PARAM_NUTSCAN_TIMEOUT, DEFAULT_NUTSCAN_TIMEOUT);
            zconfig_destroy(&config);
        }
        timeout = std::stoi(strTimeout);
    }

    const nutcommon::ScanRangeOptions scanRangeOptions(
        listAddr->firstAddress().toString(CIDR_WITHOUT_PREFIX),
        listAddr->lastAddress().toString(CIDR_WITHOUT_PREFIX),
        timeout
    );

    /**
     * Scan the network and store credential/protocol pairs which returned data.
     */
    // SNMPv3 scan.
    {
        for (const auto& credential : credentialsV3) {
            CredentialProtocolScanResult result(credential);
            nutcommon::scanDeviceRangeSNMPv3(scanRangeOptions, credential, false, result.deviceConfigs);
            if (!result.deviceConfigs.empty()) {
                results.emplace_back(result);
            }
        }
    }
    // SNMPv1 scan.
    {
        for (const auto& credential : credentialsV1) {
            CredentialProtocolScanResult result(credential);
            nutcommon::scanDeviceRangeSNMPv1(scanRangeOptions, credential, false, result.deviceConfigs);
            if (!result.deviceConfigs.empty()) {
                results.emplace_back(result);
            }
        }
    }
    // NetXML scan.
    {
        CredentialProtocolScanResult result;
        nutcommon::scanDeviceRangeNetXML(scanRangeOptions, result.deviceConfigs);
        if (!result.deviceConfigs.empty()) {
            results.emplace_back(result);
        }
    }

    if(ask_actor_term(pipe)) stop_now = true;

    if(zsys_interrupted || stop_now ) {
        zlist_destroy(&argv);
        zmsg_t *reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send (&reply, pipe);
        delete listAddr;
        return;
    }

    stop_now = inform_and_wait(pipe);

    if(zsys_interrupted || stop_now ) {
        zlist_destroy(&argv);
        zmsg_t *reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send (&reply, pipe);
        delete listAddr;
        return;
    }

    for (const auto &result : results) {
        stop_now = create_pool_dumpdata(result, devices, pipe);

        if(ask_actor_term(pipe)) {
            stop_now = true;
        }
        if(zsys_interrupted || stop_now) {
            break;
        }
    }

    zmsg_t *reply = zmsg_new();
    zmsg_pushstr(reply, REQ_DONE);
    zmsg_send (&reply, pipe);
    zlist_destroy(&argv);
    delete listAddr;
    log_debug ("scan nut actor exited");
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
scan_nut_test (bool verbose)
{
    printf (" * scan_nut: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
