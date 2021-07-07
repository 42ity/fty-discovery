/*  =========================================================================
    scan_nut - collect information from DNS

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

#include "scan_nut.h"
#include "cidr.h"
#include "device_scan.h"
#include "fty_discovery_server.h"
#include "scan_dns.h"
#include <algorithm>
#include <cxxtools/regex.h>
#include <cxxtools/split.h>
#include <fty/convert.h>
#include <fty_common_nut.h>
#include <fty_common_socket_sync_client.h>
#include <fty_log.h>
#include <fty_proto.h>
#include <map>
#include <secw_consumer_accessor.h>
#include <secw_document.h>
#include <set>
#include <vector>

static const std::string SECW_SOCKET_PATH = "/run/fty-security-wallet/secw.socket";

struct ScanResult
{
    ScanResult(const std::string& driver, const std::vector<secw::DocumentPtr>& docs = {})
        : nutDriver(driver)
        , documents(docs)
    {
    }

    std::string                    nutDriver;
    std::vector<secw::DocumentPtr> documents;
    fty::nut::DeviceConfigurations deviceConfigurations;
};

static std::map<std::string, std::string> getEndpointExtAttributs(const ScanResult& scanResult,
    const std::string& sensor, const std::string& daisyChain, const std::string& modbusAddress);

bool ip_present(discovered_devices_t* device_discovered, std::string ip);

// parse nut config line (key = "value")
std::pair<std::string, std::string> s_nut_key_and_value(std::string& line)
{
    cxxtools::Regex       regname("[a-zA-Z0-9]+");
    cxxtools::Regex       regvalue("\"[^\"]+\"");
    cxxtools::RegexSMatch match;

    if (!regname.match(line, match, 0))
        return std::make_pair("", "");
    std::string name = line.substr(
        fty::convert<size_t>(match.offsetBegin(0)), fty::convert<size_t>(match.offsetEnd(0) - match.offsetBegin(0)));

    if (!regvalue.match(line, match, 0))
        return std::make_pair("", "");
    std::string value = line.substr(fty::convert<size_t>(match.offsetBegin(0)) + 1,
        fty::convert<size_t>(match.offsetEnd(0) - match.offsetBegin(0)) - 2);

    return std::make_pair(name, value);
}

struct NutOutput
{
    std::string port;
    std::string ip;
};

void s_nut_output_to_messages(
    std::vector<NutOutput>& assets, const fty::nut::DeviceConfigurations& output, discovered_devices_t* devices)
{
    for (const auto& device : output) {
        bool      found = false;
        NutOutput asset;

        const auto itPort = device.find("port");
        if (itPort != device.end()) {
            std::string ip;
            size_t      pos = itPort->second.find("://");
            if (pos != std::string::npos) {
                ip = itPort->second.substr(pos + 3);
            } else {
                ip = itPort->second;
            }
            if (!ip_present(devices, ip)) {
                asset.ip   = ip.c_str();
                asset.port = itPort->second.c_str();
                found      = true;
            }
        }

        if (found) {
            assets.push_back(asset);
        }
    }
}

bool s_valid_dumpdata(const fty::nut::DeviceConfiguration& dump)
{
    if (dump.find("device.type") == dump.end()) {
        log_error("No subtype for this device");
        return false;
    }

    if (dump.find("device.model") == dump.end() && dump.find("ups.model") == dump.end() &&
        dump.find("device.1.model") == dump.end() && dump.find("device.1.ups.model") == dump.end()) {
        log_error("No model for this device");
        return false;
    }

    if (dump.find("device.mfr") == dump.end() && dump.find("ups.mfr") == dump.end() &&
        dump.find("device.1.mfr") == dump.end() && dump.find("device.1.ups.mfr") == dump.end()) {
        log_error("No manufacturer for this device");
        return false;
    }

    return true;
}


bool s_nut_dumpdata_to_fty_message(std::vector<fty_proto_t*>& assets, const fty::nut::DeviceConfiguration& dump,
    const fty::nut::KeyValues* mappings, const fty::nut::KeyValues* sensorMappings, const std::string& ip,
    const std::string& type)
{
    std::vector<fty_proto_t*> sensors;

    // Set up iteration limits according to daisy-chain configuration.
    int startDevice = 0, endDevice = 0;
    {
        auto item = dump.find("device.count");
        if (item != dump.end() && !streq(item->second.c_str(), "1")) {
            startDevice = 1;
            endDevice   = std::stoi(item->second);
        }
    }

    std::set<std::string> discoveredSerialSet;

    for (int i = startDevice; i <= endDevice; i++) {
        std::string deviceSerial;

        fty_proto_t* fmsg = fty_proto_new(FTY_PROTO_ASSET);

        // Map inventory data.
        auto mappedDump = fty::nut::performMapping(*mappings, dump, i);
        for (auto property : mappedDump) {
            fty_proto_ext_insert(fmsg, property.first.c_str(), "%s", property.second.c_str());
        }

        auto serialFound = mappedDump.find("serial_no");
        if (serialFound != mappedDump.end()) {
            deviceSerial = serialFound->second;
        }

        // Try to obtain DNS name ("hostname" + "dns.1" attributes)
        scan_dns(fmsg, ip.c_str(), NULL);

        // Some special cases.
        fty_proto_ext_insert(fmsg, "ip.1", "%s", ip.c_str());
        fty_proto_aux_insert(fmsg, "type", "%s", type.c_str());
        if (i != 0) {
            fty_proto_ext_insert(fmsg, "daisy_chain", "%" PRIi32, i);
        }

        if (!fty_proto_ext_string(fmsg, "manufacturer", nullptr) || !fty_proto_ext_string(fmsg, "model", nullptr)) {
            log_error("No manufacturer or model for device number %i", i);
            fty_proto_destroy(&fmsg);
            continue;
        }

        {
            // Getting type from dump is safer than parsing driver name.
            auto item = dump.find("device.type");
            if (item != dump.end()) {
                const char* device = item->second.c_str();
                if (streq(device, "pdu")) {
                    device = "epdu";
                } else if (streq(device, "ats")) {
                    device = "sts";
                }
                fty_proto_aux_insert(fmsg, "subtype", "%s", device);
            }
        }

        // Ambient sensor(s)
        // Set up iteration limits according to daisy-chain configuration.
        // FIXME: check if indexed sensors collection is present, to discard
        // legacy sensor (ambient.{temperature,humidity})
        size_t startSensor = 0, endSensor = 0;
        {
            // First, check for new style and daisychained sensors
            std::string ambientCount = "ambient.count";
            if (i != 0) { // for daisy chained devices, the ambient count is stored in device.X.ambient.count
                ambientCount = "device." + std::to_string(i) + ".ambient.count";
            }
            auto item = dump.find(ambientCount);
            if (item != dump.end() && !streq(item->second.c_str(), "1")) {
                startSensor = 1;
                endSensor   = fty::convert<size_t>(item->second);
            } else {
                // Otherwise, fallback to checking for legacy sensors
                // First, use "ambient.present" if available
                item = dump.find("ambient.present");
                if (item != dump.end() && !streq(item->second.c_str(), "no")) {
                    startSensor = endSensor = 1;
                } else {
                    // Otherwise, fallback to checking "ambient.temperature" presence
                    item = dump.find("ambient.temperature");
                    if (item != dump.end()) {
                        startSensor = endSensor = 1;
                    }
                }
            }
        }

        log_debug("Discovered %i sensor(s)", endSensor);

        assets.emplace_back(fmsg);

        for (size_t s = startSensor; s <= endSensor; s++) {
            fty_proto_t* fsmsg = fty_proto_new(FTY_PROTO_ASSET);

            // Map inventory data.
            // FIXME: limit to ambient.*
            // FIXME: use a dedicated mapping?
            auto ambientMappedDump = fty::nut::performMapping(*sensorMappings, dump, fty::convert<int>(s));
            for (auto property : ambientMappedDump) {
                fty_proto_ext_insert(fsmsg, property.first.c_str(), "%s", property.second.c_str());
            }

            // FIXME: id_parent == current device!
            // FIXME: => location = parent ename

            // check if sensor is physically present (may be reported in NUT scan, but not present)
            auto item = ambientMappedDump.find("present");
            if (item == ambientMappedDump.end()) {
                log_error("No present field for sensor number %i", s);
                fty_proto_destroy(&fsmsg);
                continue;
            }

            if (item->second != "yes") {
                log_warning("Sensor %i is not present", s);
                fty_proto_destroy(&fsmsg);
                continue;
            }

            // get sensor serial number (mandatory)
            std::string sensorSerialNumber;
            item = ambientMappedDump.find("serial_no");
            if (item == ambientMappedDump.end()) {
                log_error("No serial number for sensor number %i", s);
                fty_proto_destroy(&fsmsg);
                continue;
            }
            sensorSerialNumber = item->second;

            // check if sensor was already discovered
            if (auto f = discoveredSerialSet.find(sensorSerialNumber); f != discoveredSerialSet.end()) {
                log_warning("Sensor %s already discovered. Skipping", sensorSerialNumber.c_str());
                fty_proto_destroy(&fsmsg);
                continue;
            } else {
                // add sensor serial to set of discovered devices
                discoveredSerialSet.insert(sensorSerialNumber);
            }

            // look for parent serial number (optional)
            item = ambientMappedDump.find("parent_serial");
            std::string parentSerial;
            if (item != ambientMappedDump.end()) {
                parentSerial = item->second;
            }

            // look for sensor model (mandatory)
            std::string sensorModel;
            item = ambientMappedDump.find("model");
            // model field could be not present, if there is parent_serial field -> EMP002
            if (item != ambientMappedDump.end()) {
                sensorModel = item->second;
                // some devices report Eaton EMPDT1H1C2 instead of EMPDT1H1C2
                if (sensorModel.compare("Eaton EMPDT1H1C2") == 0) {
                    sensorModel = "EMPDT1H1C2";
                }
            } else if (!parentSerial.empty()) {
                sensorModel = "EMPDT1H1C2";
            } else {
                log_error("No model for sensor number %i", s);
                fty_proto_destroy(&fsmsg);
                continue;
            }

            // look for manufacturer (mandatory)
            item = ambientMappedDump.find("manufacturer");
            std::string sensorManufacturer;
            if (item != ambientMappedDump.end()) {
                sensorManufacturer = item->second;
            } else {
                log_error("No manufacturer for sensor number %i", s);
                fty_proto_destroy(&fsmsg);
                continue;
            }

            // define parent name (parent_name.1 field)
            std::string parentName = type + " (" + ip + ")";
            if (!deviceSerial.empty()) {
                parentName = deviceSerial;
            }

            // set parent identifier as the first available of:
            // - parentSerial
            // - deviceSerial
            // - ip
            std::string parentIdentifier = [&]() {
                if (!parentSerial.empty()) {
                    return parentSerial;
                } else if (!deviceSerial.empty()) {
                    return deviceSerial;
                }
                return ip;
            }();

            // set unique sensor external name
            // default name may be duplicated (i.e., EMPDT1H1C2 @1)
            std::string externalName = "sensor " + sensorModel + " (" + sensorSerialNumber + ")";

            fty_proto_aux_insert(fsmsg, "name", sensorSerialNumber.c_str());
            fty_proto_aux_insert(fsmsg, "type", "device");
            fty_proto_aux_insert(fsmsg, "subtype", "sensor");
            fty_proto_aux_insert(fsmsg, "parent", parentIdentifier.c_str());
            fty_proto_ext_insert(fsmsg, "name", externalName.c_str());
            fty_proto_ext_insert(fsmsg, "model", sensorModel.c_str());

            // model dependent checks
            if (sensorModel.compare("EMPDT1H1C2") == 0) {
                // look for modbus address (mandatory)
                std::string modbusAddress;
                item = ambientMappedDump.find("modbus_address");
                if (item != ambientMappedDump.end()) {
                    modbusAddress = item->second;
                } else {
                    log_error("No modbus address for sensor number %i", s);
                    fty_proto_destroy(&fsmsg);
                    continue;
                }
            } else {
                // currently other models are not supported in auto discovery
                log_error("Invalid sensor model %s", sensorModel.c_str());
                fty_proto_destroy(&fsmsg);
                continue;
            }
            // FIXME: also dry contacts?
            // FIXME: needed?
            log_debug("Added new sensor (%d of %d): SERIAL: %s - TYPE: %s - PARENT: %s", s, endSensor,
                sensorSerialNumber.c_str(), sensorModel.c_str(), parentIdentifier.c_str());
            sensors.emplace_back(fsmsg);
        }
    }

    for (const auto& s : sensors) {
        assets.push_back(s);
    }

    return !assets.empty();
}

//
bool ip_present(discovered_devices_t* device_discovered, std::string ip)
{
    if (!device_discovered)
        return false;

    std::lock_guard<std::mutex> lock(device_discovered->mtx_list);

    const auto& device_list = device_discovered->device_list;
    auto found = std::find_if(device_list.begin(), device_list.end(), [&](std::pair<std::string, std::string> el) {
        return ip == el.second;
    });

    bool present = (found != device_list.end());

    return present;
}

bool ask_actor_term(zsock_t* pipe)
{
    zmsg_t* msg_stop = zmsg_recv_nowait(pipe);
    if (msg_stop) {
        char* cmd = zmsg_popstr(msg_stop);
        if (cmd && streq(cmd, "$TERM")) {
            zstr_free(&cmd);
            zmsg_destroy(&msg_stop);
            return true;
        }
        zstr_free(&cmd);
        zmsg_destroy(&msg_stop);
    }
    return false;
}

bool inform_and_wait(zsock_t* pipe)
{
    bool    stop_now  = true;
    zmsg_t* msg_ready = zmsg_new();
    zmsg_pushstr(msg_ready, INFO_READY);
    zmsg_send(&msg_ready, pipe);

    zmsg_t* msg_run = zmsg_recv(pipe);
    if (msg_run) {
        char* cmd = zmsg_popstr(msg_run);
        if (cmd && streq(cmd, CMD_CONTINUE)) {
            stop_now = false;
        }
        zstr_free(&cmd);
        zmsg_destroy(&msg_run);
    }

    if (zsys_interrupted)
        stop_now = true;

    return stop_now;
}

#define BIOS_NUT_DUMPDATA_ENV "BIOS_NUT_DUMPDATA"

void dump_data_actor(zsock_t* pipe, void* args)
{
    zsock_signal(pipe, 0);
    zlist_t*                   argv  = static_cast<zlist_t*>(args);
    bool                       valid = true;
    NutOutput*                 initialAsset;
    const ScanResult*          cpsr;
    const fty::nut::KeyValues* mappings;
    const fty::nut::KeyValues* sensorMappings;

    int loop_nb = -1;
    if (::getenv(BIOS_NUT_DUMPDATA_ENV)) {
        loop_nb = std::stoi(::getenv(BIOS_NUT_DUMPDATA_ENV));
    }
    if (loop_nb <= 0) {
        loop_nb = std::stoi(DEFAULT_DUMPDATA_LOOP);
    }

    int        loop_iter_time = std::stoi(DEFAULT_DUMPDATA_LOOPTIME);
    zconfig_t* config         = zconfig_load(getDiscoveryConfigFile().c_str());
    if (config) {
        loop_iter_time = std::stoi(zconfig_get(config, CFG_PARAM_DUMPDATA_LOOPTIME, DEFAULT_DUMPDATA_LOOPTIME));
        zconfig_destroy(&config);
    }

    zmsg_t* reply;
    if (!argv || zlist_size(argv) != 4) {
        valid = false;
    } else {
        initialAsset   = reinterpret_cast<NutOutput*>(zlist_first(argv));
        cpsr           = reinterpret_cast<const ScanResult*>(zlist_next(argv));
        mappings       = reinterpret_cast<const fty::nut::KeyValues*>(zlist_next(argv));
        sensorMappings = reinterpret_cast<const fty::nut::KeyValues*>(zlist_next(argv));
    }

    if (!valid) {
        // ERROR
        log_error("Dump data actor error: not enough args");
        reply = zmsg_new();
        zmsg_pushstr(reply, "ERROR");
    } else {
        // waiting message from caller
        // it avoid Assertion failed: pfd.revents & POLLIN (signaler.cpp:242) on zpoller_wait for
        // a pool of zactor who use Subprocess
        if (inform_and_wait(pipe)) {
            zlist_destroy(&argv);
            return;
        }

        const std::string addr = initialAsset->port;
        const std::string ip   = initialAsset->ip;
        const std::string type = "device";

        fty::nut::DeviceConfiguration nutdata = fty::nut::dumpDevice(cpsr->nutDriver, addr,
            fty::convert<unsigned>(loop_nb), fty::convert<unsigned>(loop_iter_time), cpsr->documents);

        if (!nutdata.empty()) {
            std::vector<fty_proto_t*> assets;
            if (s_valid_dumpdata(nutdata) &&
                s_nut_dumpdata_to_fty_message(assets, nutdata, mappings, sensorMappings, ip, type)) {
                log_debug("Dump data for %s (%s) succeeded.", addr.c_str(), cpsr->nutDriver.c_str());

                for (auto i = assets.cbegin(); i != assets.cend(); i++) {
                    fty_proto_t* asset = *i;
                    // get asset subtype
                    std::string subtype(fty_proto_aux_string(asset, "subtype", ""));
                    std::string sensor;
                    if (streq(subtype.c_str(), "sensor")) {
                        // if the device is a sensor, but the model is not present, we need to fill the field anyway
                        sensor = fty_proto_ext_string(asset, "model", "unknown");
                    }

                    log_debug("Processing asset %s (%s - %s)", fty_proto_aux_string(asset, "name", "iname"),
                        type.c_str(), subtype.c_str());

                    // add the endpoint data
                    std::string daisyChain(fty_proto_ext_string(asset, "daisy_chain", ""));
                    std::string modbusAddress(fty_proto_ext_string(asset, "modbus_address", ""));

                    for (const auto& item : getEndpointExtAttributs(*cpsr, sensor, daisyChain, modbusAddress)) {
                        fty_proto_ext_insert(asset, item.first.c_str(), "%s", item.second.c_str());
                    }

                    reply = fty_proto_encode(&asset);
                    zmsg_pushstr(reply, i == (assets.cend() - 1) ? "FOUND" : "FOUND_DC");
                    zmsg_send(&reply, pipe);
                }
            } else {
                log_debug("Dump data for %s (%s) failed: invalid data.", addr.c_str(), cpsr->nutDriver.c_str());

                reply = zmsg_new();
                zmsg_pushstr(reply, "FAILED");
            }
        } else {
            log_debug("Dump data for %s (%s) failed: failed to dump data.", addr.c_str(), cpsr->nutDriver.c_str());

            reply = zmsg_new();
            zmsg_pushstr(reply, "FAILED");
        }
    }

    if (reply) {
        zmsg_send(&reply, pipe);
    }

    bool stop = false;
    while (!stop && !zsys_interrupted) {
        zmsg_t* msg_stop = zmsg_recv(pipe);
        if (msg_stop) {
            char* cmd = zmsg_popstr(msg_stop);
            if (cmd && streq(cmd, "$TERM")) {
                stop = true;
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg_stop);
        }
    }
    zlist_destroy(&argv);
}

bool create_pool_dumpdata(const ScanResult& result, discovered_devices_t* devices, zsock_t* pipe,
    const fty::nut::KeyValues* mappings, const fty::nut::KeyValues* sensorMappings)
{
    bool                   stop_now = false;
    std::vector<NutOutput> listDiscovered;
    std::vector<zactor_t*> listActor;
    zpoller_t*             poller = zpoller_new(pipe, NULL);

    zconfig_t* config = zconfig_load(getDiscoveryConfigFile().c_str());
    if (!config) {
        log_error("failed to load config file %s", getDiscoveryConfigFile().c_str());
        config = zconfig_new("root", NULL);
    }

    char*        strNbPool       = zconfig_get(config, CFG_PARAM_MAX_DUMPPOOL_NUMBER, DEFAULT_MAX_DUMPPOOL_NUMBER);
    const size_t number_max_pool = fty::convert<size_t>(strNbPool);

    s_nut_output_to_messages(listDiscovered, result.deviceConfigurations, devices);
    size_t number_asset_view = 0;
    while (number_asset_view < listDiscovered.size()) {
        if (ask_actor_term(pipe))
            stop_now = true;
        if (zsys_interrupted || stop_now)
            break;
        size_t number_pool = 0;
        while (number_pool < number_max_pool && number_asset_view < listDiscovered.size()) {
            auto& asset = listDiscovered.at(number_asset_view);
            number_asset_view++;
            zlist_t* listarg = zlist_new();
            zlist_append(listarg, &asset);
            zlist_append(listarg, const_cast<void*>(reinterpret_cast<const void*>(&result)));
            zlist_append(listarg, const_cast<void*>(reinterpret_cast<const void*>(mappings)));
            zlist_append(listarg, const_cast<void*>(reinterpret_cast<const void*>(sensorMappings)));
            zactor_t* actor = zactor_new(dump_data_actor, listarg);

            zmsg_t* msg_ready = zmsg_recv(actor);
            if (msg_ready) {
                char* cmd = zmsg_popstr(msg_ready);
                if (cmd && streq(cmd, INFO_READY)) {
                    number_pool++;
                    listActor.push_back(actor);
                    zpoller_add(poller, actor);
                } else {
                    zactor_destroy(&actor);
                }
                zstr_free(&cmd);
                zmsg_destroy(&msg_ready);
            }
        }

        // All subactor createdfor this one, inform and wait
        zmsg_t* msg_ready = zmsg_new();
        zmsg_pushstr(msg_ready, INFO_READY);
        zmsg_send(&msg_ready, pipe);
        // wait
        stop_now        = true;
        zmsg_t* msg_run = zmsg_recv(pipe);
        if (msg_run) {
            char* cmd = zmsg_popstr(msg_run);
            if (cmd && streq(cmd, CMD_CONTINUE)) {
                stop_now = false;
                // All subactor created, they can continue
                for (auto actor : listActor) {
                    zmsg_t* msg_cont = zmsg_new();
                    zmsg_pushstr(msg_cont, CMD_CONTINUE);
                    zmsg_send(&msg_cont, actor);
                }
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg_run);
        }

        size_t count = 0;
        while (count < number_pool) {
            if (zsys_interrupted || stop_now) {
                stop_now = true;
                break;
            }
            void* which = zpoller_wait(poller, -1);
            if (which != NULL) {
                zmsg_t* msg_rec = zmsg_recv(which);
                if (msg_rec) {
                    char* cmd = zmsg_popstr(msg_rec);
                    if (which == pipe) {
                        if (cmd && streq(cmd, "$TERM")) {
                            zstr_free(&cmd);
                            zmsg_destroy(&msg_rec);
                            stop_now = true;
                        }
                    } else if (which != NULL) {
                        count++;
                        if (cmd && streq(cmd, "FOUND")) {
                            zpoller_remove(poller, which);
                            zmsg_pushstr(msg_rec, "FOUND");
                            zmsg_send(&msg_rec, pipe);
                        } else if (cmd && streq(cmd, "FOUND_DC")) {
                            zmsg_pushstr(msg_rec, "FOUND");
                            zmsg_send(&msg_rec, pipe);
                            count--;
                        } else { // Dump failed
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

        for (auto actor : listActor) {
            zactor_destroy(&actor);
        }

        listActor.clear();
    }

    zpoller_destroy(&poller);
    zconfig_destroy(&config);
    return stop_now;
}

static std::map<std::string, std::string> getEndpointExtAttributs(const ScanResult& scanResult,
    const std::string& sensor, const std::string& daisyChain, const std::string& modbusAddress)
{
    std::map<std::string, std::string> extAttributs;

    if (scanResult.nutDriver == "snmp-ups") {
        if (sensor.empty()) { // not a sensor
            extAttributs["endpoint.1.protocol"]    = "nut_snmp";
            extAttributs["endpoint.1.port"]        = "161";
            extAttributs["endpoint.1.sub_address"] = (daisyChain == "0") ? "" : daisyChain;

            if (scanResult.documents.size() > 0) {
                extAttributs["endpoint.1.nut_snmp.secw_credential_id"] = scanResult.documents[0]->getId();
            } else {
                extAttributs["endpoint.1.nut_snmp.secw_credential_id"] = "";
            }
        } else {
            if (streq(sensor.c_str(), "EMPDT1H1C2")) {
                extAttributs["endpoint.1.sub_address"] = modbusAddress;
            } else {
                log_warning("Sensor model %s is not supported", sensor.c_str());
            }
        }
    } else if (scanResult.nutDriver == "netxml-ups") {
        if (sensor.empty()) { // not a sensor
            extAttributs["endpoint.1.sub_address"] = (daisyChain == "0") ? "" : daisyChain;
            extAttributs["endpoint.1.protocol"]    = "nut_xml_pdc";
            extAttributs["endpoint.1.port"]        = "80";
        } else {
            if (streq(sensor.c_str(), "EMPDT1H1C2")) {
                extAttributs["endpoint.1.sub_address"] = modbusAddress;
            } else {
                log_warning("Sensor model %s is not supported", sensor.c_str());
            }
        }
    }

    return extAttributs;
}

//  --------------------------------------------------------------------------
//  Scan IPs addresses using nut-scanner
void scan_nut_actor(zsock_t* pipe, void* args)
{
    bool stop_now = false;
    zsock_signal(pipe, 0);
    if (!args) {
        log_error("%s : actor created without parameters", __FUNCTION__);
        zmsg_t* reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send(&reply, pipe);
        return;
    }

    zlist_t* argv = static_cast<zlist_t*>(args);
    if (!argv || zlist_size(argv) != 5) {
        log_error("%s : actor created without config or devices list", __FUNCTION__);
        zlist_destroy(&argv);
        zmsg_t* reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send(&reply, pipe);
        return;
    }

    CIDRList*                    listAddr       = static_cast<CIDRList*>(zlist_first(argv));
    discovered_devices_t*        devices        = static_cast<discovered_devices_t*>(zlist_next(argv));
    const fty::nut::KeyValues*   mappings       = static_cast<const fty::nut::KeyValues*>(zlist_next(argv));
    const fty::nut::KeyValues*   sensorMappings = static_cast<const fty::nut::KeyValues*>(zlist_next(argv));
    const std::set<std::string>* documentNames  = static_cast<const std::set<std::string>*>(zlist_next(argv));
    if (!listAddr || !devices || !mappings || !sensorMappings || !documentNames) {
        log_error("%s : actor created without config or devices list", __FUNCTION__);
        zlist_destroy(&argv);
        zmsg_t* reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send(&reply, pipe);
        if (listAddr)
            delete listAddr;
        return;
    }

    std::vector<ScanResult>        results;
    std::vector<secw::DocumentPtr> credentialsV3;
    std::vector<secw::DocumentPtr> credentialsV1;

    // Grab security documents.
    try {
        fty::SocketSyncClient secwSyncClient(SECW_SOCKET_PATH);

        auto client   = secw::ConsumerAccessor(secwSyncClient);
        auto secCreds = client.getListDocumentsWithPrivateData("default", "discovery_monitoring");

        for (const auto& i : secCreds) {
            if (!documentNames->count(i->getId())) {
                continue;
            }

            auto credV3 = secw::Snmpv3::tryToCast(i);
            auto credV1 = secw::Snmpv1::tryToCast(i);
            if (credV3) {
                credentialsV3.emplace_back(i);
            } else if (credV1) {
                credentialsV1.emplace_back(i);
            }
        }
        log_debug("Fetched %d SNMPv3 and %d SNMPv1 credentials from security wallet.", credentialsV3.size(),
            credentialsV1.size());
    } catch (std::exception& e) {
        log_warning("Failed to fetch credentials from security wallet: %s", e.what());
    }

    // Grab timeout.
    int timeout;
    {
        std::string strTimeout = DEFAULT_NUTSCAN_TIMEOUT;
        zconfig_t*  config     = zconfig_load(getDiscoveryConfigFile().c_str());
        if (config) {
            strTimeout = zconfig_get(config, CFG_PARAM_NUTSCAN_TIMEOUT, DEFAULT_NUTSCAN_TIMEOUT);
            zconfig_destroy(&config);
        }
        timeout = std::stoi(strTimeout);
    }

    /**
     * Scan the network and store credential/protocol pairs which returned data.
     */
    // SNMPv3 scan.
    {
        for (const auto& credential : credentialsV3) {
            ScanResult result("snmp-ups", {credential});

            result.deviceConfigurations = fty::nut::scanRangeDevices(fty::nut::SCAN_PROTOCOL_SNMP,
                listAddr->firstAddress().toString(CIDR_WITHOUT_PREFIX),
                listAddr->lastAddress().toString(CIDR_WITHOUT_PREFIX), fty::convert<unsigned>(timeout),
                result.documents);

            results.emplace_back(result);
        }
    }
    // SNMPv1 scan.
    {
        for (const auto& credential : credentialsV1) {
            ScanResult result("snmp-ups", {credential});

            result.deviceConfigurations = fty::nut::scanRangeDevices(fty::nut::SCAN_PROTOCOL_SNMP,
                listAddr->firstAddress().toString(CIDR_WITHOUT_PREFIX),
                listAddr->lastAddress().toString(CIDR_WITHOUT_PREFIX), fty::convert<unsigned>(timeout),
                result.documents);

            results.emplace_back(result);
        }
    }
    // NetXML scan.
    {
        ScanResult result("netxml-ups");

        result.deviceConfigurations = fty::nut::scanRangeDevices(fty::nut::SCAN_PROTOCOL_NETXML,
            listAddr->firstAddress().toString(CIDR_WITHOUT_PREFIX),
            listAddr->lastAddress().toString(CIDR_WITHOUT_PREFIX), fty::convert<unsigned>(timeout));

        results.emplace_back(result);
    }

    if (ask_actor_term(pipe))
        stop_now = true;

    if (zsys_interrupted || stop_now) {
        zlist_destroy(&argv);
        zmsg_t* reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send(&reply, pipe);
        delete listAddr;
        return;
    }

    stop_now = inform_and_wait(pipe);

    if (zsys_interrupted || stop_now) {
        zlist_destroy(&argv);
        zmsg_t* reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send(&reply, pipe);
        delete listAddr;
        return;
    }

    for (const auto& result : results) {
        stop_now = create_pool_dumpdata(result, devices, pipe, mappings, sensorMappings);

        if (ask_actor_term(pipe)) {
            stop_now = true;
        }
        if (zsys_interrupted || stop_now) {
            break;
        }
    }

    zmsg_t* reply = zmsg_new();
    zmsg_pushstr(reply, REQ_DONE);
    zmsg_send(&reply, pipe);
    zlist_destroy(&argv);
    delete listAddr;
    log_debug("scan nut actor exited");
}
