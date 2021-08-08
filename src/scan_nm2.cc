#include "scan_nm2.h"
#include "cidr.h"
#include "fty_discovery_server.h"
#include "neon.h"
#include <fty_log.h>
#include <pack/pack.h>

// =========================================================================================================================================

struct Card : public pack::Node
{
    struct Identification : public pack::Node
    {
        pack::String uuid         = FIELD("uuid");
        pack::String vendor       = FIELD("vendor");
        pack::String manufacturer = FIELD("manufacturer");
        pack::String product      = FIELD("product");
        pack::String serialNumber = FIELD("serialNumber");
        pack::String name         = FIELD("name");
        pack::String physicalName = FIELD("physicalName");
        pack::String type         = FIELD("type");
        pack::String location     = FIELD("location");
        pack::String contact      = FIELD("contact");
        pack::String macAddress   = FIELD("macAddress");

        using pack::Node::Node;
        META(Identification, uuid, vendor, manufacturer, product, serialNumber, name, physicalName, type, location, contact, macAddress);
    };

    struct Services : public pack::Node
    {
        struct Member : public pack::Node
        {
            pack::String path       = FIELD("path");
            pack::String id         = FIELD("id");
            pack::String type       = FIELD("type");
            pack::String name       = FIELD("name");
            pack::String deviceType = FIELD("device-type");

            using pack::Node::Node;
            META(Member, path, id, type, name, deviceType);
        };

        pack::Int32              count   = FIELD("members-count");
        pack::ObjectList<Member> members = FIELD("members");

        using pack::Node::Node;
        META(Services, count, members);
    };

    pack::String   name           = FIELD("name");
    Identification identification = FIELD("identification");
    Services       services       = FIELD("services");

    using pack::Node::Node;
    META(Card, name, identification, services);
};

// =========================================================================================================================================

class NM2Scanner
{
public:
    NM2Scanner(const std::string& address)
        : m_address(address)
    {
    }

    fty::Expected<fty_proto_t*> resolve()
    {
        neon::Neon ne(m_address);
        if (auto ret = ne.get("etn/v1/comm")) {
            Card card;
            if (auto resp = pack::json::deserialize(*ret, card)) {
                std::optional<Card::Services::Member> power;

                for (const auto& mem : card.services.members) {
                    if (mem.path == "/etn/v1/comm/services/powerdistributions1") {
                        power = mem;
                        break;
                    }
                }

                if (power != std::nullopt) {
                    logDebug("Card is \n{}\n", card.dump());
                    return createAssetProto(card, *power);
                } else {
                    return fty::unexpected("this is not a power device");
                }
            } else {
                return fty::unexpected("Error deserialize card {}", resp.error());
            }
        }
        return nullptr;
    }

private:
    fty_proto_t* createAssetProto(const Card& card, const Card::Services::Member& power)
    {
        fty_proto_t* msg = fty_proto_new(FTY_PROTO_ASSET);


        fty_proto_aux_insert(msg, "name", card.name.value().c_str());
        fty_proto_aux_insert(msg, "type", "device");
        fty_proto_aux_insert(msg, "subtype", power.deviceType.value().c_str());
        fty_proto_aux_insert(msg, "status", "nonactive");
        // fty_proto_aux_insert(msg, "subtype", card.identification.type.value().c_str());

        fty_proto_ext_insert(msg, "name", "%s", card.identification.physicalName.value().c_str());
        fty_proto_ext_insert(msg, "ip.1", "%s", m_address.c_str());
        fty_proto_ext_insert(msg, "manufacturer", "%s", card.identification.manufacturer.value().c_str());
        fty_proto_ext_insert(msg, "model", "%s", power.name.value().c_str());
        fty_proto_ext_insert(msg, "device.contact", "%s", card.identification.contact.value().c_str());
        fty_proto_ext_insert(msg, "device.location", "%s", card.identification.location.value().c_str());
        fty_proto_ext_insert(msg, "serial_no", "%s", card.identification.serialNumber.value().c_str());
        fty_proto_ext_insert(msg, "endpoint.1.protocol", "nut_powercom");
        fty_proto_ext_insert(msg, "endpoint.1.nut_powercom.secw_credential_id", "");

        return msg;
    }

private:
    std::string m_address;
};

// =========================================================================================================================================

struct AutoRemove
{
    template <typename FuncT>
    AutoRemove(FuncT&& func)
        : m_func(func)
    {
    }
    ~AutoRemove()
    {
        m_func();
    }
    std::function<void()> m_func;
};

// =========================================================================================================================================

static bool askActorTerm(zsock_t* pipe)
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

// =========================================================================================================================================

void scan_nm2_actor(zsock_t* pipe, void* args)
{
    zsock_signal(pipe, 0);
    AutoRemove cleanup([&]() {
        if (args) {
            zlist_t* argv = static_cast<zlist_t*>(args);
            zlist_destroy(&argv);
        }
        zmsg_t* reply = zmsg_new();
        zmsg_pushstr(reply, REQ_DONE);
        zmsg_send(&reply, pipe);
    });

    if (!args) {
        logError("{} : actor created without parameters", __FUNCTION__);
        return;
    }

    zlist_t* argv = static_cast<zlist_t*>(args);
    if (!argv || zlist_size(argv) != 2) {
        log_error("{} : actor created without config or devices list", __FUNCTION__);
        return;
    }

    CIDRList*             listAddr = static_cast<CIDRList*>(zlist_first(argv));
    discovered_devices_t* devices  = static_cast<discovered_devices_t*>(zlist_next(argv));

    if (!listAddr || !devices) {
        logError("{} : actor created without config or devices list", __FUNCTION__);
        return;
    }

    CIDRAddress addr;
    while (listAddr->next(addr)) {
        std::string ip = addr.toString();

        const auto& list  = devices->device_list;
        auto        found = std::find_if(list.begin(), list.end(), [&](const std::pair<std::string, std::string>& el) {
            return ip == el.second;
        });

        if (found != list.end()) {
            logDebug("NM2 address {} already exists", ip);
            continue;
        }

        NM2Scanner scanner(ip);
        if (auto ret = scanner.resolve()) {
            if (*ret) {
                logDebug("NM2 resolved address {}", ip);

                zmsg_t* reply = fty_proto_encode(&*ret);
                zmsg_pushstr(reply, "FOUND");
                zmsg_send(&reply, pipe);
            }
        } else {
            logError("Error while resolve: {}", ret.error());
        }

        if (zsys_interrupted || askActorTerm(pipe)) {
            break;
        }
    }

    delete listAddr;
    logDebug("NM2: scan actor exited");
}
