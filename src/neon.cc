/*  ====================================================================================================================
    Copyright (C) 2020 Eaton
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
    ====================================================================================================================
*/

#include "neon.h"
#include <fty/string-utils.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>
#include <neon/ne_xml.h>
#include <pack/visitor.h>
#include <iostream>

namespace neon {

Neon::Neon(const std::string& address, uint16_t port, uint16_t timeout)
    : m_session(ne_session_create("http", address.c_str(), port), &closeSession)
{
    ne_set_session_flag(m_session.get(), NE_SESSFLAG_PERSIST, 0);
    ne_set_connect_timeout(m_session.get(), timeout);
    ne_set_read_timeout(m_session.get(), timeout);
}

Neon::~Neon()
{
}

fty::Expected<std::string> Neon::get(const std::string& path) const
{
    std::string rpath = "/" + path;
    std::unique_ptr<ne_request, decltype(&ne_request_destroy)> request(
        ne_request_create(m_session.get(), "GET", rpath.c_str()), &ne_request_destroy);

    std::string body;

    do {
        int stat = ne_begin_request(request.get());
        auto status = ne_get_status(request.get());
        if (stat != NE_OK) {
            if (!status->code) {
                return fty::unexpected(ne_get_error(m_session.get()));
            }
            return fty::unexpected("{} {}", status->code, status->reason_phrase);
        }

        if (status->code != 200) {
            return fty::unexpected("unsupported (status is not ok)");
        }

        body.clear();
        std::array<char, 1024> buffer;

        ssize_t bytes = 0;
        while ((bytes = ne_read_response_block(request.get(), buffer.data(), buffer.size())) > 0) {
            body += std::string(buffer.data(), size_t(bytes));
        }
    } while(ne_end_request(request.get()) == NE_RETRY);

    return fty::Expected<std::string>(body);
}

void Neon::closeSession(ne_session* sess)
{
    ne_session_destroy(sess);
}

// =====================================================================================================================

} // namespace neon
