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

#pragma once
#include <fty/expected.h>
#include <memory>

// =====================================================================================================================

struct ne_session_s;
typedef struct ne_session_s ne_session;

// =====================================================================================================================

namespace neon {

class Neon
{
public:
    Neon(const std::string& address, uint16_t port = 80, uint16_t timeout = 1);
    ~Neon();

    fty::Expected<std::string> get(const std::string& path) const;

private:
    static void closeSession(ne_session*);

private:
    using NeonSession = std::unique_ptr<ne_session, decltype(&closeSession)>;
    NeonSession m_session;
};

// =====================================================================================================================

} // namespace neon
