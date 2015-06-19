/******************************************************************************
 * Copyright (c) AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#ifndef ALLJOYN_SECMGR_SECURITYAGENTIDENTITYINFO_H_
#define ALLJOYN_SECMGR_SECURITYAGENTIDENTITYINFO_H_

#include <string>

using namespace std;

namespace ajn {
namespace securitymgr {
/*
 * \brief Represents an identity pertaining to a security agent.
 */
struct SecurityAgentIdentityInfo {
    /**
     * \brief The name of this security agent.
     */
    string name;

    /**
     * \brief the version of this security agent.
     */
    string version;

    /**
     * \brief The vendor of this security agent.
     */
    string vendor;

    string ToString() const
    {
        string s("SecurityAgentIdentityInfo:");
        s += "\n  Name: " + name;
        s += "\n  Version: " + version;
        s += "\n  Vendor: " + vendor + "\n";
        return s;
    }
};
}
}

#endif /* ALLJOYN_SECMGR_SECURITYAGENTIDENTITYINFO_H_ */
