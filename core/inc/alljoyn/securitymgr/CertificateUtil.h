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

#ifndef ALLJOYN_SECMGR_CERTIFICATEUTIL_H_
#define ALLJOYN_SECMGR_CERTIFICATEUTIL_H_

#include <string>

#include <qcc/CertificateECC.h>

#include <alljoyn/Status.h>
#include <alljoyn/securitymgr/Application.h>
#include <alljoyn/securitymgr/GroupInfo.h>
#include <alljoyn/securitymgr/IdentityInfo.h>

using namespace std;
using namespace qcc;

namespace ajn {
namespace securitymgr {
class CertificateUtil {
  public:
    static QStatus ToMembershipCertificate(const Application& app,
                                           const GroupInfo& groupInfo,
                                           const uint64_t validityPeriod,
                                           MembershipCertificate& memberShip);

    static QStatus ToIdentityCertificate(const Application& app,
                                         const IdentityInfo& groupInfo,
                                         const uint64_t validityPeriod,
                                         IdentityCertificate& memberShip);

    static void SetValityPeriod(const uint64_t validityPeriod,
                                CertificateX509& certificate);

  private:

    CertificateUtil() { }

    ~CertificateUtil() { }
};
}
}

#endif /* ALLJOYN_SECMGR_CERTIFICATEUTIL_H_ */
