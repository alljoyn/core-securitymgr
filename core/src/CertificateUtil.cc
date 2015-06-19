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

#include <alljoyn/securitymgr/CertificateUtil.h>

#include <qcc/Debug.h>
#include <qcc/time.h>

#define QCC_MODULE "SEGMGR_AGENT"

using namespace ajn;
using namespace std;

namespace ajn {
namespace securitymgr {
void CertificateUtil::SetValityPeriod(const uint64_t validityPeriod, CertificateX509& cert)
{
    qcc::CertificateX509::ValidPeriod period;
    uint64_t currentTime = GetEpochTimestamp() / 1000;
    period.validFrom = currentTime;
    period.validTo = period.validFrom +  validityPeriod;
    period.validFrom = period.validFrom - 3600;
    cert.SetValidity(&period);
}

QStatus CertificateUtil::ToIdentityCertificate(const Application& app,
                                               const IdentityInfo& idInfo,
                                               const uint64_t validityPeriod,
                                               IdentityCertificate& cert)
{
    cert.SetAlias(idInfo.guid.ToString());
    cert.SetSubjectPublicKey(&app.publicKey);
    cert.SetSubjectOU((const uint8_t*)idInfo.name.data(), idInfo.name.size());
    cert.SetCA(false);
    cert.SetSubjectCN((const uint8_t*)app.aki.c_str(), app.aki.size());

    SetValityPeriod(validityPeriod, cert);

    return ER_OK;
}

QStatus CertificateUtil::ToMembershipCertificate(const Application& app,
                                                 const GroupInfo& groupInfo,
                                                 const uint64_t validityPeriod,
                                                 MembershipCertificate& cert)
{
    cert.SetGuild(groupInfo.guid);
    cert.SetSubjectPublicKey(&app.publicKey);
    cert.SetCA(false);
    cert.SetSubjectCN((const uint8_t*)app.aki.c_str(), app.aki.size());

    SetValityPeriod(validityPeriod, cert);

    return ER_OK;
}
}
}
#undef QCC_MODULE
