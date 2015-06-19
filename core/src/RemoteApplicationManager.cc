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

#include "RemoteApplicationManager.h"

#include <qcc/Debug.h>
#define QCC_MODULE "SEGMGR_AGENT"

namespace ajn {
namespace securitymgr {
QStatus RemoteApplicationManager::Claim(const OnlineApplication& app,
                                        qcc::KeyInfoNISTP256& certificateAuthority,
                                        GroupInfo& adminGroup,
                                        qcc::IdentityCertificate* identityCertChain,
                                        size_t identityCertChainSize,
                                        Manifest& manifest)
{
    QStatus status;

    PermissionPolicy::Rule* manifestRules;
    size_t manifestRulesCount;
    status = manifest.GetRules(&manifestRules, &manifestRulesCount);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to get manifest rules"));
    }

    status = proxyObjectManager->Claim(app, certificateAuthority, adminGroup,
                                       identityCertChain, identityCertChainSize,
                                       manifestRules, manifestRulesCount);

    return status;
}

QStatus RemoteApplicationManager::InstallMembership(const OnlineApplication& app,
                                                    qcc::MembershipCertificate* certChain,
                                                    size_t certChainSize)
{
    return proxyObjectManager->InstallMembership(app, certChain, certChainSize);
}

QStatus RemoteApplicationManager::UpdateIdentity(const OnlineApplication& app,
                                                 qcc::IdentityCertificate* certChain,
                                                 size_t certChainSize,
                                                 const Manifest& mf)
{
    return proxyObjectManager->UpdateIdentity(app, certChain, certChainSize, mf);
}

QStatus RemoteApplicationManager::UpdatePolicy(const OnlineApplication& app,
                                               const PermissionPolicy& policy)
{
    return proxyObjectManager->UpdatePolicy(app, policy);;
}

QStatus RemoteApplicationManager::Reset(const OnlineApplication& app)
{
    return proxyObjectManager->Reset(app);
}

QStatus RemoteApplicationManager::GetIdentity(const OnlineApplication& app,
                                              qcc::IdentityCertificate& idCert)
{
    return proxyObjectManager->GetIdentity(app, &idCert);;
}

QStatus RemoteApplicationManager::GetPolicy(const OnlineApplication& app,
                                            PermissionPolicy& policy)
{
    return proxyObjectManager->GetPolicy(app, policy);
}

QStatus RemoteApplicationManager::GetManifestTemplate(const OnlineApplication& app,
                                                      Manifest& manifest)
{
    return proxyObjectManager->GetManifestTemplate(app, manifest);
}
}
}
#undef QCC_MODULE
