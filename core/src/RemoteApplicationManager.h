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

#ifndef ALLJOYN_SECMGR_REMOTEAPPLICATIONMANAGER_H_
#define ALLJOYN_SECMGR_REMOTEAPPLICATIONMANAGER_H_

#include <alljoyn/securitymgr/GroupInfo.h>
#include <alljoyn/securitymgr/Application.h>
#include <alljoyn/securitymgr/Manifest.h>

#include <qcc/CertificateECC.h>
#include <qcc/String.h>
#include <alljoyn/PermissionPolicy.h>
#include <alljoyn/Status.h>

#include "ProxyObjectManager.h"

namespace ajn {
namespace securitymgr {
class RemoteApplicationManager {
  private:
    ProxyObjectManager* proxyObjectManager;          // Owned
    ajn::BusAttachment* ba;                          // Not owned

  public:

    RemoteApplicationManager(ajn::BusAttachment* _ba) :
        proxyObjectManager(new ProxyObjectManager(_ba)), ba(_ba)
    {
    }

    ~RemoteApplicationManager()
    {
        delete proxyObjectManager;
    }

    bool Initialized(void)
    {
        return (NULL != proxyObjectManager);
    }

    QStatus Claim(const OnlineApplication& app,
                  qcc::KeyInfoNISTP256& certificateAuthority,
                  GroupInfo& adminGroup,
                  qcc::IdentityCertificate* identityCertChain,
                  size_t identityCertChainSize,
                  Manifest& manifest);

    QStatus InstallMembership(const OnlineApplication& app,
                              qcc::MembershipCertificate* certChain,
                              size_t certChainSize);

    QStatus UpdateIdentity(const OnlineApplication& app,
                           qcc::IdentityCertificate* certChain,
                           size_t certChainSize,
                           const Manifest& mf);

    QStatus UpdatePolicy(const OnlineApplication& app,
                         const PermissionPolicy& policy);

    QStatus Reset(const OnlineApplication& app);

    QStatus GetIdentity(const OnlineApplication& app,
                        qcc::IdentityCertificate& idCert);

    QStatus GetPolicy(const OnlineApplication& app,
                      PermissionPolicy& policy);

    QStatus GetManifestTemplate(const OnlineApplication& app,
                                Manifest& manifest);
};
}
}
#endif /* ALLJOYN_SECMGR_REMOTEAPPLICATIONMANAGER_H_ */
