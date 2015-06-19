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
#include <qcc/Debug.h>
#include <alljoyn/AllJoynStd.h>

#include "ProxyObjectManager.h"

#define QCC_MODULE "SEGMGR_AGENT"

#define MSG_REPLY_TIMEOUT 5000

namespace ajn {
namespace securitymgr {
ajn::AuthListener* ProxyObjectManager::listener = NULL;

ProxyObjectManager::ProxyObjectManager(ajn::BusAttachment* ba) :
    bus(ba)
{
}

ProxyObjectManager::~ProxyObjectManager()
{
}

QStatus ProxyObjectManager::GetProxyObject(const OnlineApplication app,
                                           SessionType sessionType,
                                           ajn::SecurityApplicationProxy** remoteObject)
{
    QStatus status = ER_FAIL;
    if (app.busName == "") {
        status = ER_FAIL;
        QCC_DbgRemoteError(("Application is offline"));
        return status;
    }

    lock.Lock(__FILE__, __LINE__);

    if (sessionType == ECDHE_NULL) {
        bus->EnablePeerSecurity(KEYX_ECDHE_NULL, listener, AJNKEY_STORE, true);
    } else if (sessionType == ECDHE_DSA) {
        bus->EnablePeerSecurity(ECDHE_KEYX, listener, AJNKEY_STORE, true);
    }

    const char* busName = app.busName.c_str();

    ajn::SessionId sessionId;
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false,
                     SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    status = bus->JoinSession(busName, ALLJOYN_SESSIONPORT_PERMISSION_MGMT,
                              this, sessionId, opts);
    if (status != ER_OK) {
        QCC_DbgRemoteError(("Could not join session with %s", busName));
        lock.Unlock(__FILE__, __LINE__);
        return status;
    }

    ajn::SecurityApplicationProxy* remoteObj = new ajn::SecurityApplicationProxy(*bus, busName, sessionId);
    if (remoteObj == NULL) {
        status = ER_FAIL;
        QCC_LogError(status, ("Could not create ProxyBusObject for %s", busName));
        lock.Unlock(__FILE__, __LINE__);
        return status;
    }

    *remoteObject = remoteObj;
    return status;
}

QStatus ProxyObjectManager::ReleaseProxyObject(ajn::SecurityApplicationProxy* remoteObject)
{
    lock.Unlock(__FILE__, __LINE__);

    SessionId sessionId = remoteObject->GetSessionId();
    delete remoteObject;
    return bus->LeaveSession(sessionId);
}

QStatus ProxyObjectManager::Claim(const OnlineApplication& app,
                                  qcc::KeyInfoNISTP256& certificateAuthority,
                                  GroupInfo& adminGroup,
                                  qcc::IdentityCertificate* identityCertChain,
                                  size_t identityCertChainSize,
                                  PermissionPolicy::Rule* manifest,
                                  size_t manifestSize)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_NULL, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    status = remoteObj->Claim(certificateAuthority,
                              adminGroup.guid, adminGroup.authority,
                              identityCertChain, identityCertChainSize,
                              manifest, manifestSize);

    ReleaseProxyObject(remoteObj);

    return status;
}

QStatus ProxyObjectManager::GetIdentity(const OnlineApplication& app,
                                        qcc::IdentityCertificate* cert)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_DSA, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    MsgArg certChainArg;
    status = remoteObj->GetIdentity(certChainArg);
    ReleaseProxyObject(remoteObj);

    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to GetIndentity"));
        return status;
    }

    status = SecurityApplicationProxy::MsgArgToIdentityCertChain(certChainArg, cert, 1);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to MsdArgToIdentityCertChain"));
        return status;
    }

    return status;
}

QStatus ProxyObjectManager::UpdateIdentity(const OnlineApplication& app,
                                           qcc::IdentityCertificate* certChain,
                                           size_t certChainSize,
                                           const Manifest& mf)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_DSA, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    PermissionPolicy::Rule* manifestRules;
    size_t manifestRuleCount;
    status = mf.GetRules(&manifestRules, &manifestRuleCount);
    if (ER_OK == status) {
        status = remoteObj->UpdateIdentity(certChain, certChainSize, manifestRules, manifestRuleCount);
        delete[] manifestRules;
    }

    ReleaseProxyObject(remoteObj);

    return status;
}

QStatus ProxyObjectManager::InstallMembership(const OnlineApplication& app,
                                              const qcc::MembershipCertificate* certChain,
                                              size_t certChainSize)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_DSA, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    status = remoteObj->InstallMembership(certChain, certChainSize);

    ReleaseProxyObject(remoteObj);

    return status;
}

QStatus ProxyObjectManager::UpdatePolicy(const OnlineApplication& app,
                                         const PermissionPolicy& policy)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_DSA, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    status = remoteObj->UpdatePolicy(policy);

    ReleaseProxyObject(remoteObj);

    return status;
}

QStatus ProxyObjectManager::GetManifestTemplate(const OnlineApplication& app,
                                                Manifest& manifest)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_NULL, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    MsgArg rulesMsgArg;
    status = remoteObj->GetManifestTemplate(rulesMsgArg);

    ReleaseProxyObject(remoteObj);

    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to GetManifestTemplate"));
        return status;
    }

    PermissionPolicy::Rule* manifestRules;
    size_t manifestRulesCount;
    status = PermissionPolicy::ParseRules(rulesMsgArg, &manifestRules, &manifestRulesCount);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to ParseRules"));
        goto Exit;
    }

    status = manifest.SetFromRules(manifestRules, manifestRulesCount);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to SetFromRules"));
        goto Exit;
    }

Exit:
    delete[] manifestRules;
    return status;
}

QStatus ProxyObjectManager::Reset(const OnlineApplication& app)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_DSA, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    status = remoteObj->Reset();

    ReleaseProxyObject(remoteObj);

    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to Reset"));
    }

    return status;
}

QStatus ProxyObjectManager::GetPolicy(const OnlineApplication& app,
                                      PermissionPolicy& policy)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_DSA, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    status = remoteObj->GetPolicy(policy);

    ReleaseProxyObject(remoteObj);

    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to GetPolicy"));
    }

    return status;
}

QStatus ProxyObjectManager::RemoveMembership(const OnlineApplication& app,
                                             const qcc::String& serial,
                                             const qcc::KeyInfoNISTP256& issuerKeyInfo)
{
    QStatus status;

    SecurityApplicationProxy* remoteObj;
    status = GetProxyObject(app, ECDHE_DSA, &remoteObj);
    if (ER_OK != status) {
        // errors logged in GetProxyObject
        return status;
    }

    status = remoteObj->RemoveMembership(serial, issuerKeyInfo);

    ReleaseProxyObject(remoteObj);

    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to RemoveMembership"));
    }

    return status;
}

void ProxyObjectManager::SessionLost(ajn::SessionId sessionId,
                                     SessionLostReason reason)
{
    QCC_UNUSED(reason);

    QCC_DbgPrintf(("Lost session %lu", (unsigned long)sessionId));
}
}
}
#undef QCC_MODULE
