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

#include "ApplicationUpdater.h"

#include <stdlib.h>

#include <qcc/Debug.h>
#define QCC_MODULE "SEGMGR_UPDATER"

using namespace ajn;
using namespace securitymgr;

QStatus ApplicationUpdater::ResetApplication(const OnlineApplication& app,
                                             const SecurityInfo& secInfo)
{
    QCC_UNUSED(secInfo);

    QStatus status = ER_FAIL;

    QCC_DbgPrintf(("Resetting application"));
    status = applicationManager->Reset(app);
    if (ER_OK != status) {
        SyncError* error = new SyncError(app, status, SYNC_ER_RESET);
        securityAgentImpl->NotifyApplicationListeners(error);
    }
    QCC_DbgPrintf(("Resetting application returned %s", QCC_StatusText(status)));

    return status;
}

QStatus ApplicationUpdater::UpdatePolicy(const OnlineApplication& app,
                                         const SecurityInfo& secInfo)
{
    QCC_UNUSED(secInfo);

    QCC_DbgPrintf(("Updating policy"));
    QStatus status = ER_FAIL;

    PermissionPolicy remotePolicy;
    status = applicationManager->GetPolicy(app, remotePolicy);
    if (ER_OK != status) {
        // errors logged in ProxyObjectManager
        return status;
    }
    uint32_t remoteVersion = remotePolicy.GetVersion();
    QCC_DbgPrintf(("Remote policy version %i", remoteVersion));

    PermissionPolicy localPolicy;
    status = storage->GetPolicy(app, localPolicy);
    if (ER_OK != status && ER_END_OF_DATA != status) {
        QCC_LogError(status, ("Failed to retrieve local policy"));
        SyncError* error = new SyncError(app, status, SYNC_ER_STORAGE);
        securityAgentImpl->NotifyApplicationListeners(error);
        return status;
    }
    uint32_t localVersion = localPolicy.GetVersion();
    QCC_DbgPrintf(("Local policy version %i", localVersion));

    if (localVersion == remoteVersion) {
        QCC_DbgPrintf(("Policy already up to date"));
        return ER_OK;
    } else {
        status = applicationManager->UpdatePolicy(app, localPolicy);
        QCC_DbgPrintf(("Installing new policy returned %i", status));
        SyncError* error = new SyncError(app, status, localPolicy);
        securityAgentImpl->NotifyApplicationListeners(error);
        return status;
    }
}

QStatus ApplicationUpdater::UpdateMembershipCertificates(const OnlineApplication& app,
                                                         const SecurityInfo& secInfo,
                                                         const Application& mgdAppInfo)
{
    QCC_DbgPrintf(("Updating membership certificates"));

    QStatus status = ER_OK;

    qcc::ECCPublicKey eccAppPubKey(secInfo.publicKey);

    qcc::MembershipCertificate queryCert;
    queryCert.SetSubjectPublicKey(&eccAppPubKey);
    vector<qcc::MembershipCertificate> localCerts;

    if (ER_OK != (status = storage->GetMembershipCertificates(app, localCerts))) {
        QCC_DbgPrintf(("Failed to get membership certificates"));
        SyncError* error = new SyncError(app, status, SYNC_ER_STORAGE);
        securityAgentImpl->NotifyApplicationListeners(error);
    }

    QCC_DbgPrintf(("Found %i local membership certificates", localCerts.size()));
    std::vector<qcc::MembershipCertificate>::iterator it;
    for (it = localCerts.begin(); it != localCerts.end(); ++it) {
        QCC_DbgPrintf(("Local membership certificate %s", it->GetSerial().c_str()));

        it->SetSubjectCN((const uint8_t*)mgdAppInfo.aki.data(), mgdAppInfo.aki.size());

        status = applicationManager->InstallMembership(app, &(*it), 1);
        QCC_DbgPrintf(("Install membership certificate %s returned %i", it->GetSerial().c_str(), status));

        if (ER_DUPLICATE_CERTIFICATE == status) {
            status = ER_OK;
        }

        if (ER_OK != status) {
            SyncError* error = new SyncError(app, status, *it);
            securityAgentImpl->NotifyApplicationListeners(error);
            break;
        }
    }

    return status;
}

QStatus ApplicationUpdater::UpdateIdentityCert(const OnlineApplication& app)
{
    QCC_DbgPrintf(("Updating identity certificate"));

    QStatus status = ER_FAIL;

    qcc::IdentityCertificate remoteIdCert;
    qcc::IdentityCertificate persistedIdCert;
    SyncError* error = NULL;

    do {
        Manifest mf;

        if (ER_OK != (status = storage->GetIdentityCertificateAndManifest(app, persistedIdCert, mf))) {
            error = new SyncError(app, status, SYNC_ER_STORAGE);
            QCC_LogError(status, ("Could not get identity certificate from storage"));
            break;
        }

        uint32_t localSerialNum = strtoul(persistedIdCert.GetSerial().c_str(), NULL, 0);
        QCC_DbgPrintf(("Local identity certificate serial number is %u '%s' (%lu)", localSerialNum,
                       persistedIdCert.GetSerial().c_str(), persistedIdCert.GetSerial().size()));

        if (ER_OK != (status = applicationManager->GetIdentity(app, remoteIdCert))) {
            error = new SyncError(app, status, persistedIdCert);
            QCC_LogError(status, ("Could not fetch identity certificate"));
            break;
        }

        uint32_t remoteSerialNum = strtoul(remoteIdCert.GetSerial().c_str(), NULL, 0);
        QCC_DbgPrintf(("Remote identity certificate serial number is %u", remoteSerialNum));

        if (localSerialNum == remoteSerialNum) {
            QCC_DbgPrintf(("Identity certificate is already up to date"));
            break;
        }

        status = applicationManager->UpdateIdentity(app, &persistedIdCert, 1, mf);
        if (ER_OK != status) {
            error = new SyncError(app, status, persistedIdCert);
        }
    } while (0);

    if (NULL != error) {
        securityAgentImpl->NotifyApplicationListeners(error);
    }

    return status;
}

QStatus ApplicationUpdater::UpdateApplication(const OnlineApplication& app,
                                              const SecurityInfo& secInfo)
{
    QStatus status = ER_FAIL;

    QCC_DbgPrintf(("Updating %s", secInfo.busName.c_str()));
    busAttachment->EnableConcurrentCallbacks();

    Application application;
    application.publicKey = secInfo.publicKey;
    status = storage->GetManagedApplication(application);
    QCC_DbgPrintf(("GetManagedApplication returned %s", QCC_StatusText(status)));

    if (ER_END_OF_DATA == status) {
        status = ResetApplication(app, secInfo);
    } else {
        do {
            if (ER_OK != (status = UpdatePolicy(app, secInfo))) {
                break;
            }
            if (ER_OK != (status = UpdateMembershipCertificates(app, secInfo, application))) {
                break;
            }
            status = UpdateIdentityCert(app);
        } while (0);
    }

    // This assumes no database changes have been made while updating an
    // application.

    if (ER_OK == status) {
        QCC_DbgPrintf(("Updates completed %s returned %s ", secInfo.busName.c_str(), QCC_StatusText(status)));
        status = storage->UpdatesCompleted(application);
        //TODO restart if still updates are pending.

        //OnlineApplication liveAppInfo;
        //securityAgentImpl->GetApplication(liveAppInfo);
        //status = securityAgentImpl->SetUpdatesPending(liveAppInfo, false);
    }

    QCC_DbgPrintf(("Updating %s returned %s ", secInfo.busName.c_str(), QCC_StatusText(status)));

    return status;
}

QStatus ApplicationUpdater::UpdateApplication(const SecurityInfo& secInfo)
{
    OnlineApplication app(secInfo.applicationState, secInfo.busName);
    app.publicKey = secInfo.publicKey;
    return UpdateApplication(app, secInfo);
}

QStatus ApplicationUpdater::UpdateApplication(const OnlineApplication& app)
{
    OnlineApplication tmp = app;
    QStatus status = securityAgentImpl->GetApplication(tmp);
    if (status != ER_OK) {
        return ER_OK;
    }
    status = securityAgentImpl->SetUpdatesPending(tmp, true);
    SecurityInfo secInfo;
    secInfo.busName = app.busName;
    status = securityAgentImpl->GetApplicationSecInfo(secInfo);
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to fetch security info !"));
        return status;
    }
    return UpdateApplication(app, secInfo);
}

void ApplicationUpdater::OnPendingChanges(std::vector<Application>& apps)
{
    QCC_LogError(ER_OK, ("Changes needed from DB"));
    std::vector<Application>::iterator it = apps.begin();
    for (; it != apps.end(); it++) {
        OnlineApplication app;
        app.publicKey = it->publicKey;
        QStatus status = securityAgentImpl->GetApplication(app);
        if (status == ER_OK && app.busName.size() != 0) {
            SecurityInfo secInfo;
            secInfo.busName = app.busName;
            if (ER_OK == monitor->GetApplication(secInfo)) {
                QCC_LogError(ER_OK, ("Added to queue ..."));
                queue.AddTask(new SecurityEvent(&secInfo, NULL));
            }
        }
    }
}

void ApplicationUpdater::OnSecurityStateChange(const SecurityInfo* oldSecInfo,
                                               const SecurityInfo* newSecInfo)
{
    queue.AddTask(new SecurityEvent(newSecInfo, oldSecInfo));
}

void ApplicationUpdater::HandleTask(SecurityEvent* event)
{
    const SecurityInfo* oldSecInfo = event->oldInfo;
    const SecurityInfo* newSecInfo = event->newInfo;

    if ((NULL == oldSecInfo) && (NULL != newSecInfo)) {
        // new security info
        QCC_DbgPrintf(("Detected new busName %s", newSecInfo->busName.c_str()));
        UpdateApplication(*newSecInfo);
    }
}

#undef QCC_MODULE
