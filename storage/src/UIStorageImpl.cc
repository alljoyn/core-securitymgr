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

#include "UIStorageImpl.h"

#define QCC_MODULE "SEGMGR_STORAGE"

using namespace qcc;
namespace ajn {
namespace securitymgr {
QStatus UIStorageImpl::RemoveApplication(Application& app)
{
    app.updatesPending = true;
    QStatus status = storage->RemoveApplication(app);
    if (status == ER_OK) {
        NotifyListeners(app);
    }
    return status;
}

QStatus UIStorageImpl::GetManagedApplications(std::vector<Application>& apps) const
{
    return storage->GetManagedApplications(apps);
}

QStatus UIStorageImpl::GetManagedApplication(Application& app) const
{
    return storage->GetManagedApplication(app);
}

QStatus UIStorageImpl::StoreGroup(GroupInfo& groupInfo)
{
    if (groupInfo.authority.empty()) {
        ca->GetCaPublicKeyInfo(groupInfo.authority);
    }
    return storage->StoreGroup(groupInfo);
}

QStatus UIStorageImpl::RemoveGroup(const GroupInfo& groupInfo)
{
    if (groupInfo.authority.empty()) {
        GroupInfo tmpGroup;
        tmpGroup.guid = groupInfo.guid;
        ca->GetCaPublicKeyInfo(tmpGroup.authority);
        return storage->RemoveGroup(tmpGroup);
    }
    return storage->RemoveGroup(groupInfo);
}

QStatus UIStorageImpl::GetGroup(GroupInfo& groupInfo) const
{
    if (groupInfo.authority.empty()) {
        ca->GetCaPublicKeyInfo(groupInfo.authority);
    }
    return storage->GetGroup(groupInfo);
}

QStatus UIStorageImpl::GetGroups(std::vector<GroupInfo>& groupsInfo) const
{
    return storage->GetGroups(groupsInfo);
}

QStatus UIStorageImpl::StoreIdentity(IdentityInfo& idInfo)
{
    if (idInfo.authority.empty()) {
        ca->GetCaPublicKeyInfo(idInfo.authority);
    }
    return storage->StoreIdentity(idInfo);
}

QStatus UIStorageImpl::RemoveIdentity(const IdentityInfo& idInfo)
{
    if (idInfo.authority.empty()) {
        IdentityInfo tmpInfo;
        ca->GetCaPublicKeyInfo(tmpInfo.authority);
        tmpInfo.guid = idInfo.guid;
        return storage->RemoveIdentity(tmpInfo);
    }
    return storage->RemoveIdentity(idInfo);
}

QStatus UIStorageImpl::GetIdentity(IdentityInfo& idInfo) const
{
    if (idInfo.authority.empty()) {
        ca->GetCaPublicKeyInfo(idInfo.authority);
    }
    return storage->GetIdentity(idInfo);
}

QStatus UIStorageImpl::GetIdentities(std::vector<IdentityInfo>& idInfos) const
{
    return storage->GetIdentities(idInfos);
}

QStatus UIStorageImpl::SetAppMetaData(const Application& app, const ApplicationMetaData& appMetaData)
{
    return storage->SetAppMetaData(app, appMetaData);
}

QStatus UIStorageImpl::GetAppMetaData(const Application& app, ApplicationMetaData& appMetaData) const
{
    return storage->GetAppMetaData(app, appMetaData);
}

void UIStorageImpl::Reset()
{
    storage->Reset();
}

QStatus UIStorageImpl::UpdatesCompleted(Application& app)
{
    QStatus status = storage->GetManagedApplication(app);
    if (status == ER_END_OF_DATA || app.updatesPending == true) {
        app.updatesPending = false;
        if (status == ER_END_OF_DATA) {
            status = ER_OK;
        } else {
            status = storage->StoreApplication(app, true);
        }
        NotifyListeners(app, true);
    }
    return status;
}

void UIStorageImpl::RegisterStorageListener(StorageListener* listener)
{
    lock.Lock();
    if (listener) {
        listeners.push_back(listener);
    }
    lock.Unlock();
}

void UIStorageImpl::UnRegisterStorageListener(StorageListener* listener)
{
    lock.Lock();
    if (listener) {
        vector<StorageListener*>::iterator it = listeners.begin();
        for (; it != listeners.end(); it++) {
            if (*it == listener) {
                listeners.erase(it);
                break;
            }
        }
    }
    lock.Unlock();
}

void UIStorageImpl::NotifyListeners(const Application& app, bool completed)
{
    vector<Application> apps;
    apps.push_back(app);
    lock.Lock();
    for (size_t i = 0; i < listeners.size(); ++i) {
        if (completed) {
            listeners[i]->OnPendingChangesCompleted(apps);
        } else {
            listeners[i]->OnPendingChanges(apps);
        }
    }
    lock.Unlock();
}

QStatus UIStorageImpl::GetStoredGroupAndAppInfo(Application& app, GroupInfo& groupInfo)
{
    QStatus status = storage->GetGroup(groupInfo);
    if (ER_OK != status) {
        return status;
    }
    return storage->GetManagedApplication(app);
}

QStatus UIStorageImpl::InstallMembership(const Application& app, const GroupInfo& groupInfo)
{
    GroupInfo storedGroup(groupInfo);
    Application storedApp(app);
    QStatus status = GetStoredGroupAndAppInfo(storedApp, storedGroup);
    if (ER_OK != status) {
        return status;
    }
    MembershipCertificate certificate;
    status = ca->GenerateMembershipCertificate(storedApp, storedGroup, certificate);
    if (ER_OK != status) {
        return status;
    }
    status = storage->StoreCertificate(certificate);
    if (ER_OK != status) {
        return status;
    }
    MembershipCertificate m;
    m.SetSubjectPublicKey(certificate.GetSubjectPublicKey());
    m.SetGuild(certificate.GetGuild());
    status = storage->GetCertificate(m);
    if (ER_OK != status) {
        return status;
    }

    return ApplicationUpdated(storedApp);
}

QStatus UIStorageImpl::RemoveMembership(const Application& app, const GroupInfo& groupInfo)
{
    GroupInfo storedGroup(groupInfo);
    Application storedApp(app);
    QStatus status = GetStoredGroupAndAppInfo(storedApp, storedGroup);
    if (ER_OK != status) {
        return status;
    }
    MembershipCertificate cert;
    cert.SetGuild(storedGroup.guid);
    cert.SetSubjectPublicKey(&storedApp.publicKey);
    status = storage->GetCertificate(cert);
    if (ER_OK != status) {
        return status;
    }
    status = storage->RemoveCertificate(cert);
    if (ER_OK != status) {
        return status;
    }
    return ApplicationUpdated(storedApp);
}

QStatus UIStorageImpl::UpdatePolicy(Application& app, PermissionPolicy& policy)
{
    QStatus status = GetManagedApplication(app);
    if (ER_OK != status) {
        return status;
    }
    PermissionPolicy local;
    status = storage->GetPolicy(app, local);
    if (ER_OK != status && ER_END_OF_DATA != status) {
        return status;
    }
    policy.SetVersion(local.GetVersion() + 1);
    status = storage->StorePolicy(app, policy);
    if (ER_OK != status) {
        return status;
    }
    storage->GetPolicy(app, local);
    return ApplicationUpdated(app);
}

QStatus UIStorageImpl::GetPolicy(const Application& app, PermissionPolicy& policy)
{
    return storage->GetPolicy(app, policy);
}

QStatus UIStorageImpl::UpdateIdentity(Application& app, const IdentityInfo identityInfo)
{
    QStatus status = storage->GetManagedApplication(app);
    if (ER_OK != status) {
        return status;
    }
    Manifest mf;
    status = storage->GetManifest(app, mf);
    if (ER_OK != status) {
        return status;
    }
    IdentityCertificate cert;
    status = ca->GenerateIdentityCertificate(app, identityInfo, mf, cert);
    if (ER_OK != status) {
        return status;
    }
    status = storage->StoreCertificate(cert, true);
    if (ER_OK != status) {
        return status;
    }
    return ApplicationUpdated(app);
}

QStatus UIStorageImpl::ApplicationUpdated(Application& app)
{
    QStatus status = ER_OK;

    if (!app.updatesPending) {
        app.updatesPending = true;
        status = storage->StoreApplication(app, true);
        NotifyListeners(app);
    }
    return status;
}

QStatus UIStorageImpl::GetManifest(const Application& app, Manifest& manifest) const
{
    return storage->GetManifest(app, manifest);
}
}
}
#undef QCC_MODULE
