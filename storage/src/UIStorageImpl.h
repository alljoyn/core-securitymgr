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

#ifndef ALLJOYN_SECMGR_STORAGE_UISTORAGEIMPL_H_
#define ALLJOYN_SECMGR_STORAGE_UISTORAGEIMPL_H_

#include <alljoyn/securitymgr/sqlstorage/UIStorage.h>
#include <alljoyn/securitymgr/Application.h>
#include <alljoyn/securitymgr/GroupInfo.h>
#include <alljoyn/securitymgr/IdentityInfo.h>
#include <alljoyn/Status.h>
#include <qcc/Mutex.h>

#include "AJNCaStorage.h"
#include "SQLStorage.h"

using namespace qcc;
namespace ajn {
namespace securitymgr {
class UIStorageImpl :
    public UIStorage, public StorageListenerHandler {
  public:
    UIStorageImpl(shared_ptr<AJNCaStorage>& _ca, shared_ptr<SQLStorage>& localStorage) : ca(_ca),
        storage(localStorage)
    {
    }

    QStatus RemoveApplication(Application& app);

    QStatus GetManagedApplications(std::vector<Application>& apps) const;

    QStatus GetManagedApplication(Application& app) const;

    QStatus StoreGroup(GroupInfo& groupInfo);

    QStatus RemoveGroup(const GroupInfo& groupInfo);

    QStatus GetGroup(GroupInfo& groupInfo) const;

    QStatus GetGroups(std::vector<GroupInfo>& groupsInfo) const;

    QStatus StoreIdentity(IdentityInfo& idInfo);

    QStatus RemoveIdentity(const IdentityInfo& idInfo);

    QStatus GetIdentity(IdentityInfo& idInfo) const;

    QStatus GetIdentities(std::vector<IdentityInfo>& idInfos) const;

    QStatus SetAppMetaData(const Application& app,
                           const ApplicationMetaData& appMetaData);

    QStatus GetAppMetaData(const Application& app,
                           ApplicationMetaData& appMetaData) const;

    void Reset();

    void RegisterStorageListener(StorageListener* listener);

    void UnRegisterStorageListener(StorageListener* listener);

    QStatus UpdatesCompleted(Application& app);

    virtual QStatus InstallMembership(const Application& app,
                                      const GroupInfo& groupInfo);

    virtual QStatus RemoveMembership(const Application& app,
                                     const GroupInfo& groupInfo);

    virtual QStatus UpdatePolicy(Application& app,
                                 PermissionPolicy& policy);

    virtual QStatus GetPolicy(const Application& app,
                              PermissionPolicy& policy);

    virtual QStatus UpdateIdentity(Application& app,
                                   const IdentityInfo identityInfo);

    virtual QStatus GetManifest(const Application& app,
                                Manifest& manifest) const;

  private:

    QStatus GetStoredGroupAndAppInfo(Application& app,
                                     GroupInfo& groupInfo);

    QStatus ApplicationUpdated(Application& app);

    void NotifyListeners(const Application& app,
                         bool completed = false);

    qcc::Mutex lock;
    vector<StorageListener*> listeners;
    shared_ptr<AJNCaStorage> ca;
    shared_ptr<SQLStorage> storage;
};
}
}
#endif /* ALLJOYN_SECMGR_STORAGE_UISTORAGEIMPL_H_ */
