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

#ifndef ALLJOYN_SECMGR_SECURITYAGENTIMPL_H_
#define ALLJOYN_SECMGR_SECURITYAGENTIMPL_H_

#include <alljoyn/AboutListener.h>
#include <alljoyn/Status.h>
#include <alljoyn/PermissionPolicy.h>
#include <qcc/CryptoECC.h>
#include <qcc/String.h>
#include <qcc/Mutex.h>
#include <qcc/GUID.h>

#include <alljoyn/securitymgr/ApplicationListener.h>
#include <alljoyn/securitymgr/Application.h>
#include <alljoyn/securitymgr/GroupInfo.h>
#include <alljoyn/securitymgr/IdentityInfo.h>
#include <alljoyn/securitymgr/SecurityAgentIdentityInfo.h>
#include <alljoyn/securitymgr/SecurityAgent.h>
#include <alljoyn/securitymgr/CaStorage.h>

#include "ApplicationMonitor.h"
#include "ProxyObjectManager.h"
#include "RemoteApplicationManager.h"
#include "ApplicationUpdater.h"
#include "TaskQueue.h"

#include <memory>

using namespace qcc;

namespace ajn {
namespace securitymgr {
class Identity;
class SecurityInfoListener;
class ApplicationUpdater;
struct SecurityInfo;

class AppListenerEvent {
  public:
    AppListenerEvent(const OnlineApplication* oldInfo,
                     const OnlineApplication* newInfo,
                     const SyncError* error) :
        oldApp(oldInfo), newApp(newInfo), syncError(error)
    {
    }

    ~AppListenerEvent()
    {
        delete oldApp;
        delete newApp;
        delete syncError;
    }

    const OnlineApplication* oldApp;
    const OnlineApplication* newApp;
    const SyncError* syncError;
};

/**
 * \class SecurityAgentImpl
 *
 * \brief the class provides for the SecurityManager implementation hiding
 */
class SecurityAgentImpl :
    private SecurityInfoListener,
    private StorageListener {
  public:

    SecurityAgentImpl(const SecurityAgentIdentityInfo& securityAgentIdendtityInfo,
                      const std::shared_ptr<CaStorage>& _caStorage,
                      BusAttachment* ba = nullptr);

    ~SecurityAgentImpl();

    QStatus Init();

    void SetManifestListener(ManifestListener* listener);

    QStatus Claim(const OnlineApplication& app,
                  const IdentityInfo& identityInfo);

    QStatus GetApplications(vector<OnlineApplication>& apps,
                            const PermissionConfigurator::ApplicationState appsClaimState =
                                PermissionConfigurator::CLAIMABLE) const;

    QStatus GetApplication(OnlineApplication& _application) const;

    void RegisterApplicationListener(ApplicationListener* al);

    void UnregisterApplicationListener(ApplicationListener* al);

    void SyncWithApplications(const vector<OnlineApplication>* apps = nullptr);

    QStatus SetUpdatesPending(const OnlineApplication& app,
                              bool updatesPending);

    QStatus GetApplicationSecInfo(SecurityInfo& secInfo) const;

    const KeyInfoNISTP256& GetPublicKeyInfo() const;

    void NotifyApplicationListeners(const SyncError* syncError);

    void HandleTask(AppListenerEvent* event);

  private:

    typedef std::map<ECCPublicKey, OnlineApplication> OnlineApplicationMap; /* key = peerID of app, value = info */

    QStatus ClaimSelf();

    virtual void OnSecurityStateChange(const SecurityInfo* oldSecInfo,
                                       const SecurityInfo* newSecInfo);

    virtual void OnPendingChanges(std::vector<Application>& apps);

    virtual void OnPendingChangesCompleted(std::vector<Application>& apps);

    OnlineApplicationMap::iterator SafeAppExist(const ECCPublicKey key,
                                                bool& exist);

    void AddSecurityInfo(OnlineApplication& app,
                         const SecurityInfo& si);

    void RemoveSecurityInfo(OnlineApplication& app,
                            const SecurityInfo& si);

    void NotifyApplicationListeners(const OnlineApplication* oldApp,
                                    const OnlineApplication* newApp);

    // to prevent compilation warning on MSCV
    SecurityAgentImpl& operator=(const SecurityAgentImpl& other);

  private:

    KeyInfoNISTP256 publicKeyInfo;
    SecurityAgentIdentityInfo agentIdentity;
    OnlineApplicationMap applications;
    vector<ApplicationListener*> listeners;
    shared_ptr<RemoteApplicationManager> remoteApplicationManager;
    shared_ptr<ApplicationUpdater> applicationUpdater;
    shared_ptr<ApplicationMonitor> appMonitor;
    BusAttachment* busAttachment;
    const std::shared_ptr<CaStorage>& caStorage;
    mutable qcc::Mutex appsMutex;
    mutable qcc::Mutex applicationListenersMutex;
    TaskQueue<AppListenerEvent*, SecurityAgentImpl> queue;
    ManifestListener* mfListener;
};
}
}

#endif /* ALLJOYN_SECMGR_SECURITYAGENTIMPL_H_ */
