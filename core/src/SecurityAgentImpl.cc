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

#include <alljoyn/version.h>
#include <alljoyn/Session.h>
#include <alljoyn/AllJoynStd.h>

#include <qcc/Debug.h>
#include <qcc/CertificateECC.h>
#include <qcc/KeyInfoECC.h>
#include <CredentialAccessor.h> // still in alljoyn_core/src!
#include <PermissionManager.h> // still in alljoyn_core/src!
#include <PermissionMgmtObj.h> // still in alljoyn_core/src!

#include <alljoyn/securitymgr/Util.h>

#include "SecurityAgentImpl.h"
#include "ApplicationUpdater.h"

#define QCC_MODULE "SEGMGR_AGENT"

namespace ajn {
namespace securitymgr {
class ECDHEKeyXListener :
    public AuthListener {
  public:
    ECDHEKeyXListener()
    {
    }

    bool RequestCredentials(const char* authMechanism, const char* authPeer,
                            uint16_t authCount, const char* userId, uint16_t credMask,
                            Credentials& creds)
    {
        QCC_UNUSED(credMask);
        QCC_UNUSED(userId);
        QCC_UNUSED(authCount);
        QCC_UNUSED(authPeer);

        QCC_DbgPrintf(("RequestCredentials %s", authMechanism));
        if (strcmp(authMechanism, KEYX_ECDHE_NULL) == 0) {
            creds.SetExpiration(100);             /* set the master secret expiry time to 100 seconds */
            return true;
        }
        return false;
    }

    bool VerifyCredentials(const char* authMechanism, const char* authPeer,
                           const Credentials& creds)
    {
        QCC_UNUSED(creds);
        QCC_UNUSED(authPeer);

        QCC_DbgPrintf(("SecMgr: VerifyCredentials %s", authMechanism));
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            return true;
        }
        return false;
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer,
                                bool success)
    {
        QCC_UNUSED(authPeer);

        QCC_DbgPrintf(("SecMgr: AuthenticationComplete '%s' success = %i", authMechanism, success));
    }
};

QStatus SecurityAgentImpl::ClaimSelf()
{
    QStatus status = ER_FAIL;

    // Manifest
    size_t manifestRuleCount = 1;
    PermissionPolicy::Rule manifestRules;
    manifestRules.SetInterfaceName("*");
    PermissionPolicy::Rule::Member* mfPrms = new PermissionPolicy::Rule::Member[1];
    mfPrms[0].SetMemberName("*");
    mfPrms[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                            PermissionPolicy::Rule::Member::ACTION_MODIFY |
                            PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    manifestRules.SetMembers(1, mfPrms);
    Manifest mf;
    mf.SetFromRules(&manifestRules, manifestRuleCount);

    // Policy
    PermissionPolicy policy;
    policy.SetVersion(1);

    PermissionPolicy::Acl* acls = NULL;
    PermissionPolicy::Peer* peers = NULL;
    PermissionPolicy::Rule* rules = NULL;
    PermissionPolicy::Rule::Member* prms = NULL;

    acls = new PermissionPolicy::Acl[1];
    peers = new PermissionPolicy::Peer[1];
    rules = new PermissionPolicy::Rule[1];
    prms = new PermissionPolicy::Rule::Member[3];

    if (acls == NULL || peers == NULL || rules == NULL || prms == NULL) {
        QCC_LogError(status, ("Failed to create policy"));
        delete[] acls;
        delete[] peers;
        delete[] rules;
        delete[] prms;
        return ER_FAIL;
    }

    peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
    acls[0].SetPeers(1, peers);
    rules[0].SetInterfaceName("*");
    prms[0].SetMemberName("*");
    prms[0].SetMemberType(PermissionPolicy::Rule::Member::METHOD_CALL);
    prms[0].SetActionMask(
        PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY);
    prms[1].SetMemberName("*");
    prms[1].SetMemberType(PermissionPolicy::Rule::Member::PROPERTY);
    prms[1].SetActionMask(
        PermissionPolicy::Rule::Member::ACTION_PROVIDE  | PermissionPolicy::Rule::Member::ACTION_MODIFY |
        PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    prms[2].SetMemberName("*");
    prms[2].SetMemberType(PermissionPolicy::Rule::Member::SIGNAL);
    prms[2].SetActionMask(
        PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_OBSERVE);

    rules[0].SetMembers(3, prms);
    acls[0].SetRules(1, rules);

    policy.SetAcls(1, acls);

    // Get public key, identity and membership certificates
    CredentialAccessor ca(*busAttachment);
    ECCPublicKey ownPublicKey;
    ca.GetDSAPublicKey(ownPublicKey);
    vector<IdentityCertificate> idCerts;
    vector<MembershipCertificateChain> memberships;

    GroupInfo adminGroup;
    status = caStorage->RegisterAgent(agentIdentity, ownPublicKey,
                                      mf, adminGroup, idCerts, memberships);

    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register agent"));
        return status;
    }

    // Claim
    qcc::String ownBusName = busAttachment->GetUniqueName();
    OnlineApplication ownAppInfo;
    ownAppInfo.busName = ownBusName;

    status = remoteApplicationManager->Claim(ownAppInfo, publicKeyInfo,
                                             adminGroup, &idCerts.front(), 1, mf);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to Claim"));
        return status;
    }

    // Store policy
    uint8_t* pByteArray = NULL;
    size_t pSize;
    Util::GetPolicyByteArray(policy, &pByteArray, &pSize);
    KeyStore::Key pKey;
    pKey.SetGUID(GUID128("F5CB9E723D7D4F1CFF985F4DD0D5E388"));
    KeyBlob pKeyBlob((uint8_t*)pByteArray, pSize, KeyBlob::GENERIC);
    delete[] pByteArray;
    status = ca.StoreKey(pKey, pKeyBlob);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to store policy"));
        return status;
    }

    // Store membership certificate
    MembershipCertificateChain mcChain = *memberships.begin();
    MembershipCertificate mCert = *(mcChain.GetMembershipCertificates().begin());
    GUID128 mGUID;
    KeyStore::Key mKey(KeyStore::Key::LOCAL, mGUID);
    KeyBlob mKeyBlob(mCert.GetEncoded(), mCert.GetEncodedLen(), KeyBlob::GENERIC);
    mKeyBlob.SetTag(mCert.GetSerial());
    KeyStore::Key mHead;
    mHead.SetGUID(GUID128("42B0C7F35695A3220A46B3938771E965"));
    KeyBlob mHeaderBlob;
    uint8_t mNumEntries = 1;
    mHeaderBlob.Set(&mNumEntries, 1, KeyBlob::GENERIC);
    status = ca.StoreKey(mHead, mHeaderBlob);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to store membership header"));
        return status;
    }
    status = ca.AddAssociatedKey(mHead, mKey, mKeyBlob);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to store membership certificate"));
        return status;
    }

    return status;
}

SecurityAgentImpl::SecurityAgentImpl(const SecurityAgentIdentityInfo& securityAgentIdendtityInfo,
                                     const std::shared_ptr<CaStorage>& _caStorage, BusAttachment* ba) :
    publicKeyInfo(), agentIdentity(securityAgentIdendtityInfo),
    appMonitor(ApplicationMonitor::GetApplicationMonitor(ba)),
    busAttachment(ba),
    caStorage(_caStorage),
    queue(TaskQueue<AppListenerEvent*, SecurityAgentImpl>(this)), mfListener(NULL)
{
    remoteApplicationManager = NULL;
    applicationUpdater = NULL;
}

QStatus SecurityAgentImpl::Init()
{
    SessionOpts opts;
    QStatus status = ER_OK;

    do {
        if (NULL == caStorage) {
            status = ER_FAIL;
            QCC_LogError(status, ("Invalid caStorage means."));
            break;
        }

        if (NULL == busAttachment) {
            status = ER_FAIL;
            QCC_LogError(status, ("Null bus attachment."));
            break;
        }

        status = Util::Init(busAttachment);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to initialize Util"));
        }

        ProxyObjectManager::listener = new ECDHEKeyXListener();
        if (ProxyObjectManager::listener == NULL) {
            status = ER_FAIL;
            QCC_LogError(status, ("Failed to allocate ECDHEKeyXListener"));
            break;
        }

        status = busAttachment->EnablePeerSecurity(KEYX_ECDHE_NULL, ProxyObjectManager::listener,
                                                   AJNKEY_STORE, true);
        if (ER_OK != status) {
            QCC_LogError(status,
                         ("Failed to enable security on the security manager bus attachment."));
            break;
        }

        status = caStorage->GetCaPublicKeyInfo(publicKeyInfo);
        if (ER_OK != status || publicKeyInfo.GetPublicKey()->empty()) {
            QCC_LogError(status, ("publicKeyInfo.GetPublicKey()->empty() = %i", publicKeyInfo.GetPublicKey()->empty()));
        }

        remoteApplicationManager = make_shared<RemoteApplicationManager>(busAttachment);

        if (NULL == remoteApplicationManager) {
            QCC_LogError(ER_FAIL,
                         ("Could not create remoteApplicationManager!"));
            status = ER_FAIL;
            break;
        }

        if (!remoteApplicationManager->Initialized()) {
            remoteApplicationManager = nullptr;
            QCC_LogError(ER_FAIL, ("Could not initialize the remote application manager"));
            break;
        }

        PermissionConfigurator::ApplicationState applicationState;
        busAttachment->GetPermissionConfigurator().GetApplicationState(applicationState);
        if (PermissionConfigurator::CLAIMABLE == applicationState) {
            status = ClaimSelf();
            if (status != ER_OK) {
                QCC_LogError(status, ("Failed to claim self"));
                break;
            }
        }

        applicationUpdater = make_shared<ApplicationUpdater>(busAttachment,
                                                             caStorage,
                                                             remoteApplicationManager,
                                                             appMonitor,
                                                             this);
        if (NULL == applicationUpdater) {
            status = ER_FAIL;
            QCC_LogError(status, ("Failed to initialize application updater."));
            break;
        }

        std::vector<Application> apps;

        status = caStorage->GetManagedApplications(apps);
        if (ER_OK != status) {
            QCC_LogError(ER_FAIL, ("Could not get applications."));
            break;
        }

        std::vector<Application>::const_iterator it =
            apps.begin();
        for (; it != apps.end(); ++it) {
            OnlineApplication app(PermissionConfigurator::CLAIMED, ""); // BusName will be filled in when discovering the app is online.
            app.publicKey = it->publicKey;
            app.aki = it->aki;
            app.updatesPending = it->updatesPending;
            appsMutex.Lock(__FILE__, __LINE__);
            applications[app.publicKey] = app;
            appsMutex.Unlock(__FILE__, __LINE__);
        }

        caStorage->RegisterStorageListener(this);

        if (NULL == appMonitor) {
            QCC_LogError(status, ("NULL Application Monitor"));
            status = ER_FAIL;
            break;
        }
        appMonitor->RegisterSecurityInfoListener(this);
    } while (0);

    return status;
}

SecurityAgentImpl::~SecurityAgentImpl()
{
    caStorage->UnRegisterStorageListener(this);

    appMonitor->UnregisterSecurityInfoListener(this);

    queue.Stop();

    Util::Fini();

    delete ProxyObjectManager::listener;
    ProxyObjectManager::listener = NULL;
}

void SecurityAgentImpl::SetManifestListener(ManifestListener* mfl)
{
    mfListener = mfl;
}

QStatus SecurityAgentImpl::SetUpdatesPending(const OnlineApplication& app, bool updatesPending)
{
    appsMutex.Lock(__FILE__, __LINE__);

    bool exist;
    OnlineApplicationMap::iterator it = SafeAppExist(app.publicKey, exist);
    if (!exist) {
        appsMutex.Unlock(__FILE__, __LINE__);
        QCC_LogError(ER_FAIL, ("Application does not exist !"));
        return ER_FAIL;
    }

    OnlineApplication oldApp = it->second;
    if (oldApp.updatesPending != updatesPending) {
        it->second.updatesPending = updatesPending;
        NotifyApplicationListeners(&oldApp, &(it->second));
    }

    appsMutex.Unlock(__FILE__, __LINE__);
    return ER_OK;
}

QStatus SecurityAgentImpl::Claim(const OnlineApplication& app, const IdentityInfo& identityInfo)
{
    QStatus status;

    // Check ManifestListener
    if (mfListener == NULL) {
        status = ER_FAIL;
        QCC_LogError(status, ("No ManifestListener set"));
        return status;
    }

    // Check app
    bool exist;
    OnlineApplicationMap::iterator appItr = SafeAppExist(app.publicKey, exist);
    if (!exist) {
        status = ER_FAIL;
        QCC_LogError(status, ("Unknown application"));
        return status;
    }
    OnlineApplication _app = appItr->second;

    /*===========================================================
     * Step 1: Accept manifest
     */
    Manifest manifest;
    status = remoteApplicationManager->GetManifestTemplate(_app, manifest);
    if (ER_OK != status) {
        QCC_LogError(status, ("Could not retrieve manifest"));
        return status;
    }

    if (!mfListener->ApproveManifest(_app, manifest)) {
        return ER_MANIFEST_REJECTED;
    }

    /*===========================================================
     * Step 2: Claim
     */

    qcc::KeyInfoNISTP256 CAKeyInfo;
    status = caStorage->GetCaPublicKeyInfo(CAKeyInfo);

    qcc::IdentityCertificate idCertificate;

    GroupInfo adminGroup;
    status = caStorage->NewApplication(_app, identityInfo, manifest, adminGroup, idCertificate);
    if (status != ER_OK) {
        return status;
    }
    status = remoteApplicationManager->Claim(_app, CAKeyInfo, adminGroup, &idCertificate, 1, manifest);
    if (ER_OK != status) {
        QCC_LogError(status, ("Could not claim application"));
    }
    status = caStorage->ApplicationClaimed(_app, status);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to notify Application got claimed"));
        //TODO: should we unclaim?
    }

    return status;
}

void SecurityAgentImpl::AddSecurityInfo(OnlineApplication& app, const SecurityInfo& si)
{
    app.busName = si.busName;
    app.claimState = si.applicationState;
    app.publicKey = si.publicKey;
    CertificateX509::GenerateAuthorityKeyId(&app.publicKey, app.aki);
}

void SecurityAgentImpl::RemoveSecurityInfo(OnlineApplication& app, const SecurityInfo& si)
{
    // Update online app if the busName is still relevant
    if (app.busName == si.busName) {
        app.busName = "";
    }
}

void SecurityAgentImpl::OnSecurityStateChange(const SecurityInfo* oldSecInfo,
                                              const SecurityInfo* newSecInfo)
{
    if ((NULL == newSecInfo) && (NULL == oldSecInfo)) {
        QCC_LogError(ER_FAIL, ("Both OnSecurityStateChange args are NULL!"));
        return;
    }

    qcc::ECCPublicKey pubKey =
        (NULL != newSecInfo) ? newSecInfo->publicKey : oldSecInfo->publicKey;
    bool exist;
    OnlineApplicationMap::iterator foundAppItr = SafeAppExist(pubKey, exist);

    if (exist) {
        OnlineApplication old(foundAppItr->second);
        if (NULL != newSecInfo) {
            // update of known application
            AddSecurityInfo(foundAppItr->second, *newSecInfo);
            NotifyApplicationListeners(&old, &foundAppItr->second);
        } else {
            // removal of known application
            RemoveSecurityInfo(foundAppItr->second, *oldSecInfo);
            NotifyApplicationListeners(&old, &foundAppItr->second);
        }
    } else {
        if (NULL == newSecInfo) {
            // removal of unknown application
            return;
        }
        // add new application
        OnlineApplication app;
        AddSecurityInfo(app, *newSecInfo);

        appsMutex.Lock(__FILE__, __LINE__);
        applications[app.publicKey] = app;
        appsMutex.Unlock(__FILE__, __LINE__);

        NotifyApplicationListeners(NULL, &app);
    }
}

const KeyInfoNISTP256& SecurityAgentImpl::GetPublicKeyInfo() const
{
    return publicKeyInfo;
}

QStatus SecurityAgentImpl::GetApplication(OnlineApplication& _application) const
{
    QStatus status = ER_END_OF_DATA;
    appsMutex.Lock(__FILE__, __LINE__);
    OnlineApplicationMap::const_iterator ret = applications.find(_application.publicKey);
    if (ret != applications.end()) {
        status = ER_OK;
        _application = ret->second;
    }
    appsMutex.Unlock(__FILE__, __LINE__);

    return status;
}

QStatus SecurityAgentImpl::GetApplications(vector<OnlineApplication>& apps,
                                           const PermissionConfigurator::ApplicationState appsClaimState)
const
{
    QStatus status = ER_FAIL;
    OnlineApplicationMap::const_iterator appItr;

    appsMutex.Lock(__FILE__, __LINE__);

    if (applications.empty()) {
        appsMutex.Unlock(__FILE__, __LINE__);
        return ER_END_OF_DATA;
    }

    for (appItr = applications.begin(); appItr != applications.end();
         ++appItr) {
        const OnlineApplication& app = appItr->second;
        if (appItr->second.claimState == appsClaimState) {
            apps.push_back(app);
        }
    }

    appsMutex.Unlock(__FILE__, __LINE__);

    status = (apps.empty() ? ER_END_OF_DATA : ER_OK);

    return status;
}

void SecurityAgentImpl::RegisterApplicationListener(ApplicationListener* al)
{
    if (NULL != al) {
        applicationListenersMutex.Lock(__FILE__, __LINE__);
        listeners.push_back(al);
        applicationListenersMutex.Unlock(__FILE__, __LINE__);
    }
}

void SecurityAgentImpl::UnregisterApplicationListener(ApplicationListener* al)
{
    applicationListenersMutex.Lock(__FILE__, __LINE__);
    std::vector<ApplicationListener*>::iterator it = std::find(
        listeners.begin(), listeners.end(), al);
    if (listeners.end() != it) {
        listeners.erase(it);
    }
    applicationListenersMutex.Unlock(__FILE__, __LINE__);
}

SecurityAgentImpl::OnlineApplicationMap::iterator SecurityAgentImpl::SafeAppExist(const qcc::
                                                                                  ECCPublicKey
                                                                                  pubKey,
                                                                                  bool& exist)
{
    appsMutex.Lock(__FILE__, __LINE__);
    OnlineApplicationMap::iterator ret = applications.find(pubKey);
    exist = (ret != applications.end());
    appsMutex.Unlock(__FILE__, __LINE__);
    return ret;
}

void SecurityAgentImpl::NotifyApplicationListeners(const SyncError* error)
{
    queue.AddTask(new AppListenerEvent(NULL, NULL, error));
}

void SecurityAgentImpl::OnPendingChanges(std::vector<Application>& apps)
{
    OnPendingChangesCompleted(apps);
}

void SecurityAgentImpl::OnPendingChangesCompleted(std::vector<Application>& apps)
{
    for (size_t i = 0; i < apps.size(); i++) {
        OnlineApplication old;
        old.publicKey = apps[i].publicKey;
        if (ER_OK == GetApplication(old)) {
            OnlineApplication app = old;
            app.updatesPending = apps[i].updatesPending;
            appsMutex.Lock();
            applications[app.publicKey] = app;
            appsMutex.Unlock();
            queue.AddTask(new AppListenerEvent(new OnlineApplication(old), new OnlineApplication(app), NULL));
        }
    }
}

void SecurityAgentImpl::NotifyApplicationListeners(const OnlineApplication* oldApp,
                                                   const OnlineApplication* newApp)
{
    queue.AddTask(new AppListenerEvent(oldApp ? new OnlineApplication(*oldApp) : NULL,
                                       newApp ? new OnlineApplication(*newApp) : NULL,
                                       NULL));
}

void SecurityAgentImpl::HandleTask(AppListenerEvent* event)
{
    applicationListenersMutex.Lock(__FILE__, __LINE__);
    if (event->syncError) {
        for (size_t i = 0; i < listeners.size(); ++i) {
            listeners[i]->OnSyncError(event->syncError);
        }
    } else {
        for (size_t i = 0; i < listeners.size(); ++i) {
            listeners[i]->OnApplicationStateChange(event->oldApp, event->newApp);
        }
    }
    applicationListenersMutex.Unlock(__FILE__, __LINE__);
}

QStatus SecurityAgentImpl::GetApplicationSecInfo(SecurityInfo& secInfo) const
{
    return appMonitor->GetApplication(secInfo);
}

void SecurityAgentImpl::SyncWithApplications(const vector<OnlineApplication>* apps)
{
    bool syncAll = (apps == nullptr);
    OnlineApplicationMap::const_iterator appMapItr;

    if (syncAll) {
        for (appMapItr = applications.begin(); appMapItr != applications.end();
             ++appMapItr) {
            const OnlineApplication& app = appMapItr->second;
            if (app.claimState == PermissionConfigurator::CLAIMED) {
                applicationUpdater->UpdateApplication(app);
            }
        }
    } else {
        vector<OnlineApplication>::const_iterator appItr = apps->begin();
        while (appItr != apps->end()) {
            if ((appMapItr = applications.find(appItr->publicKey)) != applications.end()) {
                const OnlineApplication& app = appMapItr->second;
                if (app.claimState == PermissionConfigurator::CLAIMED) {
                    applicationUpdater->UpdateApplication(app);
                }
            }
            appMapItr++;
        }
    }
}
}
}
#undef QCC_MODULE
