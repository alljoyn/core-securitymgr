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

#include <alljoyn/securitymgr/ApplicationState.h>

#include "ApplicationMonitor.h"
#include "KeyInfoHelper.h"

#include <algorithm>
#include <iostream>

#include <vector>
#include <qcc/Debug.h>

#define QCC_MODULE "SEGMGR_AGENT"

#define PM_NOTIF_MEMBER "NotifyConfig"
#define AUTOPING_GROUPNAME (qcc::String("AMPingGroup"))

using namespace ajn;
using namespace ajn::securitymgr;

ApplicationMonitor::ApplicationMonitor(ajn::BusAttachment* ba) :
    pinger(new AutoPinger(*ba)), busAttachment(ba)
{
    QStatus status = ER_FAIL;

    if (NULL == busAttachment) {
        QCC_LogError(status, ("NULL busAttachment !"));
        return;
    }

    if (NULL == pinger) {
        QCC_LogError(status, ("NULL pinger !"));
        return;
    }
    pinger->AddPingGroup(qcc::String(AUTOPING_GROUPNAME), *this, 5);

    busAttachment->RegisterApplicationStateListener(*this);
    busAttachment->AddApplicationStateRule();
}

ApplicationMonitor::~ApplicationMonitor()
{
    busAttachment->RemoveApplicationStateRule();
    busAttachment->UnregisterApplicationStateListener(*this);
    delete pinger;
}

void ApplicationMonitor::State(const char* busName,
                               const qcc::KeyInfoNISTP256& publicKeyInfo,
                               PermissionConfigurator::ApplicationState state)
{
    QCC_DbgPrintf(("Received ApplicationState !!!"));

    SecurityInfo info;
    info.busName = qcc::String(busName);
    info.applicationState = state;
    info.publicKey = *(publicKeyInfo.GetPublicKey());

    // ignore signals of local security manager
    qcc::String localBusName = busAttachment->GetUniqueName();
    if (info.busName == localBusName) {
        QCC_DbgPrintf(("Ignoring ApplicationState of local Security Manager."));
        return;
    }

    QCC_DbgPrintf(("busName = %s", info.busName.c_str()));
    QCC_DbgPrintf(("applicationState = %s", ToString(state)));

    appsMutex.Lock(__FILE__, __LINE__);

    std::map<qcc::String, SecurityInfo>::iterator it = applications.find(info.busName);
    if (it != applications.end()) {
        // known bus name
        SecurityInfo oldInfo = it->second;
        it->second = info;
        appsMutex.Unlock(__FILE__, __LINE__);
        NotifySecurityInfoListeners(&oldInfo, &info);
    } else {
        // new bus name
        applications[info.busName] = info;
        appsMutex.Unlock(__FILE__, __LINE__);

        //Intentional sleep, see: ASACORE-1493
        qcc::Sleep(500);

        QStatus status = pinger->AddDestination(AUTOPING_GROUPNAME, info.busName);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to add destination to AutoPinger."));
        }

        NotifySecurityInfoListeners(NULL, &info);
    }
}

std::vector<SecurityInfo> ApplicationMonitor::GetApplications() const
{
    appsMutex.Lock(__FILE__, __LINE__);

    if (!applications.empty()) {
        std::vector<SecurityInfo> apps;
        std::map<qcc::String, SecurityInfo>::const_iterator it = applications.begin();
        for (; it != applications.end(); ++it) {
            const SecurityInfo& app = it->second;
            apps.push_back(app);
        }
        appsMutex.Unlock(__FILE__, __LINE__);
        return apps;
    }
    appsMutex.Unlock(__FILE__, __LINE__);
    return std::vector<SecurityInfo>();
}

QStatus ApplicationMonitor::GetApplication(SecurityInfo& secInfo) const
{
    appsMutex.Lock(__FILE__, __LINE__);
    std::map<qcc::String, SecurityInfo>::const_iterator it  = applications.find(secInfo.busName);
    if (it != applications.end()) {
        secInfo = it->second;
        appsMutex.Unlock(__FILE__, __LINE__);
        return ER_OK;
    }
    appsMutex.Unlock(__FILE__, __LINE__);
    return ER_FAIL;
}

void ApplicationMonitor::RegisterSecurityInfoListener(SecurityInfoListener* al)
{
    if (NULL != al) {
        securityListenersMutex.Lock(__FILE__, __LINE__);
        listeners.push_back(al);
        securityListenersMutex.Unlock(__FILE__, __LINE__);
    }
}

void ApplicationMonitor::UnregisterSecurityInfoListener(SecurityInfoListener* al)
{
    securityListenersMutex.Lock(__FILE__, __LINE__);
    std::vector<SecurityInfoListener*>::iterator it = std::find(listeners.begin(), listeners.end(), al);
    if (listeners.end() != it) {
        listeners.erase(it);
    }
    securityListenersMutex.Unlock(__FILE__, __LINE__);
}

void ApplicationMonitor::NotifySecurityInfoListeners(const SecurityInfo* oldSecInfo,
                                                     const SecurityInfo* newSecInfo)
{
    securityListenersMutex.Lock(__FILE__, __LINE__);
    for (size_t i = 0; i < listeners.size(); ++i) {
        listeners[i]->OnSecurityStateChange(oldSecInfo, newSecInfo);
    }
    securityListenersMutex.Unlock(__FILE__, __LINE__);
}

void ApplicationMonitor::DestinationLost(const qcc::String& group, const qcc::String& destination)
{
    QCC_UNUSED(group);

    QCC_DbgPrintf(("DestinationLost %s\n", destination.data()));
    appsMutex.Lock(__FILE__, __LINE__);

    std::map<qcc::String, SecurityInfo>::iterator it = applications.find(destination);

    if (it != applications.end()) {
        /* we already know this application */
        SecurityInfo secInfo = it->second;
        applications.erase(it);
        appsMutex.Unlock(__FILE__, __LINE__);
        NotifySecurityInfoListeners(&secInfo, NULL);
    } else {
        appsMutex.Unlock(__FILE__, __LINE__);
        /* We are monitoring an app not in the list. Remove it. */
        pinger->RemoveDestination(AUTOPING_GROUPNAME, destination);
    }
}

void ApplicationMonitor::DestinationFound(const qcc::String& group, const qcc::String& destination)
{
    QCC_UNUSED(group);
    QCC_UNUSED(destination);
}

#undef QCC_MODULE
