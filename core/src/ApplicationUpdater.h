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

#ifndef ALLJOYN_SECMGR_APPLICATIONUPDATER_H_
#define ALLJOYN_SECMGR_APPLICATIONUPDATER_H_

#include <qcc/GUID.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Status.h>

#include <alljoyn/securitymgr/CaStorage.h>
#include <alljoyn/securitymgr/Application.h>

#include "RemoteApplicationManager.h"
#include "SecurityInfoListener.h"
#include "TaskQueue.h"
#include "SecurityAgentImpl.h"
#include <memory>

namespace ajn {
namespace securitymgr {
class SecurityEvent {
  public:
    SecurityInfo* newInfo;
    SecurityInfo* oldInfo;
    SecurityEvent(const SecurityInfo* n,
                  const SecurityInfo* o) :
        newInfo(n == NULL ? NULL :
                new SecurityInfo(*n)), oldInfo(o == NULL ? NULL :
                                               new SecurityInfo(*o))
    {
    }

    ~SecurityEvent()
    {
        delete newInfo;
        delete oldInfo;
    }
};

class ApplicationUpdater :
    public SecurityInfoListener,
    public StorageListener {
  public:
    ApplicationUpdater(BusAttachment* ba, // no ownership
                       const shared_ptr<CaStorage>& s,
                       shared_ptr<RemoteApplicationManager>& ram,
                       shared_ptr<ApplicationMonitor>& _monitor,
                       SecurityAgentImpl* smi // no ownership
                       ) :
        busAttachment(ba), storage(s), applicationManager(ram), monitor(_monitor),
        securityAgentImpl(smi),
        queue(TaskQueue<SecurityEvent*, ApplicationUpdater>(this))
    {
        monitor->RegisterSecurityInfoListener(this);
        storage->RegisterStorageListener(this);
    }

    ~ApplicationUpdater()
    {
        storage->UnRegisterStorageListener(this);
        monitor->UnregisterSecurityInfoListener(this);
        queue.Stop();
    }

    QStatus UpdateApplication(const OnlineApplication& app);

    QStatus UpdateApplication(const SecurityInfo& secInfo);

    void HandleTask(SecurityEvent* event);

  private:
    QStatus UpdateApplication(const OnlineApplication& app,
                              const SecurityInfo& secInfo);

    QStatus ResetApplication(const OnlineApplication& app,
                             const SecurityInfo& secInfo);

    QStatus UpdatePolicy(const OnlineApplication& app,
                         const SecurityInfo& secInfo);

    QStatus UpdateMembershipCertificates(const OnlineApplication& app,
                                         const SecurityInfo& secInfo,
                                         const Application& mgdAppInfo);

    QStatus UpdateIdentityCert(const OnlineApplication& app);

    virtual void OnSecurityStateChange(const SecurityInfo* oldSecInfo,
                                       const SecurityInfo* newSecInfo);

    virtual void OnPendingChanges(std::vector<Application>& apps);

    virtual void OnPendingChangesCompleted(std::vector<Application>& apps)
    {
        QCC_UNUSED(apps);
    }

  private:
    ajn::BusAttachment* busAttachment;
    shared_ptr<CaStorage> storage;
    shared_ptr<RemoteApplicationManager> applicationManager;
    shared_ptr<ApplicationMonitor> monitor;
    SecurityAgentImpl* securityAgentImpl;

    TaskQueue<SecurityEvent*, ApplicationUpdater> queue;
};
}
}

#endif /* ALLJOYN_SECMGR_APPLICATIONUPDATER_H_ */
