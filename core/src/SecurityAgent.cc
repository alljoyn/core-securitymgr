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

#include <alljoyn/securitymgr/SecurityAgent.h>
#include "SecurityAgentImpl.h"

#define QCC_MODULE "SEGMGR_AGENT"

using namespace ajn;
using namespace qcc;
using namespace securitymgr;

SecurityAgent::SecurityAgent(const SecurityAgentIdentityInfo& securityAgentIdendtityInfo,
                             const std::shared_ptr<CaStorage>& caStorage, BusAttachment* ba) :
    securityAgentImpl(new SecurityAgentImpl(securityAgentIdendtityInfo, caStorage, ba))
{
}

SecurityAgent::~SecurityAgent()
{
    securityAgentImpl.reset();
}

QStatus SecurityAgent::Claim(const OnlineApplication& app,
                             const IdentityInfo& id)
{
    return securityAgentImpl->Claim(app, id);
}

void SecurityAgent::SetManifestListener(ManifestListener* listener)
{
    securityAgentImpl->SetManifestListener(listener);
}

void SecurityAgent::RegisterApplicationListener(ApplicationListener* al)
{
    return securityAgentImpl->RegisterApplicationListener(al);
}

void SecurityAgent::UnregisterApplicationListener(ApplicationListener* al)
{
    return securityAgentImpl->UnregisterApplicationListener(al);
}

QStatus SecurityAgent::GetApplications(vector<OnlineApplication>& apps,
                                       const PermissionConfigurator::ApplicationState appsClaimState) const
{
    return securityAgentImpl->GetApplications(apps, appsClaimState);
}

QStatus SecurityAgent::GetApplication(OnlineApplication& app) const
{
    return securityAgentImpl->GetApplication(app);
}

void SecurityAgent::SyncWithApplications(const vector<OnlineApplication>* apps)
{
    securityAgentImpl->SyncWithApplications(apps);
}

QStatus SecurityAgent::Init()
{
    return securityAgentImpl->Init();
}

const KeyInfoNISTP256& SecurityAgent::GetPublicKeyInfo() const
{
    return securityAgentImpl->GetPublicKeyInfo();
}

#undef QCC_MODULE
