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

#include <alljoyn/securitymgr/SecurityAgentFactory.h>

#define QCC_MODULE "SEGMGR_AGENT"

using namespace ajn;
using namespace qcc;
using namespace securitymgr;

SecurityAgentFactory::SecurityAgentFactory()
{
    ownBa = false;
    status = ER_OK;
    ba = NULL;
}

SecurityAgentFactory::~SecurityAgentFactory()
{
    if (ownBa == true) {
        ba->Disconnect();
        ba->Stop();
        ba->Join();
        delete ba;
    }
}

SecurityAgent* SecurityAgentFactory::GetSecurityAgent(const SecurityAgentIdentityInfo& securityAgentIdendtityInfo,
                                                      const shared_ptr<CaStorage>& caStorage,
                                                      BusAttachment* _ba)
{
    SecurityAgent* sa = nullptr;

    if (_ba == nullptr) {
        if (ba == nullptr) {
            ba =
                new BusAttachment((securityAgentIdendtityInfo.name.empty() ? "SecurityAgent" :
                                   securityAgentIdendtityInfo.
                                   name.c_str()), true);
            ownBa = true;
            do {
                status = ba->Start();
                if (status != ER_OK) {
                    QCC_LogError(status, ("Failed to start bus attachment"));
                    break;
                }

                status = ba->Connect();
                if (status != ER_OK) {
                    QCC_LogError(status, ("Failed to connect bus attachment"));
                    break;
                }
            } while (0);
        }
    } else {
        ba = _ba;
    }

    sa = new SecurityAgent(securityAgentIdendtityInfo, caStorage, ba);
    if (nullptr == sa || ER_OK != sa->Init()) {
        delete sa;
        sa = nullptr;
    }
    return sa;
}

#undef QCC_MODULE
