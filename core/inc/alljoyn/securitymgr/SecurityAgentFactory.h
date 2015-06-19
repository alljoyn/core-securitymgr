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

#ifndef ALLJOYN_SECMGR_SECURITYAGENTFACTORY_H_
#define ALLJOYN_SECMGR_SECURITYAGENTFACTORY_H_

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Status.h>

#include "SecurityAgent.h"
#include "SecurityAgentIdentityInfo.h"
#include "CaStorage.h"

#include <memory>

namespace ajn {
namespace securitymgr {
/* This is a singleton */
class SecurityAgentFactory {
  private:

    BusAttachment* ba;
    bool ownBa;
    QStatus status;

    SecurityAgentFactory();

    ~SecurityAgentFactory();

    SecurityAgentFactory(SecurityAgentFactory const& sf)
    {
        ba = sf.ba;
        ownBa = false;
        status = ER_OK;
    }

    void operator=(SecurityAgentFactory const&) { }

  public:
    /**
     * \brief Get a singleton instance of the security agent factory.
     *
     * \retval SecurityAgentFactory reference to the singleton security agent factory.
     */
    static SecurityAgentFactory& GetInstance()
    {
        static SecurityAgentFactory smf;
        return smf;
    }

    /* \brief Get a security agent instance.
     * \param[in] securityAgentIdendtityInfo
     *               The identity information that should be used
     *               in creating the security agent.
     *               \see{SecurityAgentIdentityInfo}
     * \param[in] ba The bus attachment to be used. If NULL,
     *               then one will be created and owned.
     *
     * \retval SecurityAgent a pointer to a security agent instance.
     * \retval NULL otherwise.
     */
    SecurityAgent* GetSecurityAgent(const SecurityAgentIdentityInfo& securityAgentIdendtityInfo,
                                    const std::shared_ptr<CaStorage>& caStorage,
                                    BusAttachment* ba = nullptr);
};
}
}
#endif /* ALLJOYN_SECMGR_SECURITYAGENTFACTORY_H_ */
