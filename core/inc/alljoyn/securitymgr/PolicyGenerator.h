#ifndef ALLJOYN_SECMGR_POLICYGENERATOR_H_
#define ALLJOYN_SECMGR_POLICYGENERATOR_H_

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

#include <vector>

#include <qcc/String.h>
#include <qcc/GUID.h>
#include <qcc/CryptoECC.h>
#include <alljoyn/PermissionPolicy.h>
#include <alljoyn/Status.h>

#include <alljoyn/securitymgr/GroupInfo.h>

namespace ajn {
namespace securitymgr {
class PolicyGenerator {
  public:
    /*
     * Generates a default policy in which any member of the specified groups can
     * provide any interface to this application and can modify any interface
     * provided by this application.
     *
     * \param[in]  groupInfos  the groups in the generated policy
     * \param[out] policy      the generated policy
     *
     * \return ER_OK           if policy was generated successfully
     * \return others          on failure
     */
    static QStatus DefaultPolicy(const std::vector<GroupInfo>& groupInfos,
                                 PermissionPolicy& policy);

  private:
    static QStatus DefaultGroupPolicyAcl(const GroupInfo& group,
                                         PermissionPolicy::Acl& acl);

    static QStatus DefaultGroupPolicyRule(PermissionPolicy::Rule& rule);
};
}
}

#endif  /* ALLJOYN_SECMGR_POLICYGENERATOR_H_ */
