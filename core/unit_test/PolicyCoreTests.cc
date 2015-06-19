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

#include "TestUtil.h"
#include <alljoyn/securitymgr/PolicyGenerator.h>

namespace secmgrcoretest_unit_nominaltests {
using namespace secmgrcoretest_unit_testutil;

using namespace ajn::securitymgr;

class PolicyCoreTests :
    public BasicTest {
  private:

  protected:

  public:
    PolicyCoreTests()
    {
        idInfo.guid = GUID128();
        idInfo.name = "TestIdentity";
        groupGUID = qcc::GUID128(0xab);
    }

    IdentityInfo idInfo;

    GUID128 groupGUID;
    GUID128 groupGUID2;
    PermissionPolicy policy;
    PermissionPolicy policy2;
};

TEST_F(PolicyCoreTests, SuccessfulInstallPolicy) {
    bool claimAnswer = true;
    TestClaimListener tcl(claimAnswer);

    vector<GroupInfo> policyGroups;
    GroupInfo group;
    group.guid = groupGUID;
    policyGroups.push_back(group);
    PolicyGenerator::DefaultPolicy(policyGroups, policy);

    GroupInfo group2;
    group2.guid = groupGUID2;
    policyGroups.push_back(group2);
    PolicyGenerator::DefaultPolicy(policyGroups, policy2);

    /* Start the stub */
    stub = new Stub(&tcl);

    /* Wait for signals */
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMABLE, ajn::securitymgr::STATE_RUNNING));

    /* Installing/retrieving policy before claiming should fail */
    Application app = lastAppInfo;
    PermissionPolicy policyLocal;
    ASSERT_NE(ER_OK, storage->UpdatePolicy(app, policy));
    ASSERT_NE(ER_OK, storage->UpdatePolicy(app, policy2));
    ASSERT_NE(ER_OK, storage->GetPolicy(app, policyLocal));

    OnlineApplication checkUpdatesPendingInfo;
    checkUpdatesPendingInfo.publicKey = app.publicKey;
    ASSERT_EQ(ER_OK, secMgr->GetApplication(checkUpdatesPendingInfo));
    ASSERT_FALSE(checkUpdatesPendingInfo.updatesPending);

    /* Create identity */
    ASSERT_EQ(storage->StoreIdentity(idInfo), ER_OK);

    /* Claim application */
    ASSERT_EQ(ER_OK, secMgr->Claim(lastAppInfo, idInfo));

    /* Check security signal */
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING));

    /* Check default policy */
    ASSERT_EQ(ER_END_OF_DATA, storage->GetPolicy(app, policyLocal));

    /* Install policy and check retrieved policy */
    ASSERT_EQ(ER_OK, storage->UpdatePolicy(app, policy));
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, true));
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, false));
    ASSERT_EQ(ER_OK, storage->GetPolicy(app, policyLocal));
    ASSERT_EQ((size_t)1, policyLocal.GetAclsSize());

    ASSERT_EQ(ER_OK, secMgr->GetApplication(checkUpdatesPendingInfo));
    ASSERT_FALSE(checkUpdatesPendingInfo.updatesPending);

    /* Install another policy and check retrieved policy */
    ASSERT_EQ(ER_OK, storage->UpdatePolicy(app, policy2));
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, true));
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, false));
    ASSERT_EQ(ER_OK, storage->GetPolicy(app, policyLocal));
    ASSERT_EQ((size_t)2, policyLocal.GetAclsSize());

    ASSERT_EQ(ER_OK, secMgr->GetApplication(checkUpdatesPendingInfo));
    ASSERT_FALSE(checkUpdatesPendingInfo.updatesPending);

    /* Clear the keystore of the stub */
    stub->Reset();

    /* Stop the stub */
    delete stub;
    stub = NULL;
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_NOT_RUNNING));
}
} // namespace
