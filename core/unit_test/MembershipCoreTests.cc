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
#include "qcc/Thread.h"

namespace secmgrcoretest_unit_nominaltests {
using namespace secmgrcoretest_unit_testutil;

using namespace ajn::securitymgr;

class MembershipCoreTests :
    public BasicTest {
  private:

  protected:

  public:
    MembershipCoreTests()
    {
        idInfo.guid = GUID128();
        idInfo.name = "TestIdentity";

        groupInfo1.guid = GUID128();
        groupInfo1.name = "MyGroup 1";
        groupInfo1.desc = "My test group 1 description";

        groupInfo2.guid = GUID128();
        groupInfo2.name = "MyGroup 2";
        groupInfo2.desc = "My test group 2 description";
    }

    IdentityInfo idInfo;
    GroupInfo groupInfo1;
    GroupInfo groupInfo2;
};

TEST_F(MembershipCoreTests, SuccessfulInstallMembership) {
    bool claimAnswer = true;
    TestClaimListener tcl(claimAnswer);

    /* Create groups */
    ASSERT_EQ(ER_OK, storage->StoreGroup(groupInfo1));
    ASSERT_EQ(ER_OK, storage->StoreGroup(groupInfo2));

    /* Start the stub */
    stub = new Stub(&tcl);

    /* Wait for signals */
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMABLE, ajn::securitymgr::STATE_RUNNING));

    /* Installing or removing membership before claiming should fail */
    Application app = lastAppInfo;
    ASSERT_NE(ER_OK, storage->InstallMembership(app, groupInfo2)); // fails due to manifest missing in persistency
    ASSERT_NE(ER_OK, storage->RemoveMembership(app, groupInfo2)); // fails due to certificate missing in persistency

    /* Create identity */
    ASSERT_EQ(storage->StoreIdentity(idInfo), ER_OK);

    /* Claim application */
    ASSERT_EQ(ER_OK, secMgr->Claim(lastAppInfo, idInfo));

    stub->SetDSASecurity(true);

    /* Check security signal */
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, false));

    ASSERT_EQ(ER_OK, storage->InstallMembership(app, groupInfo1));
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, true));
    OnlineApplication checkUpdatesPendingInfo;
    checkUpdatesPendingInfo.publicKey = app.publicKey;
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, false));

    ASSERT_EQ(ER_OK, secMgr->GetApplication(checkUpdatesPendingInfo));
    ASSERT_FALSE(checkUpdatesPendingInfo.updatesPending);

    ASSERT_EQ(ER_OK, storage->InstallMembership(app, groupInfo2));
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, false));
    ASSERT_EQ(ER_OK, secMgr->GetApplication(checkUpdatesPendingInfo));
    ASSERT_FALSE(checkUpdatesPendingInfo.updatesPending);

    ASSERT_EQ(ER_OK, storage->RemoveMembership(app, groupInfo1));
    ASSERT_EQ(ER_OK, storage->RemoveMembership(app, groupInfo2));
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_RUNNING, false));

    /* Clear the keystore of the stub */
    stub->Reset();

    /* Stop the stub */
    delete stub;
    stub = NULL;
    ASSERT_TRUE(WaitForState(ajn::PermissionConfigurator::CLAIMED, ajn::securitymgr::STATE_NOT_RUNNING));
}
} // namespace
