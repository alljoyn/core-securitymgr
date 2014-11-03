/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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
#include <semaphore.h>

namespace secmgrcoretest_unit_nominaltests {
using namespace secmgrcoretest_unit_testutil;

using namespace ajn::securitymgr;

class ClaimingCoreTests :
    public ClaimTest {
  private:

  protected:

  public:
    ClaimingCoreTests()
    {
    }
};

TEST_F(ClaimingCoreTests, SuccessfulClaim) {
    bool claimAnswer = true;
    TestClaimListener tcl(claimAnswer);

    /* Start the stub */
    Stub* stub = new Stub(&tcl);

    /* Wait for signals */
    sem_wait(&sem); // security signal
    if (tal->_lastAppInfo.appName.size() == 0) {
        sem_wait(&sem); // about signal
    } else {
        sem_trywait(&sem);
    }
    ASSERT_EQ(ajn::securitymgr::STATE_RUNNING, tal->_lastAppInfo.runningState);
    ASSERT_EQ(ajn::PermissionConfigurator::STATE_CLAIMABLE, tal->_lastAppInfo.claimState);

    /* Create identity */
    IdentityInfo idInfo;
    idInfo.guid = GUID128("abcdef123456789");
    idInfo.name = "TestIdentity";
    ASSERT_EQ(secMgr->StoreIdentity(idInfo, false), ER_OK);

    /* Claim */
    ASSERT_EQ(ER_OK, secMgr->Claim(tal->_lastAppInfo, idInfo));

    /* Check security signal */
    sem_wait(&sem);
    ASSERT_EQ(ajn::securitymgr::STATE_RUNNING, tal->_lastAppInfo.runningState);
    ASSERT_EQ(ajn::PermissionConfigurator::STATE_CLAIMED, tal->_lastAppInfo.claimState);

    /* Try to claim again */
    ASSERT_EQ(ER_PERMISSION_DENIED, secMgr->Claim(tal->_lastAppInfo, idInfo));

    /* Clear the keystore of the stub */
    stub->Reset();

    /* Stop the stub */
    delete stub;

    while (sem_trywait(&sem) == 0) {
        ;
    }
    sem_wait(&sem);

    ASSERT_EQ(ajn::securitymgr::STATE_NOT_RUNNING, tal->_lastAppInfo.runningState);
    ASSERT_EQ(ajn::PermissionConfigurator::STATE_CLAIMED, tal->_lastAppInfo.claimState);
}

TEST_F(ClaimingCoreTests, SuccessfulClaimApplication) {
    bool claimAnswer = true;
    TestClaimListener tcl(claimAnswer);

    /* Start the stub */
    Stub* stub = new Stub(&tcl);

    /* Wait for signals */
    sem_wait(&sem); // security signal
    if (tal->_lastAppInfo.appName.size() == 0) {
        sem_wait(&sem); // about signal
    } else {
        sem_trywait(&sem);
    }
    ASSERT_EQ(ajn::securitymgr::STATE_RUNNING, tal->_lastAppInfo.runningState);
    ASSERT_EQ(ajn::PermissionConfigurator::STATE_CLAIMABLE, tal->_lastAppInfo.claimState);

    /* Create identity */
    IdentityInfo idInfo;
    idInfo.guid = GUID128("abcdef123456789");
    idInfo.name = "TestIdentity";
    ASSERT_EQ(secMgr->StoreIdentity(idInfo, false), ER_OK);

    /* Claim application */
    ASSERT_EQ(ER_OK, secMgr->ClaimApplication(tal->_lastAppInfo, idInfo, &AutoAcceptManifest));

    /* Check security signal */
    sem_wait(&sem);
    ASSERT_EQ(ajn::securitymgr::STATE_RUNNING, tal->_lastAppInfo.runningState);
    ASSERT_EQ(ajn::PermissionConfigurator::STATE_CLAIMED, tal->_lastAppInfo.claimState);

    /* Try to claim again */
    ASSERT_EQ(ER_PERMISSION_DENIED, secMgr->ClaimApplication(tal->_lastAppInfo, idInfo, &AutoAcceptManifest));

    /* Clear the keystore of the stub */
    stub->Reset();

    /* Stop the stub */
    delete stub;

    while (sem_trywait(&sem) == 0) {
        ;
    }
    sem_wait(&sem);

    ASSERT_EQ(ajn::securitymgr::STATE_NOT_RUNNING, tal->_lastAppInfo.runningState);
    ASSERT_EQ(ajn::PermissionConfigurator::STATE_CLAIMED, tal->_lastAppInfo.claimState);
}
} // namespace