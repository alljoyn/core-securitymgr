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

#include "gtest/gtest.h"
#include "TestUtil.h"
#include <StorageConfig.h>
#include "SecurityManagerFactory.h"
#include <string>

using namespace secmgrcoretest_unit_testutil;
using namespace ajn::securitymgr;
using namespace std;

/**
 * Several identity manipulation (i.e., create, delete, retrieve, list identity(s), etc.) robustness tests.
 */
namespace secmgrcoretest_unit_robustnesstests {
class IdentityManipulationRobustnessTests :
    public BasicTest {
};

/**
 * \test The test should make sure that basic identity manipulation can fail gracefully.
 *       -# Try to get an unknown identity and make sure this fails
 *       -# Try to remove an unknown identity and make sure this fails
 *       -# Try to get all managed identities and make sure the vector is empty
 *       -# change the identityInfo to some dummy info
 *       -# Store it and make sure this was successful
 *       -# Try to store it again and make sure this fails
 * */
TEST_F(IdentityManipulationRobustnessTests, FailedBasicIdentityOperations) {
    vector<IdentityInfo> empty;

    IdentityInfo identityInfo;

    identityInfo.name = "Wrong Identity";

    ASSERT_NE(secMgr->GetIdentity(identityInfo), ER_OK);
    ASSERT_NE(secMgr->RemoveIdentity(identityInfo.guid), ER_OK);
    ASSERT_EQ(secMgr->GetManagedIdentities(empty), ER_OK);
    ASSERT_TRUE(empty.empty());

    identityInfo.name = "Dummy Identity";

    ASSERT_EQ(secMgr->StoreIdentity(identityInfo), ER_OK);
    ASSERT_NE(secMgr->StoreIdentity(identityInfo), ER_OK);
}

/**
 * \test The test should make sure that basic identity update works.
 *       -# Create a identityInfo with some Identity ID (guid)
 *       -# Try to store the identity with update=true and make sure this fails as the identity was not added before
 *       -# Try to store the identity with update=false and make sure this is successful
 *       -# Get the identity and make sure this is successful
 *       -# Try to store the identity without the update flag and make sure this fails as the identity already exists
 *       -# Change the name and description of the identity and try to store with update=true and make sure this succeeds
 *       -# Get the identity and compare the updated fields with the new info and make sure this is successful
 * */
TEST_F(IdentityManipulationRobustnessTests, IdentityUpdate) {
    vector<IdentityInfo> empty;

    IdentityInfo identityInfo;

    qcc::String name = "Hello Identity";
    qcc::String desc = "This is a hello world test identity";

    identityInfo.name = name;

    ASSERT_NE(secMgr->StoreIdentity(identityInfo, true), ER_OK);
    ASSERT_EQ(secMgr->StoreIdentity(identityInfo, false), ER_OK);
    ASSERT_EQ(secMgr->GetIdentity(identityInfo), ER_OK);

    ASSERT_NE(secMgr->StoreIdentity(identityInfo), ER_OK);

    name += " - updated";
    desc += " - updated";

    identityInfo.name = name;

    ASSERT_EQ(secMgr->StoreIdentity(identityInfo, true), ER_OK);
    ASSERT_EQ(secMgr->GetIdentity(identityInfo), ER_OK);

    ASSERT_EQ(identityInfo.name, name);
}
}
//namespace