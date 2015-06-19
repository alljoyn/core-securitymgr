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

#include "gtest/gtest.h"

#include <stdio.h>
#include <alljoyn/securitymgr/PolicyGenerator.h>
#include <alljoyn/securitymgr/GroupInfo.h>
#include <qcc/StringUtil.h>

using namespace std;
using namespace ajn;
using namespace qcc;
using namespace securitymgr;

TEST(PolicyGeneratorTest, BasicTest) {
    ECCPublicKey publicKey;
    PermissionPolicy pol;
    GUID128 groupID;
    qcc::String groupIDString = BytesToHexString(groupID.GetBytes(), GUID128::SIZE);

    GroupInfo group1;
    group1.guid = groupID;

    vector<GroupInfo> groups;
    groups.push_back(group1);

    PolicyGenerator::DefaultPolicy(groups, pol);
    qcc::String policyString = pol.ToString();
    ASSERT_EQ((size_t)1, pol.GetAclsSize());

    GUID128 groupID2;
    qcc::String groupID2String = BytesToHexString(groupID2.GetBytes(), GUID128::SIZE);

    GroupInfo group2;
    group2.guid = groupID2;
    groups.push_back(group2);

    PolicyGenerator::DefaultPolicy(groups, pol);
    policyString = pol.ToString();

    ASSERT_EQ((size_t)2, pol.GetAclsSize());
}
