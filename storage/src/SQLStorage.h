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

#ifndef ALLJOYN_SECMGR_STORAGE_SQLSTORAGE_H_
#define ALLJOYN_SECMGR_STORAGE_SQLSTORAGE_H_

#include "sqlite3.h"

#include <alljoyn/securitymgr/Application.h>
#include <alljoyn/securitymgr/GroupInfo.h>
#include <alljoyn/securitymgr/IdentityInfo.h>
#include <alljoyn/securitymgr/Manifest.h>
#include <alljoyn/securitymgr/sqlstorage/ApplicationMetaData.h>

#include <alljoyn/Status.h>
#include <qcc/String.h>
#include <qcc/CertificateECC.h>
#include <qcc/CryptoECC.h>
#include <qcc/Mutex.h>

#include <iostream>
#include "SQLStorageConfig.h"

/**
 * \class SQLStorage
 * \brief A class that is meant to implement the Storage abstract class in order to provide a persistent storage
 *        on a native Linux device.
 **/
#define INITIAL_SERIAL_NUMBER 1

using namespace qcc;
namespace ajn {
namespace securitymgr {
struct Keys {
    const qcc::ECCPublicKey* appECCPublicKey;
    qcc::String* groupID;
};

enum InfoType {
    INFO_GROUP,
    INFO_IDENTITY
};

class SQLStorage {
  private:

    QStatus status;
    sqlite3* nativeStorageDB;
    SQLStorageConfig storageConfig;
    mutable qcc::Mutex storageMutex;

    QStatus Init();

    static QStatus ExportKeyInfo(const qcc::KeyInfoNISTP256& authority,
                                 uint8_t** data,
                                 size_t& exportedSize);

    QStatus StoreInfo(InfoType type,
                      const qcc::KeyInfoNISTP256& authority,
                      const GUID128& guid,
                      const qcc::String& name,
                      const qcc::String& desc,
                      bool update);

    QStatus GetInfo(InfoType type,
                    const qcc::KeyInfoNISTP256& auth,
                    const GUID128& guid,
                    qcc::String& name,
                    qcc::String& desc) const;

    QStatus RemoveInfo(InfoType type,
                       const qcc::KeyInfoNISTP256& authority,
                       const GUID128& guid);

    QStatus BindCertForStorage(qcc::CertificateX509& certificate,
                               const char* sqlStmtText,
                               sqlite3_stmt** statement);                                                                       //Could be generalized in the future for all cert types

    QStatus StepAndFinalizeSqlStmt(sqlite3_stmt* statement) const;

    QStatus InitSerialNumber();

    qcc::String GetStoragePath() const;

    QStatus PrepareCertificateQuery(const qcc::MembershipCertificate& cert,
                                    sqlite3_stmt** statement) const;

    QStatus GetCertificateFromRow(sqlite3_stmt** statement,
                                  qcc::MembershipCertificate& cert) const;

    QStatus GetCertificateFromRow(sqlite3_stmt** statement,
                                  qcc::CertificateX509& cert,
                                  const qcc::String tableName,
                                  Keys keys) const;

    QStatus GetPolicyOrManifest(const Application& app,
                                const char* type,
                                uint8_t** byteArray,
                                size_t* size) const;

    QStatus StorePolicyOrManifest(const Application& app,
                                  const uint8_t* byteArray,
                                  const size_t size,
                                  const char* type);

  public:

    SQLStorage(const SQLStorageConfig& _storageConfig) :
        status(ER_OK), storageConfig(_storageConfig)
    {
        status = Init();
    }

    QStatus GetStatus() const
    {
        return status;
    }

    QStatus StoreApplication(const Application& app,
                             const bool update = false);

    QStatus SetAppMetaData(const Application& app,
                           const ApplicationMetaData& appMetaData);

    QStatus GetAppMetaData(const Application& app,
                           ApplicationMetaData& appMetaData) const;

    QStatus RemoveApplication(const Application& app);

    QStatus GetManagedApplications(std::vector<Application>& apps) const;

    QStatus GetManagedApplication(Application& app) const;

    QStatus GetManifest(const Application& app,
                        Manifest& manifest) const;

    QStatus GetPolicy(const Application& app,
                      PermissionPolicy& policy) const;

    QStatus StoreManifest(const Application& app,
                          const Manifest& manifest);

    QStatus StorePolicy(const Application& app,
                        const PermissionPolicy& policy);

    QStatus StoreCertificate(qcc::CertificateX509& certificate,
                             bool update = false);

    QStatus RemoveCertificate(qcc::CertificateX509& certificate);

    QStatus GetCertificate(qcc::CertificateX509& certificate);

    QStatus GetCertificates(const qcc::MembershipCertificate& certificate,
                            std::vector<qcc::MembershipCertificate>& certificates) const;

    QStatus StoreGroup(const GroupInfo& groupInfo);

    QStatus RemoveGroup(const GroupInfo& groupInfo);

    QStatus GetGroup(GroupInfo& groupInfo) const;

    QStatus GetGroups(std::vector<GroupInfo>& groupsInfo) const;

    QStatus StoreIdentity(const IdentityInfo& idInfo);

    QStatus RemoveIdentity(const IdentityInfo& idInfo);

    QStatus GetIdentity(IdentityInfo& idInfo) const;

    QStatus GetIdentities(std::vector<IdentityInfo>& idInfos) const;

    QStatus GetNewSerialNumber(qcc::String& serialNumber) const;

    void Reset();

    virtual ~SQLStorage();
};
}
}
#endif /* ALLJOYN_SECMGR_STORAGE_SQLSTORAGE_H_ */
