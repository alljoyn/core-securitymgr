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

#include <SQLStorage.h>
#include <SQLStorageSettings.h>
#include <qcc/Crypto.h>
#include <qcc/Debug.h>
#include <qcc/GUID.h>
#include <qcc/CertificateECC.h>

#include "alljoyn/securitymgr/Util.h"

#define QCC_MODULE "SEGMGR_STORAGE"

namespace ajn {
namespace securitymgr {
#define LOGSQLERROR(a) { QCC_LogError((a), ((qcc::String("SQL Error: ") + (sqlite3_errmsg(nativeStorageDB))).c_str())); \
}

QStatus SQLStorage::StoreApplication(const Application& app, const bool update)
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement;
    QStatus funcStatus = ER_FAIL;
    qcc::String sqlStmtText;
    int keyPosition = 1;
    int othersStartPosition = 1;

    if (update) {
        Application tmp = app;
        if (ER_OK != GetManagedApplication(tmp)) {
            QCC_LogError(funcStatus, ("Trying to update a non-existing application !"));
            return funcStatus;
        }

        sqlStmtText = "UPDATE ";
        sqlStmtText.append(CLAIMED_APPS_TABLE_NAME);
        sqlStmtText.append(
            " SET APP_NAME = ?, PEER_ID = ?, DEV_NAME = ?, USER_DEF_NAME = ?, UPDATES_PENDING = ? WHERE APPLICATION_PUBKEY = ?");
        keyPosition = 6;
    } else {
        sqlStmtText = "INSERT INTO ";
        sqlStmtText.append(CLAIMED_APPS_TABLE_NAME);
        sqlStmtText.append(
            " (APPLICATION_PUBKEY, APP_NAME, PEER_ID, DEV_NAME, USER_DEF_NAME, UPDATES_PENDING) VALUES (?, ?, ?, ?, ?, ?)");
        othersStartPosition++;
    }

    if (app.aki.empty()) {
        funcStatus = ER_FAIL;
        QCC_LogError(funcStatus, ("Empty peer ID !"));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
    size_t size = sizeof(publicKey);
    funcStatus = app.publicKey.Export(publicKey, &size);
    if (funcStatus != ER_OK) {
        QCC_LogError(funcStatus, ("Failed to export public key"));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }
    do {
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        sqlRetCode = sqlite3_bind_blob(statement, keyPosition,
                                       publicKey, qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ,
                                       SQLITE_TRANSIENT);

        sqlRetCode |= sqlite3_bind_text(statement, ++othersStartPosition,
                                        app.aki.c_str(), -1, SQLITE_TRANSIENT);
        othersStartPosition += 2; // Skip DEV_NAME, USER_DEF_NAME
        sqlRetCode |= sqlite3_bind_int(statement,
                                       ++othersStartPosition,
                                       (const bool)app.updatesPending);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    funcStatus = StepAndFinalizeSqlStmt(statement);
    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::RemoveApplication(const Application& app)
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    const char* sqlStmtText = NULL;
    QStatus funcStatus = ER_OK;

    do {
        sqlStmtText =
            "DELETE FROM " CLAIMED_APPS_TABLE_NAME " WHERE APPLICATION_PUBKEY = ?";
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText, -1,
                                        &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t size = sizeof(publicKey);
        funcStatus = app.publicKey.Export(publicKey, &size);
        if (funcStatus != ER_OK) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }
        sqlRetCode = sqlite3_bind_blob(statement, 1,
                                       publicKey, qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ,
                                       SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    funcStatus = StepAndFinalizeSqlStmt(statement);

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::SetAppMetaData(const Application& app, const ApplicationMetaData& appMetaData)
{
    storageMutex.Lock(__FILE__, __LINE__);

    QStatus funcStatus = ER_FAIL;
    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement;
    qcc::String sqlStmtText;

    Application tmp = app;
    if (ER_OK != (funcStatus = GetManagedApplication(tmp))) {
        QCC_LogError(funcStatus, ("Trying to update meta data for a non-existing application !"));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    if (app.aki.empty()) {
        funcStatus = ER_FAIL;
        QCC_LogError(funcStatus, ("Empty peer ID !"));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    sqlStmtText = "UPDATE ";
    sqlStmtText.append(CLAIMED_APPS_TABLE_NAME);
    sqlStmtText.append(" SET APP_NAME = ?, DEV_NAME = ?, USER_DEF_NAME = ? WHERE APPLICATION_PUBKEY = ?");

    uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
    size_t size = sizeof(publicKey);
    funcStatus = app.publicKey.Export(publicKey, &size);
    if (funcStatus != ER_OK || (size != qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ)) {
        QCC_LogError(funcStatus, ("Failed to export public key"));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }
    do {
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        sqlRetCode = sqlite3_bind_blob(statement, 4,
                                       publicKey, qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ,
                                       SQLITE_TRANSIENT);

        sqlRetCode |= sqlite3_bind_text(statement, 1,
                                        appMetaData.appName.c_str(), -1, SQLITE_TRANSIENT);
        sqlRetCode |= sqlite3_bind_text(statement, 2,
                                        appMetaData.deviceName.c_str(), -1, SQLITE_TRANSIENT);
        sqlRetCode |= sqlite3_bind_text(statement, 3,
                                        appMetaData.userDefinedName.c_str(), -1, SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    funcStatus = StepAndFinalizeSqlStmt(statement);
    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetAppMetaData(const Application& app, ApplicationMetaData& appMetaData) const
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_FAIL;

    Application tmp = app;
    if (ER_OK != (funcStatus = GetManagedApplication(tmp))) {
        QCC_LogError(funcStatus, ("Trying to get meta data for a non-existing application !"));
        return funcStatus;
    }

    do {
        sqlStmtText = "SELECT APP_NAME, DEV_NAME, USER_DEF_NAME FROM ";
        sqlStmtText.append(CLAIMED_APPS_TABLE_NAME);
        sqlStmtText.append(" WHERE APPLICATION_PUBKEY LIKE ?");

        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t size = sizeof(publicKey);
        funcStatus = app.publicKey.Export(publicKey, &size);
        if (funcStatus != ER_OK || (size != qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ)) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }
        sqlRetCode = sqlite3_bind_blob(statement, 1, publicKey,
                                       qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ, SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
        sqlRetCode = sqlite3_step(statement);
        if (SQLITE_ROW == sqlRetCode) {
            appMetaData.appName.assign((const char*)sqlite3_column_text(statement, 0));
            appMetaData.deviceName.assign((const char*)sqlite3_column_text(statement, 1));
            appMetaData.userDefinedName.assign((const char*)sqlite3_column_text(statement, 2));
        } else if (SQLITE_DONE == sqlRetCode) {
            QCC_DbgHLPrintf(("No meta data was found !"));
            funcStatus = ER_END_OF_DATA;
            break;
        } else {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetManagedApplications(std::vector<Application>& apps) const
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;

    sqlStmtText = "SELECT * FROM ";
    sqlStmtText.append(CLAIMED_APPS_TABLE_NAME);

    /* prepare the sql query */
    sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(), -1,
                                    &statement, NULL);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    /* iterate over all the rows in the query */
    while (SQLITE_ROW == (sqlRetCode = sqlite3_step(statement))) {
        Application app;
        app.publicKey.Import((const uint8_t*)sqlite3_column_blob(statement,
                                                                 0), qcc::ECC_COORDINATE_SZ +
                             qcc::ECC_COORDINATE_SZ);

        app.aki.assign(
            (const char*)sqlite3_column_text(statement, 2));
        app.updatesPending = sqlite3_column_int(statement, 7);
        apps.push_back(app);
    }

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetManifest(const Application& app,
                                Manifest& manifest) const
{
    storageMutex.Lock(__FILE__, __LINE__);
    uint8_t* byteArray = nullptr;
    size_t size = 0;
    QStatus funcStatus = GetPolicyOrManifest(app, "MANIFEST", &byteArray, &size);

    if (funcStatus == ER_OK) {
        funcStatus = manifest.SetFromByteArray(byteArray, size);
    }

    if (funcStatus != ER_OK) {
        QCC_LogError(funcStatus, ("Failed to get manifest"));
    }

    delete byteArray;
    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetPolicy(const Application& app, PermissionPolicy& policy) const
{
    storageMutex.Lock(__FILE__, __LINE__);
    uint8_t* byteArray = nullptr;
    size_t size = 0;

    QStatus funcStatus = GetPolicyOrManifest(app, "POLICY", &byteArray, &size);
    if (funcStatus == ER_OK) {
        funcStatus  = Util::GetPolicy(byteArray, size, policy);         // Util reports error on de-serialization issues
    } else {
        QCC_LogError(funcStatus, ("Failed to get policy"));
    }

    delete byteArray;
    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetNewSerialNumber(qcc::String& serialNumber) const
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;
    sqlStmtText = "SELECT * FROM ";
    sqlStmtText.append(SERIALNUMBER_TABLE_NAME);

    /* prepare the sql query */
    sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(), -1,
                                    &statement, NULL);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    if (SQLITE_ROW == (sqlRetCode = sqlite3_step(statement))) {
        int value = sqlite3_column_int(statement, 0);
        sqlRetCode = sqlite3_finalize(statement);
        char buffer[33];
        snprintf(buffer, 32, "%x", value);
        buffer[32] = 0; //make sure we have a trailing 0.
        serialNumber.clear();
        serialNumber.append(buffer);

        //update the value in the database.
        sqlStmtText = "UPDATE ";
        sqlStmtText.append(SERIALNUMBER_TABLE_NAME);
        sqlStmtText.append(" SET VALUE = ?");
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(), -1,
                                        &statement, NULL);

        sqlRetCode |= sqlite3_bind_int(statement, 1, value + 1);
        funcStatus = StepAndFinalizeSqlStmt(statement);
    } else if (SQLITE_DONE == sqlRetCode) {
        funcStatus = ER_END_OF_DATA;
        QCC_LogError(ER_END_OF_DATA, ("Serial number was not initialized!"));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetManagedApplication(Application& app) const
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;

    do {
        sqlStmtText = "SELECT * FROM ";
        sqlStmtText.append(CLAIMED_APPS_TABLE_NAME);
        sqlStmtText.append(" WHERE APPLICATION_PUBKEY LIKE ?");

        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t size = sizeof(publicKey);
        funcStatus = app.publicKey.Export(publicKey, &size);
        if (funcStatus != ER_OK) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }
        sqlRetCode = sqlite3_bind_blob(statement, 1, publicKey,
                                       qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ, SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
        sqlRetCode = sqlite3_step(statement);
        if (SQLITE_ROW == sqlRetCode) {
            app.aki.assign((const char*)sqlite3_column_text(statement, 2));
            app.updatesPending = sqlite3_column_int(statement, 7);
        } else if (SQLITE_DONE == sqlRetCode) {
            QCC_DbgHLPrintf(("No managed application was found !"));
            funcStatus = ER_END_OF_DATA;
            break;
        } else {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::StoreManifest(const Application& app, const Manifest& manifest)
{
    storageMutex.Lock(__FILE__, __LINE__);
    QStatus funcStatus = ER_FAIL;
    uint8_t* manifestByteArray = nullptr;
    size_t size = 0;

    do {
        if (ER_OK != (funcStatus = manifest.GetByteArray(&manifestByteArray, &size))) {
            QCC_LogError(funcStatus, ("Failed to export manifest data"));
            break;
        }

        if (ER_OK != (funcStatus = StorePolicyOrManifest(app,  manifestByteArray, size, "MANIFEST"))) {
            QCC_LogError(funcStatus, ("Failed to store manifest !"));
            break;
        }
    } while (0);

    delete[]manifestByteArray;

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::StorePolicy(const Application& app, const PermissionPolicy& policy)
{
    storageMutex.Lock(__FILE__, __LINE__);
    QStatus funcStatus = ER_FAIL;
    uint8_t* byteArray = nullptr;
    size_t size = 0;

    if (ER_OK == (funcStatus = Util::GetPolicyByteArray(policy, &byteArray, &size))) { // Util reports in case of serialization errors
        if (ER_OK != (funcStatus = StorePolicyOrManifest(app,  byteArray, size, "POLICY"))) {
            QCC_LogError(funcStatus, ("Failed to store policy !"));
        }
    }

    delete[]byteArray;

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::StoreCertificate(qcc::CertificateX509& certificate,
                                     const bool update)
{
    storageMutex.Lock(__FILE__, __LINE__);

    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;

    if (update) {
        sqlStmtText = "INSERT OR REPLACE INTO ";
    } else {
        sqlStmtText = "INSERT INTO ";
    }

    switch (certificate.GetType()) {
    case qcc::CertificateX509::IDENTITY_CERTIFICATE: {
            sqlStmtText.append(IDENTITY_CERTS_TABLE_NAME);
            sqlStmtText.append(" (SUBJECT, ISSUER"
                               ", DER"
                               ", ID) VALUES (?, ?, ?, ?)");
        }
        break;

    case qcc::CertificateX509::MEMBERSHIP_CERTIFICATE: {
            sqlStmtText.append(MEMBERSHIP_CERTS_TABLE_NAME);
            sqlStmtText.append(" (SUBJECT, ISSUER"
                               ", DER"
                               ", GUID) VALUES (?, ?, ?, ?)");
        }
        break;

    default: {
            QCC_LogError(ER_FAIL, ("Unsupported certificate type !"));
            storageMutex.Unlock(__FILE__, __LINE__);
            return ER_FAIL;
        }
    }

    funcStatus = BindCertForStorage(certificate, sqlStmtText.c_str(),
                                    &statement);

    if (ER_OK != funcStatus) {
        QCC_LogError(funcStatus, ("Binding values of certificate for storage has failed"));
        StepAndFinalizeSqlStmt(statement);
    } else {
        funcStatus = StepAndFinalizeSqlStmt(statement);
    }
    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetCertificates(const qcc::MembershipCertificate& certificate,
                                    std::vector<qcc::MembershipCertificate>& certificates) const
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    QStatus funcStatus = ER_OK;

    funcStatus = PrepareCertificateQuery(certificate, &statement);
    if (ER_OK != funcStatus) {
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    while (SQLITE_ROW == (sqlRetCode = sqlite3_step(statement))) {
        qcc::MembershipCertificate cert;
        funcStatus = GetCertificateFromRow(&statement, cert);
        if (ER_OK != funcStatus) {
            break;
        }
        certificates.push_back(cert);
    }

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);
    return funcStatus;
}

QStatus SQLStorage::GetCertificate(qcc::CertificateX509& cert)
{
    storageMutex.Lock(__FILE__, __LINE__);

    sqlite3_stmt* statement = NULL;
    int sqlRetCode = SQLITE_OK;
    QStatus funcStatus = ER_OK;
    qcc::String sqlStmtText = "";
    qcc::String tableName = "";
    const qcc::ECCPublicKey* appECCPublicKey = NULL;
    qcc::String groupId = "";

    appECCPublicKey = cert.GetSubjectPublicKey();

    if (NULL == appECCPublicKey) {
        funcStatus = ER_FAIL;
        QCC_LogError(funcStatus, ("Null application public key."));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }
    do {
        sqlStmtText = "SELECT DER, LENGTH(DER) FROM ";

        switch (cert.GetType()) {
        case qcc::CertificateX509::IDENTITY_CERTIFICATE: {
                tableName = IDENTITY_CERTS_TABLE_NAME;
                sqlStmtText += IDENTITY_CERTS_TABLE_NAME;
                sqlStmtText += " WHERE SUBJECT = ? ";
            }
            break;

        case qcc::CertificateX509::MEMBERSHIP_CERTIFICATE: {
                tableName = MEMBERSHIP_CERTS_TABLE_NAME;
                sqlStmtText += MEMBERSHIP_CERTS_TABLE_NAME;
                sqlStmtText += " WHERE SUBJECT = ? AND GUID = ? ";
                groupId =
                    dynamic_cast<qcc::MembershipCertificate&>(cert).GetGuild().ToString();
            }
            break;

        default: {
                QCC_LogError(ER_FAIL, ("Unsupported certificate type !"));
                storageMutex.Unlock(__FILE__, __LINE__);
                return ER_FAIL;
            }
        }

        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t size = sizeof(publicKey);
        funcStatus = appECCPublicKey->Export(publicKey, &size);
        if (funcStatus != ER_OK) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }
        sqlRetCode = sqlite3_bind_blob(statement, 1, publicKey,
                                       sizeof(publicKey), SQLITE_TRANSIENT);

        if (qcc::CertificateX509::MEMBERSHIP_CERTIFICATE == cert.GetType()) {
            sqlRetCode |= sqlite3_bind_text(statement, 2, groupId.c_str(), -1,
                                            SQLITE_TRANSIENT);
        }

        if (SQLITE_ROW == (sqlRetCode = sqlite3_step(statement))) {
            /*********************Common to all certificates*****************/
            int derSize = sqlite3_column_int(statement, 1);     // DER is never empty
            funcStatus =  cert.LoadEncoded((const uint8_t*)sqlite3_column_blob(statement, 0), derSize);
        } else if (SQLITE_DONE == sqlRetCode) {
            QCC_DbgHLPrintf(("No certificate was found!"));
            funcStatus = ER_END_OF_DATA;
            break;
        } else {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::RemoveCertificate(qcc::CertificateX509& cert)
{
    storageMutex.Lock(__FILE__, __LINE__);

    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    int sqlRetCode = SQLITE_OK;
    QStatus funcStatus = ER_OK;
    qcc::String certTableName = "";
    qcc::String whereKeys = "";
    const qcc::ECCPublicKey* appECCPublicKey = NULL;

    appECCPublicKey = cert.GetSubjectPublicKey();

    if (NULL == appECCPublicKey) {
        QCC_LogError(ER_FAIL, ("Null application public key."));
        storageMutex.Unlock(__FILE__, __LINE__);
        return ER_FAIL;
    }

    switch (cert.GetType()) {
    case qcc::CertificateX509::IDENTITY_CERTIFICATE: {
            certTableName = IDENTITY_CERTS_TABLE_NAME;
            whereKeys = " WHERE SUBJECT = ? ";
        }
        break;

    case qcc::CertificateX509::MEMBERSHIP_CERTIFICATE: {
            certTableName = MEMBERSHIP_CERTS_TABLE_NAME;
            whereKeys = " WHERE SUBJECT = ? AND GUID = ? ";
        }
        break;

    default: {
            QCC_LogError(ER_FAIL, ("Unsupported certificate type !"));
            storageMutex.Unlock(__FILE__, __LINE__);
            return ER_FAIL;
        }
    }

    do {
        sqlStmtText = "DELETE FROM ";
        sqlStmtText.append(certTableName);
        sqlStmtText.append(whereKeys);

        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            break;
        }

        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t size = sizeof(publicKey);
        funcStatus = appECCPublicKey->Export(publicKey, &size);
        if (funcStatus != ER_OK) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }
        sqlRetCode = sqlite3_bind_blob(statement, 1, publicKey,
                                       sizeof(publicKey), SQLITE_TRANSIENT);
        if (qcc::CertificateX509::MEMBERSHIP_CERTIFICATE == cert.GetType()) {
            sqlRetCode |=
                sqlite3_bind_text(statement, 2,
                                  dynamic_cast<qcc::MembershipCertificate&>(cert).GetGuild().
                                  ToString().c_str(),
                                  -1, SQLITE_TRANSIENT);
        }

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    funcStatus = StepAndFinalizeSqlStmt(statement);

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::StoreGroup(const GroupInfo& groupInfo)
{
    QStatus funcStatus = ER_FAIL;
    storageMutex.Lock(__FILE__, __LINE__);

    bool update;
    GroupInfo tmp = groupInfo; // to avoid const cast
    funcStatus = GetGroup(tmp);
    if (ER_OK == funcStatus) {
        update = true;
    } else if (ER_END_OF_DATA == funcStatus) {
        update = false;
    } else {
        QCC_LogError(funcStatus, ("Could not determine update status for group."));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    funcStatus = StoreInfo(INFO_GROUP,
                           groupInfo.authority, groupInfo.guid, groupInfo.name, groupInfo.desc, update);
    storageMutex.Unlock(__FILE__, __LINE__);
    return funcStatus;
}

QStatus SQLStorage::RemoveGroup(const GroupInfo& groupInfo)
{
    QStatus funcStatus = ER_FAIL;
    storageMutex.Lock(__FILE__, __LINE__);

    GroupInfo tmp = groupInfo; // to avoid const cast
    if (ER_OK != (funcStatus = GetGroup(tmp))) {
        QCC_LogError(funcStatus, ("Group does not exist."));
    } else {
        funcStatus = RemoveInfo(INFO_GROUP, groupInfo.authority, groupInfo.guid);
    }

    storageMutex.Unlock(__FILE__, __LINE__);
    return funcStatus;
}

QStatus SQLStorage::GetGroup(GroupInfo& groupInfo) const
{
    QStatus funcStatus = ER_FAIL;
    storageMutex.Lock(__FILE__, __LINE__);

    funcStatus =
        GetInfo(INFO_GROUP, groupInfo.authority, groupInfo.guid, groupInfo.name, groupInfo.desc);

    storageMutex.Unlock(__FILE__, __LINE__);
    return funcStatus;
}

QStatus SQLStorage::GetGroups(std::vector<GroupInfo>& groupsInfo) const
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;

    sqlStmtText = "SELECT NAME, DESC, AUTHORITY, LENGTH(AUTHORITY), ID FROM ";
    sqlStmtText.append(GROUPS_TABLE_NAME);

    /* Prepare the sql query */
    sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(), -1,
                                    &statement, NULL);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    /* Iterate over all the rows in the query */
    while (SQLITE_ROW == (sqlRetCode = sqlite3_step(statement))) {
        GroupInfo info;

        info.name.assign((const char*)sqlite3_column_text(statement, 0));
        info.desc.assign((const char*)sqlite3_column_text(statement, 1));
        funcStatus = info.authority.Import((const uint8_t*)sqlite3_column_blob(statement, 2),
                                           sqlite3_column_int(statement, 3));
        if (ER_OK != funcStatus) {
            QCC_LogError(funcStatus, ("Failed to import auth Info %i", sqlite3_column_int(statement, 3)));
            break;
        }
        info.guid = qcc::GUID128((const char*)sqlite3_column_text(statement, 4));

        groupsInfo.push_back(info);
    }

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::StoreIdentity(const IdentityInfo& idInfo)
{
    QStatus funcStatus = ER_FAIL;
    storageMutex.Lock(__FILE__, __LINE__);

    bool update;
    IdentityInfo tmp = idInfo; // to avoid const cast
    funcStatus = GetIdentity(tmp);
    if (ER_OK == funcStatus) {
        update = true;
    } else if (ER_END_OF_DATA == funcStatus) {
        update = false;
    } else {
        QCC_LogError(funcStatus, ("Could not determine update status for identity."));
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    qcc::String desc; // placeholder
    funcStatus = StoreInfo(INFO_IDENTITY, idInfo.authority, idInfo.guid, idInfo.name, desc, update);
    storageMutex.Unlock(__FILE__, __LINE__);
    return funcStatus;
}

QStatus SQLStorage::RemoveIdentity(const IdentityInfo& idInfo)
{
    QStatus funcStatus = ER_FAIL;
    storageMutex.Lock(__FILE__, __LINE__);

    IdentityInfo tmp = idInfo; // to avoid const cast
    if (ER_OK != (funcStatus = GetIdentity(tmp))) {
        QCC_LogError(funcStatus, ("Identity does not exist."));
    } else {
        funcStatus = RemoveInfo(INFO_IDENTITY, idInfo.authority, idInfo.guid);
    }

    storageMutex.Unlock(__FILE__, __LINE__);
    return funcStatus;
}

QStatus SQLStorage::GetIdentity(IdentityInfo& idInfo) const
{
    QStatus funcStatus = ER_FAIL;
    storageMutex.Lock(__FILE__, __LINE__);

    qcc::String desc; // placeholder
    funcStatus = GetInfo(INFO_IDENTITY, idInfo.authority, idInfo.guid, idInfo.name, desc);

    storageMutex.Unlock(__FILE__, __LINE__);
    return funcStatus;
}

QStatus SQLStorage::GetIdentities(std::vector<IdentityInfo>& idInfos) const
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;

    sqlStmtText = "SELECT NAME, AUTHORITY, LENGTH(AUTHORITY), ID FROM ";
    sqlStmtText.append(IDENTITY_TABLE_NAME);

    /* Prepare the sql query */
    sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(), -1,
                                    &statement, NULL);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    /* Iterate over all the rows in the query */
    KeyInfoNISTP256 authority;
    while (SQLITE_ROW == (sqlRetCode = sqlite3_step(statement))) {
        IdentityInfo info;

        info.name.assign((const char*)sqlite3_column_text(statement, 0));
        funcStatus = authority.Import((const uint8_t*)sqlite3_column_blob(statement, 1),
                                      sqlite3_column_int(statement, 2));
        if (ER_OK != funcStatus) {
            break;
        }
        info.authority = authority;
        info.guid = qcc::GUID128((const char*)sqlite3_column_text(statement, 3));

        idInfos.push_back(info);
    }

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

void SQLStorage::Reset()
{
    storageMutex.Lock(__FILE__, __LINE__);
    sqlite3_close(nativeStorageDB);
    remove(GetStoragePath().c_str());
    storageMutex.Unlock(__FILE__, __LINE__);
}

SQLStorage::~SQLStorage()
{
    storageMutex.Lock(__FILE__, __LINE__);
    int sqlRetCode;
    if ((sqlRetCode = sqlite3_close(nativeStorageDB)) != SQLITE_OK) { //TODO :: change to sqlite3_close_v2 once Jenkins machines allow for it
        LOGSQLERROR(ER_FAIL);
    }
    storageMutex.Unlock(__FILE__, __LINE__);
}

/*************************************************PRIVATE*********************************************************/

QStatus SQLStorage::BindCertForStorage(qcc::CertificateX509& cert,
                                       const char* sqlStmtText, sqlite3_stmt*
                                       * statement)
{
    int sqlRetCode = SQLITE_OK;                                        // Equal zero
    QStatus funcStatus = ER_OK;
    int column = 1;

    do {
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText, -1,
                                        statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            break;
        }

        /*********************Common to all certificates*****************/
        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t size = sizeof(publicKey);
        funcStatus = cert.GetSubjectPublicKey()->Export(publicKey, &size);
        if (funcStatus != ER_OK) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }

        sqlRetCode = sqlite3_bind_blob(*statement, column,
                                       publicKey, sizeof(publicKey),
                                       SQLITE_TRANSIENT);

        qcc::String aki = cert.GetAuthorityKeyId();

        sqlRetCode |= sqlite3_bind_blob(*statement, ++column,
                                        aki.data(),
                                        aki.size(),
                                        SQLITE_TRANSIENT);

        const uint8_t* encodedCert = cert.GetEncoded();
        if (encodedCert != NULL) {
            sqlRetCode |= sqlite3_bind_blob(*statement, ++column,
                                            encodedCert,
                                            cert.GetEncodedLen(),
                                            SQLITE_TRANSIENT);
        } else {
            funcStatus = ER_FAIL;
            break;
        }

        /****************************************************************/

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            break;
        }

        switch (cert.GetType()) {
        case qcc::CertificateX509::IDENTITY_CERTIFICATE: {
                const qcc::IdentityCertificate& idCert =
                    dynamic_cast<const qcc::IdentityCertificate&>(cert);
                sqlRetCode |= sqlite3_bind_text(*statement, ++column,
                                                idCert.GetAlias().c_str(), -1,
                                                SQLITE_TRANSIENT);

                if (SQLITE_OK != sqlRetCode) {
                    funcStatus = ER_FAIL;
                }
            }
            break;

        case qcc::CertificateX509::MEMBERSHIP_CERTIFICATE: {
                qcc::CertificateX509& c = const_cast<qcc::CertificateX509&>(cert);
                qcc::MembershipCertificate& memCert = dynamic_cast<qcc::MembershipCertificate&>(c);
                sqlRetCode |= sqlite3_bind_text(*statement, ++column,
                                                memCert.GetGuild().ToString().c_str(), -1,
                                                SQLITE_TRANSIENT);

                if (SQLITE_OK != sqlRetCode) {
                    funcStatus = ER_FAIL;
                }
            }
            break;

        default: {
                QCC_LogError(ER_FAIL, ("Unsupported certificate type !"));
                return ER_FAIL;
            }
        }
    } while (0);

    if (ER_OK != funcStatus) {
        LOGSQLERROR(funcStatus);
    }

    return funcStatus;
}

QStatus SQLStorage::StepAndFinalizeSqlStmt(sqlite3_stmt* statement) const
{
    int sqlRetCode = SQLITE_OK;
    QStatus funcStatus = ER_OK;

    if (NULL == statement) {
        QCC_LogError(ER_FAIL, ("NULL statement argument"));
        return ER_FAIL;
    }

    sqlRetCode = sqlite3_step(statement);

    if (SQLITE_DONE != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    if (ER_OK != funcStatus) {
        LOGSQLERROR(funcStatus);
    }

    return funcStatus;
}

qcc::String SQLStorage::GetStoragePath() const
{
    qcc::String pathkey(STORAGE_FILEPATH_KEY);
    qcc::String storagePath;
    std::map<qcc::String, qcc::String>::const_iterator pathItr =
        storageConfig.settings.find(pathkey);
    if (pathItr != storageConfig.settings.end()) {
        storagePath = pathItr->second;
    }

    return storagePath;
}

QStatus SQLStorage::Init()
{
    int sqlRetCode = SQLITE_OK;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;

    do {
        if (SQLITE_OK != (sqlRetCode = sqlite3_shutdown())) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            QCC_DbgHLPrintf(("Failed in shutting down sqlite in preparation for initialization !!"));
            break;
        }

        if (sqlite3_threadsafe() == 0) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            QCC_DbgHLPrintf(("Sqlite was compiled NOT to be thread-safe !!"));
            break;
        }

        if (SQLITE_OK != (sqlRetCode = sqlite3_config(SQLITE_CONFIG_SERIALIZED))) {
            funcStatus = ER_FAIL;
            QCC_DbgHLPrintf(("Serialize failed with %d", sqlRetCode));
            LOGSQLERROR(funcStatus);
            break;
        }

        if (SQLITE_OK != (sqlRetCode = sqlite3_initialize())) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            QCC_DbgHLPrintf(("Failed in sqlite initialization !!"));
            break;
        }

        qcc::String storagePath = GetStoragePath();
        if (storagePath.empty()) {
            funcStatus = ER_FAIL;
            QCC_DbgHLPrintf(("Invalid path to be used for storage !!"));
            break;
        }
        sqlRetCode = sqlite3_open(storagePath.c_str(), &nativeStorageDB);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            sqlite3_close(nativeStorageDB);
            break;
        }

        sqlStmtText = CLAIMED_APPLICATIONS_TABLE_SCHEMA;
        sqlStmtText.append(IDENTITY_CERTS_TABLE_SCHEMA);
        sqlStmtText.append(MEMBERSHIP_CERTS_TABLE_SCHEMA);
        sqlStmtText.append(GROUPS_TABLE_SCHEMA);
        sqlStmtText.append(IDENTITY_TABLE_SCHEMA);
        sqlStmtText.append(SERIALNUMBER_TABLE_SCHEMA);
        sqlStmtText.append(DEFAULT_PRAGMAS);

        sqlRetCode = sqlite3_exec(nativeStorageDB, sqlStmtText.c_str(), NULL, 0,
                                  NULL);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
        funcStatus = InitSerialNumber();
    } while (0);

    return funcStatus;
}

QStatus SQLStorage::StoreInfo(InfoType type,
                              const qcc::KeyInfoNISTP256& auth,
                              const GUID128& guid,
                              const qcc::String& name,
                              const qcc::String& desc,
                              bool update)
{
    size_t authoritySize;
    uint8_t* authority = NULL;
    QStatus funcStatus = ExportKeyInfo(auth, &authority, authoritySize);
    if (funcStatus != ER_OK) {
        return funcStatus;
    }

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement;

    qcc::String sqlStmtText;
    if (update) {
        sqlStmtText = "UPDATE ";
        sqlStmtText.append(type == INFO_GROUP ? GROUPS_TABLE_NAME : IDENTITY_TABLE_NAME);
        sqlStmtText.append(" SET NAME = ?");
        if (type == INFO_GROUP) {
            sqlStmtText.append(", DESC = ?");
        }
        sqlStmtText.append(" WHERE AUTHORITY = ? AND ID LIKE ?");
    } else {
        sqlStmtText = "INSERT INTO ";
        sqlStmtText.append(type == INFO_GROUP ? GROUPS_TABLE_NAME : IDENTITY_TABLE_NAME);
        sqlStmtText.append(" (NAME, ");
        if (type == INFO_GROUP) {
            sqlStmtText.append("DESC, ");
        }
        sqlStmtText.append("AUTHORITY, ID) VALUES (?, ?, ?");
        if (type == INFO_GROUP) {
            sqlStmtText.append(", ?");
        }
        sqlStmtText.append(")");
    }

    do {
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        int i = 1;
        sqlRetCode |= sqlite3_bind_text(statement, i++, name.c_str(), -1, SQLITE_TRANSIENT);
        if (type == INFO_GROUP) {
            sqlRetCode |= sqlite3_bind_text(statement, i++, desc.c_str(), -1, SQLITE_TRANSIENT);
        }
        sqlRetCode |= sqlite3_bind_blob(statement, i++, authority, authoritySize, SQLITE_TRANSIENT);
        sqlRetCode |= sqlite3_bind_text(statement, i++, guid.ToString().c_str(), -1, SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    funcStatus = StepAndFinalizeSqlStmt(statement);
    delete[] authority;

    return funcStatus;
}

QStatus SQLStorage::GetInfo(InfoType type,
                            const qcc::KeyInfoNISTP256& auth,
                            const GUID128& guid,
                            qcc::String& name,
                            qcc::String& desc) const
{
    QStatus funcStatus = ER_FAIL;

    if (auth.empty()) {
        funcStatus = ER_FAIL;
        QCC_LogError(funcStatus, ("Empty authority!"));
        return funcStatus;
    }

    if (guid.ToString().empty()) {
        funcStatus = ER_FAIL;
        QCC_LogError(funcStatus, ("Empty GUID!"));
        return funcStatus;
    }

    size_t authoritySize;
    uint8_t* authority = NULL;
    funcStatus = ExportKeyInfo(auth, &authority, authoritySize);
    if (funcStatus != ER_OK) {
        return funcStatus;
    }

    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    int sqlRetCode = SQLITE_OK;

    sqlStmtText = "SELECT NAME";
    if (type == INFO_GROUP) {
        sqlStmtText.append(", DESC");
    }
    sqlStmtText.append(" FROM ");
    sqlStmtText.append(type == INFO_GROUP ? GROUPS_TABLE_NAME : IDENTITY_TABLE_NAME);
    sqlStmtText.append(" WHERE AUTHORITY = ? AND ID LIKE ?");
    do {
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        sqlRetCode |= sqlite3_bind_blob(statement, 1, authority, authoritySize, SQLITE_TRANSIENT);
        sqlRetCode |= sqlite3_bind_text(statement, 2, guid.ToString().c_str(), -1, SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        sqlRetCode = sqlite3_step(statement);
        if (SQLITE_ROW == sqlRetCode) {
            name.assign((const char*)sqlite3_column_text(statement, 0));
            if (type == INFO_GROUP) {
                desc.assign((const char*)sqlite3_column_text(statement, 1));
            }
        } else if (SQLITE_DONE == sqlRetCode) {
            funcStatus = ER_END_OF_DATA;
            break;
        } else {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }
    delete[] authority;
    return funcStatus;
}

QStatus SQLStorage::ExportKeyInfo(const qcc::KeyInfoNISTP256& auth, uint8_t** data, size_t& authoritySize)
{
    authoritySize = auth.GetExportSize();
    uint8_t* authority = new uint8_t[authoritySize];
    if (authority == NULL) {
        return ER_OUT_OF_MEMORY;
    }

    QStatus funcStatus = auth.Export(authority);
    if (funcStatus != ER_OK) {
        QCC_LogError(funcStatus, ("Failed to export authority"));
        delete[] authority;
        return funcStatus;
    }
    *data = authority;
    return ER_OK;
}

QStatus SQLStorage::RemoveInfo(InfoType type,
                               const qcc::KeyInfoNISTP256& auth,
                               const qcc::GUID128& guid)
{
    size_t authoritySize;
    uint8_t* authority = NULL;
    QStatus funcStatus = ExportKeyInfo(auth, &authority, authoritySize);
    if (funcStatus != ER_OK) {
        return funcStatus;
    }

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement;

    qcc::String sqlStmtText = "DELETE FROM ";
    sqlStmtText.append(type == INFO_GROUP ? GROUPS_TABLE_NAME : IDENTITY_TABLE_NAME);
    sqlStmtText.append(" WHERE AUTHORITY = ? AND ID LIKE ?");

    do {
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        sqlRetCode |= sqlite3_bind_blob(statement, 1, authority,
                                        authoritySize, SQLITE_TRANSIENT);
        sqlRetCode |= sqlite3_bind_text(statement, 2, guid.ToString().c_str(),
                                        -1, SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    funcStatus = StepAndFinalizeSqlStmt(statement);
    delete[] authority;
    return funcStatus;
}

QStatus SQLStorage::GetPolicyOrManifest(const Application& app,
                                        const char* type,
                                        uint8_t** byteArray,
                                        size_t* size) const
{
    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_FAIL;

    *size = 0;
    *byteArray = nullptr;

    if ((strcmp(type, "MANIFEST") != 0) &&  (strcmp(type, "POLICY") != 0)) {
        QCC_LogError(funcStatus, ("Invalid field type to retrieve!"));
        return funcStatus;
    }

    do {
        sqlStmtText = "SELECT ";
        sqlStmtText += type;
        sqlStmtText += ", LENGTH(" + qcc::String(type) + ")";
        sqlStmtText += (" FROM ");
        sqlStmtText += CLAIMED_APPS_TABLE_NAME;
        sqlStmtText += " WHERE APPLICATION_PUBKEY LIKE ?";

        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t pubKeySize = sizeof(publicKey);
        funcStatus = app.publicKey.Export(publicKey, &pubKeySize);
        if (funcStatus != ER_OK || (pubKeySize != qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ)) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }
        sqlRetCode = sqlite3_bind_blob(statement, 1, publicKey,
                                       qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ, SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
        sqlRetCode = sqlite3_step(statement);
        if (SQLITE_ROW == sqlRetCode) {
            *size = sqlite3_column_int(statement, 1);
            if (*size > 0) {
                *byteArray = new uint8_t[*size];
                memcpy(*byteArray, (const uint8_t*)sqlite3_column_blob(statement, 0), *size);
            } else {
                funcStatus = ER_END_OF_DATA;
                QCC_LogError(funcStatus, ("Application has no %s !", type));
                break;
            }
        } else if (SQLITE_DONE == sqlRetCode) {
            QCC_DbgHLPrintf(("No managed application was found !"));
            funcStatus = ER_END_OF_DATA;
            break;
        } else {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    sqlRetCode = sqlite3_finalize(statement);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    return funcStatus;
}

QStatus SQLStorage::StorePolicyOrManifest(const Application& app,  const uint8_t* byteArray,
                                          const size_t size, const char* type)
{
    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    QStatus funcStatus = ER_FAIL;
    qcc::String sqlStmtText;

    sqlStmtText = "UPDATE ";
    sqlStmtText.append(CLAIMED_APPS_TABLE_NAME);

    do {
        if (strcmp(type, "MANIFEST") == 0) {
            sqlStmtText.append(" SET MANIFEST = ? ");
        } else if (strcmp(type, "POLICY") == 0) {
            sqlStmtText.append(" SET POLICY = ? ");
        } else {
            funcStatus = ER_FAIL;
            QCC_LogError(funcStatus, ("Invalid field type to store!"));
            break;
        }

        sqlStmtText.append("WHERE APPLICATION_PUBKEY = ?");

        if (app.aki.empty()) {
            funcStatus = ER_FAIL;
            QCC_LogError(funcStatus, ("Empty peer ID !"));
            break;
        }

        uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
        size_t pubKeySize = sizeof(publicKey);
        funcStatus = app.publicKey.Export(publicKey, &pubKeySize);
        if (funcStatus != ER_OK || (pubKeySize != qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ)) {
            QCC_LogError(funcStatus, ("Failed to export public key"));
            break;
        }

        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }

        sqlRetCode |= sqlite3_bind_blob(statement, 1, byteArray, size, SQLITE_TRANSIENT);

        sqlRetCode = sqlite3_bind_blob(statement, 2,
                                       publicKey, qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ,
                                       SQLITE_TRANSIENT);

        if (SQLITE_OK != sqlRetCode) {
            funcStatus = ER_FAIL;
            LOGSQLERROR(funcStatus);
            break;
        }
    } while (0);

    funcStatus = StepAndFinalizeSqlStmt(statement);

    return funcStatus;
}

QStatus SQLStorage::InitSerialNumber()
{
    storageMutex.Lock(__FILE__, __LINE__);

    int sqlRetCode = SQLITE_OK;
    sqlite3_stmt* statement = NULL;
    qcc::String sqlStmtText = "";
    QStatus funcStatus = ER_OK;

    sqlStmtText = "SELECT VALUE FROM ";
    sqlStmtText.append(SERIALNUMBER_TABLE_NAME);

    /* prepare the sql query */
    sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(), -1,
                                    &statement, NULL);
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
        storageMutex.Unlock(__FILE__, __LINE__);
        return funcStatus;
    }

    if (SQLITE_ROW == (sqlRetCode = sqlite3_step(statement))) {
        sqlRetCode = sqlite3_finalize(statement);
    } else if (SQLITE_DONE == sqlRetCode) {
        //insert a single entry with the initial serial number.
        sqlRetCode = sqlite3_finalize(statement);
        sqlStmtText = "INSERT INTO ";
        sqlStmtText.append(SERIALNUMBER_TABLE_NAME);
        sqlStmtText.append(" (VALUE) VALUES (?)");
        statement = NULL;
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, &statement, NULL);
        sqlRetCode |= sqlite3_bind_int(statement, 1, INITIAL_SERIAL_NUMBER);
        funcStatus = StepAndFinalizeSqlStmt(statement);
    }
    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    storageMutex.Unlock(__FILE__, __LINE__);

    return funcStatus;
}

QStatus SQLStorage::GetCertificateFromRow(sqlite3_stmt** statement,
                                          qcc::CertificateX509& cert,
                                          const qcc::String tableName,
                                          Keys keys) const
{
    ECCPublicKey subject;
    QStatus funcStatus = subject.Import((const uint8_t*)sqlite3_column_blob(*statement, 0),
                                        qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ);
    if (ER_OK != funcStatus) {
        return funcStatus;
    }
    keys.appECCPublicKey = &subject;

    int derColumn = 2;
    int derSizeColumn = derColumn + 2;
    size_t size = sqlite3_column_int(*statement, derSizeColumn);

    funcStatus = cert.LoadEncoded((const uint8_t*)sqlite3_column_blob(*statement, derColumn), size);
    return funcStatus;
}

QStatus SQLStorage::GetCertificateFromRow(sqlite3_stmt** statement, qcc::MembershipCertificate& cert) const
{
    int column = 3;
    Keys keys;
    qcc::String groupID = qcc::String((const char*)sqlite3_column_text(*statement, column));
    cert.SetGuild(GUID128(groupID));
    keys.groupID = &groupID;

    return GetCertificateFromRow(statement, cert, MEMBERSHIP_CERTS_TABLE_NAME, keys);
}

QStatus SQLStorage::PrepareCertificateQuery(const qcc::MembershipCertificate& certificate,
                                            sqlite3_stmt** statement) const
{
    QStatus funcStatus = ER_OK;
    int sqlRetCode = SQLITE_OK;

    qcc::MembershipCertificate& cert = const_cast<qcc::MembershipCertificate&>(certificate);
    const qcc::ECCPublicKey* appPubKey = cert.GetSubjectPublicKey();
    qcc::String groupId;
    if (cert.IsGuildSet()) {
        groupId = cert.GetGuild().ToString();
    }

    qcc::String sqlStmtText = "SELECT *, LENGTH(DER) FROM ";
    sqlStmtText += MEMBERSHIP_CERTS_TABLE_NAME;

    if (appPubKey && groupId.empty()) {
        sqlStmtText += " WHERE SUBJECT = ?";
    } else if (appPubKey && (!groupId.empty())) {
        sqlStmtText += " WHERE SUBJECT = ? AND GUID = ? ";
    } else if (!appPubKey && (!groupId.empty())) {
        sqlStmtText += " WHERE GUID = ?";
    }

    do {
        sqlRetCode = sqlite3_prepare_v2(nativeStorageDB, sqlStmtText.c_str(),
                                        -1, statement, NULL);
        if (SQLITE_OK != sqlRetCode) {
            break;
        }

        if (appPubKey) {
            uint8_t publicKey[qcc::ECC_COORDINATE_SZ + qcc::ECC_COORDINATE_SZ];
            size_t size = sizeof(publicKey);
            funcStatus = const_cast<qcc::ECCPublicKey*>(appPubKey)->Export(publicKey, &size);

            if (ER_OK != funcStatus) {
                QCC_LogError(funcStatus, ("Failed to export public key"));
                break;
            }
            sqlRetCode = sqlite3_bind_blob(*statement, 1, publicKey,
                                           sizeof(publicKey), SQLITE_TRANSIENT);
            if (SQLITE_OK != sqlRetCode) {
                break;
            }
        }

        if (!groupId.empty()) {
            sqlRetCode = sqlite3_bind_text(*statement, 2, groupId.c_str(), -1,
                                           SQLITE_TRANSIENT);
        }
    } while (0);

    if (SQLITE_OK != sqlRetCode) {
        funcStatus = ER_FAIL;
        LOGSQLERROR(funcStatus);
    }

    return funcStatus;
}
}
}
#undef QCC_MODULE
