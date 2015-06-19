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

#include "AJNCa.h"
#include "AJNCaStorage.h"

#include <qcc/Debug.h>

#include <alljoyn/securitymgr/CertificateUtil.h>

#include <PermissionMgmtObj.h> // still in alljoyn_core/src!

#define QCC_MODULE "SEGMGR_STORAGE"

using namespace qcc;
using namespace std;

namespace ajn {
namespace securitymgr {
QStatus AJNCaStorage::Init(const string storeName, shared_ptr<SQLStorage>& sqlStorage)
{
    ca = unique_ptr<AJNCa>(new AJNCa());
    QStatus status = ca->Init(storeName);
    if (status != ER_OK) {
        return status;
    }
    sql = sqlStorage;
    return ER_OK;
}

QStatus AJNCaStorage::GetAdminGroup(GroupInfo& adminGroup) const
{
    adminGroup.name = "Admin group";
    adminGroup.guid = GUID128((uint8_t)0xab);
    QStatus status = GetCaPublicKeyInfo(adminGroup.authority);
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to set DSA key on adminGroup"));
    }
    return status;
}

QStatus AJNCaStorage::NewApplication(const Application& app,
                                     const IdentityInfo& idInfo,
                                     const Manifest& mf,
                                     GroupInfo& adminGroup,
                                     IdentityCertificate& idCert)
{
    QStatus status = GetAdminGroup(adminGroup);
    if (status != ER_OK) {
        return status;
    }

    status = GenerateIdentityCertificate(app, idInfo, mf, idCert);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to create IdentityCertificate"));
        return status;
    }

    status =  sql->StoreApplication(app);
    if (ER_OK != status) {
        QCC_LogError(status, ("StoreApplication failed"));
        return status;
    }
    status = sql->StoreCertificate(idCert);
    if (ER_OK !=  status) {
        QCC_LogError(status, ("StoreCertificate failed"));
    } else {
        status = sql->StoreManifest(app, mf);
    }
    if (ER_OK != status) {
        sql->RemoveApplication(app);
    }
    return status;
}

QStatus AJNCaStorage::GetManagedApplications(vector<Application>& apps,
                                             bool all) const
{
    QCC_UNUSED(all);

    //TODO add support for all = false (only apps with pending changes).
    return sql->GetManagedApplications(apps);
}

QStatus AJNCaStorage::GetManagedApplication(Application& app) const
{
    return sql->GetManagedApplication(app);
}

QStatus AJNCaStorage::ApplicationClaimed(Application& app,
                                         QStatus status)
{
    if (status != ER_OK) {
        status = sql->RemoveApplication(app);
    } else {
        //TODO mark app as claimed
    }
    return status;
}

QStatus AJNCaStorage::UpdatesCompleted(Application& app)
{
    //TODO.: check if app contains the latest state.
    return handler->UpdatesCompleted(app);
}

QStatus AJNCaStorage::RegisterAgent(const SecurityAgentIdentityInfo& agentIdentity,
                                    const ECCPublicKey& agentKey,
                                    const Manifest& mf,
                                    GroupInfo& adminGroup,
                                    vector<IdentityCertificate>& idCertificates,
                                    vector<MembershipCertificateChain>& adminGroupMemberships)
{
    QCC_UNUSED(agentIdentity);
    QStatus status = GetAdminGroup(adminGroup);
    if (status != ER_OK) {
        return status;
    }

    Application agentInfo;
    if (agentKey.empty()) {
        QCC_LogError(status, ("Bad Name: key empty ? %i", agentKey.empty()));
        return ER_FAIL;
    }
    agentInfo.publicKey = agentKey;
    CertificateX509::GenerateAuthorityKeyId(&agentKey, agentInfo.aki);

    MembershipCertificate memberShip;
    GenerateMembershipCertificate(agentInfo, adminGroup, memberShip);
    MembershipCertificateChain chain(memberShip);
    adminGroupMemberships.push_back(chain);

    IdentityInfo agentID;
    agentID.name = "Admin";
    agentID.guid = GUID128(0xab);
    IdentityCertificate idCert;
    status = GenerateIdentityCertificate(agentInfo, agentID, mf, idCert);
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to generate identity certificate for agent"));
        return status;
    }
    idCertificates.push_back(idCert);
    return ER_OK;
}

QStatus AJNCaStorage::SignCertifcate(CertificateX509& certificate) const
{
    if (certificate.GetSerial().size() == 0) {
        qcc::String serialNr;     //TODO replace with std::string.
        sql->GetNewSerialNumber(serialNr);
        certificate.SetSerial(serialNr);
    }
    //TODO: check all status return values where needed.
    KeyInfoNISTP256 caInfo;
    GetCaPublicKeyInfo(caInfo);
    certificate.SetIssuerCN(caInfo.GetKeyId(), caInfo.GetKeyIdLen());
    ECCPrivateKey epk;
    QStatus status = ca->GetDSAPrivateKey(epk);
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to load key"));
        return status;
    }
    status = certificate.SignAndGenerateAuthorityKeyId(&epk, caInfo.GetPublicKey());
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to sign certificate"));
    }
    return status;
}

QStatus AJNCaStorage::GenerateIdentityCertificate(const Application& app,
                                                  const IdentityInfo& idInfo,
                                                  const Manifest& mf,
                                                  IdentityCertificate& idCertificate)
{
    QStatus status = CertificateUtil::ToIdentityCertificate(app, idInfo, 3600 * 24 * 10 * 365, idCertificate);
    if (status != ER_OK) {
        return status;
    }
    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    mf.GetDigest(digest);
    idCertificate.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);
    return SignCertifcate(idCertificate);
}

QStatus AJNCaStorage::GenerateMembershipCertificate(const Application& app,
                                                    const GroupInfo& groupInfo, MembershipCertificate& memberShip)
{
    QStatus status = CertificateUtil::ToMembershipCertificate(app, groupInfo, 3600 * 24 * 10 * 365, memberShip);
    if (status != ER_OK) {
        return status;
    }
    return SignCertifcate(memberShip);
}

QStatus AJNCaStorage::GetCaPublicKeyInfo(KeyInfoNISTP256& CAKeyInfo) const
{
    ECCPublicKey key;
    QStatus status = ca->GetDSAPublicKey(key);
    if (status != ER_OK || key.empty()) {
        return status == ER_OK ? ER_BUS_KEY_UNAVAILABLE : status;
    }
    CAKeyInfo.SetPublicKey(&key);
    qcc::String id;
    status = CertificateX509::GenerateAuthorityKeyId(&key, id);
    if (status != ER_OK) {
        return status;
    }
    CAKeyInfo.SetKeyId((uint8_t*)id.data(), id.size());
    return ER_OK;
}

QStatus AJNCaStorage::GetMembershipCertificates(const Application& app,
                                                vector<qcc::MembershipCertificate>& membershipCertificates) const
{
    MembershipCertificate cert;
    cert.SetSubjectPublicKey(&app.publicKey);
    QStatus status = sql->GetCertificates(cert, membershipCertificates);
    if (ER_OK == status) {
        for (size_t i = 0; i < membershipCertificates.size(); i++) {
            SignCertifcate(membershipCertificates[i]);
        }
    }
    return status;
}

QStatus AJNCaStorage::GetIdentityCertificateAndManifest(const Application& app,
                                                        qcc::IdentityCertificate& persistedIdCert, Manifest& mf) const
{
    Application _app(app);
    QStatus status = GetManagedApplication(_app);
    if (ER_OK != status) {
        return status;
    }
    persistedIdCert.SetSubjectPublicKey(&app.publicKey);
    status = sql->GetCertificate(persistedIdCert);
    if (ER_OK != status) {
        return status;
    }
    return sql->GetManifest(app, mf);
}

QStatus AJNCaStorage::GetPolicy(const Application& app, PermissionPolicy& policy) const
{
    Application _app(app);
    QStatus status = GetManagedApplication(_app);
    if (ER_OK != status) {
        return status;
    }
    return sql->GetPolicy(app, policy);
}
}
}
#undef QCC_MODULE
