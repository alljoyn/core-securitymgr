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

#ifndef ALLJOYN_SECMGR_CASTORAGE_H_
#define ALLJOYN_SECMGR_CASTORAGE_H_

#include <string>
#include <vector>

#include <qcc/CryptoECC.h>
#include <qcc/Crypto.h>

#include <alljoyn/Status.h>

#include <alljoyn/securitymgr/SecurityAgentIdentityInfo.h>
#include <alljoyn/securitymgr/Application.h>
#include <alljoyn/securitymgr/IdentityInfo.h>
#include <alljoyn/securitymgr/GroupInfo.h>
#include <alljoyn/securitymgr/Manifest.h>

using namespace std;
using namespace qcc;

namespace ajn {
namespace securitymgr {
/**
 * Listener class. This allows the agent to register himself to the storage to receive events for pending
 * changes. This callback can be triggered when a commit is done locally or if the storage receives configuration
 * changes via alternative paths (direct accessed by UI, multiple agents, ...).
 */
class StorageListener {
  public:
    virtual void OnPendingChanges(std::vector<Application>& apps) = 0;

    virtual void OnPendingChangesCompleted(std::vector<Application>& apps) = 0;

    virtual ~StorageListener() { }
};

class MembershipCertificateChain {
  public:
    MembershipCertificateChain() { }

    MembershipCertificateChain(const MembershipCertificate& certificate)
    {
        certificates.push_back(certificate);
    }

    MembershipCertificateChain(const MembershipCertificateChain& otherChain)
    {
        certificates = otherChain.certificates;
    }

    MembershipCertificateChain& operator=(const MembershipCertificateChain& other)
    {
        if (this != &other) {
            certificates = other.certificates;
        }
        return *this;
    }

    const vector<MembershipCertificate>& GetMembershipCertificates() const
    {
        return certificates;
    }

  private:
    vector<MembershipCertificate> certificates;
};

class CaStorage {
  public:
    CaStorage() { }

    virtual ~CaStorage() { }

    /**
     * \brief Retrieve a list of managed applications.
     *
     * \param[in,out] apps a vector of managed applications
     * \param[in] all true for all applications, false only returns applications with pending changes.
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus GetManagedApplications(vector<Application>& apps,
                                           bool all = true) const = 0;

    virtual QStatus GetManagedApplication(Application& app) const = 0;

    virtual QStatus RegisterAgent(const SecurityAgentIdentityInfo& agentIdentity,
                                  const ECCPublicKey& agentKey,
                                  const Manifest& mf,
                                  GroupInfo& adminGroup,
                                  vector<IdentityCertificate>& idCertificates,
                                  vector<MembershipCertificateChain>& adminGroupMemberships) = 0;

    /**
     * Informs the storage a new application is found and will be claimed.
     * This method is called prior to calling the claim method to actually claim the application.
     *
     * \param[out] idCert the identity certificate for
     */
    virtual QStatus NewApplication(const Application& app,
                                   const IdentityInfo& idInfo,
                                   const Manifest& mf,
                                   GroupInfo& adminGroup,
                                   IdentityCertificate& idCert) = 0;

    virtual QStatus ApplicationClaimed(Application& app,
                                       QStatus status) = 0;

    virtual QStatus UpdatesCompleted(Application& app) = 0;

    virtual QStatus GetCaPublicKeyInfo(qcc::KeyInfoNISTP256& CAKeyInfo) const = 0;

    vector<qcc::MembershipCertificate> localCerts;

    //TODO: transform into MembershipCertificate chains.
    virtual QStatus GetMembershipCertificates(const Application& app,
                                              vector<qcc::MembershipCertificate>& membershipCertificates) const = 0;

    //TODO: replace with id cert list.
    virtual QStatus GetIdentityCertificateAndManifest(const Application& app,
                                                      qcc::IdentityCertificate& persistedIdCert,
                                                      Manifest& mf) const = 0;

    virtual QStatus GetPolicy(const Application& app,
                              PermissionPolicy& policy) const = 0;

    virtual void RegisterStorageListener(StorageListener* listener) = 0;

    virtual void UnRegisterStorageListener(StorageListener* listener) = 0;

  private:
};
}
}

#endif /* ALLJOYN_SECMGR_CASTORAGE_H_ */
