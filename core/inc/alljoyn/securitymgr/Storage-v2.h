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

#ifndef STORAGE_H_
#define STORAGE_H_

#include <alljoyn/securitymgr/IdentityInfo.h>
#include <alljoyn/Status.h>

#include <string>

#include <qcc/CertificateECC.h>
#include <qcc/CryptoECC.h>
#include <alljoyn/PermissionPolicy.h>

#include <vector>

/**
 * Note this is a draft proposal. Some shortcuts are taken:
 *  - One big header file
 *    The final version will define most classes in their own header file
 *  - The utility classes are not yet fully defined. some are even empty.
 *
 *  Terminology:
 *  - There are many security managers, each one of them identified by its CA. The Ca use
 *    linked to Storage the manager agent is using is called the LocalCA.
 */

using namespace ajn;

namespace ajn {
namespace securitymgr {
struct GroupInfo {//rename of existing GuildInfo
    /**
     * \brief The authority of this group. It is the public key of the security
     * manager that created this group. It is part of the composite key of this
     * object.
     */
    qcc::ECCPublicKey authority;
    /**
     * \brief The guid of this group. It is part of the composite key of this
     * object.
     */
    qcc::GUID128 guid;
    /**
     * \brief The name of this group.
     */
    std::string name;
    /**
     * \brief A description for this group.
     */
    std::string desc;

    bool operator==(const GroupInfo& gi) const
    {
        if (authority != gi.authority) {
            return false;
        }

        if (guid != gi.guid) {
            return false;
        }

        return true;
    }

    std::string ToString() const
    {
        std::string s = "GroupInfo:";
        s += "\n  authority: ";
        s += authority.ToString();
        s += "\n  guid: ";
        s += guid.ToString();
        s += "\n  name: " + name + "\n  desc: " + desc + "\n";
        return s;
    }
};

/**
 * A class describing a identity certificate received from another security manager.
 */
class RemoteIdentity {
    /**
     * The CA issusing the certificate.
     */
    const CA& GetCA() const;

    /**
     * The identity certificate issues by the other CA. The subject of this certificate
     * should be the public key of the local CA.
     */
    const IdentityCertificate& GetIdentityCertificate() const;
};

struct ManagedApplicationInfo {
    qcc::ECCPublicKey publicKey;
    std::string userDefinedName;
    std::string deviceName;
    std::string appName;
    std::string peerID;
    bool updatesPending;
    /** A volatile counter referring to the current database state.
     * Every time the configuration of an application changes, this counter will increase */
    uint64_t updateCount;
};

/**
 *
 */
class CA {
  public:
    QStatus GetPublicKey(qcc::ECCPublicKey& caKey) const;

    /**
     * Returns the certificate chains representing the identity of the CA. This can be an
     * empty array if no such certificates are available, a self-signed certificate or
     * a certificate chain if the identity is approved by an external 3rd party.
     *
     * Currently no certificate type is specified for this
     */
    QStatus GetIdentity(std::vector<Certificate>& caIdentityCertificates) const;

    std::string GetName() const;
};

/*
 * A Set of access rules.
 * A wrapper class reusing Rule class as defined in core
 */
class Manifest {
  public:
    const std::vector<const PermissionPolicy::Rule>& GetRules() const;
};

class ACL {
    const std::vector<const PermissionPolicy::Peer>& GetPeers() const;

    const std::vector<const PermissionPolicy::Rule>& GetRules() const;
};

/**
 * A policy template describes the ACLs required to interact with a CA. A template can either
 * be local or remote. A local template contains the ACLs required by the local managed applications
 * to interact with the CA linked to this template. A remote template contains the ACLS the peer CA
 * should add this it policy so that the apps it is managing can talk to the local ones.
 */
class PolicyTemplate {
    const CA& GetCA() const;

    const std::vector<const ACL>& GetACLs() const;

    const bool IsLocalTemplate() const;
};

/**
 * Base certificate class. To be extended as needed.
 */
class Certificate {
  public:
    const qcc::ECCPublicKey& GetSubject() const;

    const qcc::ECCPublicKey& GetIssuer() const;

    const std::string GetSerialNumber() const;

    const std::string GetX509Data(bool pem) const;
};

class MembershipCertificate :
    public Certificate {
};

class IdentityCertificate :
    public Certificate {
};

class MembershipCertificateChain {
    const std::vector<const MembershipCertificate>& GetMembershipCertificates() const;
};

/**
 * Listener class. This allows the agent to register himself to the storage to receive events for pending
 * changes. This callback can be triggered when a commit is done locally or if the storage receives configuration
 * changes via alternative paths (direct accessed by UI, multiple agents, ...).
 */
class StorageListener {
    void OnPendingChanges(std::vector<ManagedApplicationInfo> apps) = 0;

    virtual ~StorageListener();
};
/**
 * \class Storage
 * \brief An abstract class that is meant to define the interfacing with a persistent storage means.
 *
 *  Applications and Groups can be managed persistently through this API.
 *
 */
//TODO do we need a new name?
class Storage {
  public:

    Storage() { }

    //========================================================================
    // Managing of local components
    //========================================================================
    /**
     * \brief Remove the information pertaining to a previously managed application, including
     * its certificates.
     *
     * \param[in] managedApplicationInfo the application info, ONLY the publicKey is mandatory here
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus RemoveApplication(const ManagedApplicationInfo& managedApplicationInfo) = 0;

    /**
     * \brief Retrieve a list of managed applications.
     *
     * \param[in,out] managedApplications a vector of managed applications
     * \param[in] all true for all applications, false only returns applications with pending changes.
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus GetManagedApplications(std::vector<ManagedApplicationInfo>& managedApplications,
                                           bool all = true) const = 0;

    /**
     * \brief Get a managed application if it already exists.
     *
     *
     * \param[in] managedApplicationInfo the managed application info to be filled in. Only the publicKey field is required
     * \param[in, out] managed a boolean stating whether the application is managed or not
     *
     * \retval ER_OK  on success
     * \retval ER_END_OF_DATA if no data is found
     * \retval others on failure
     */
    virtual QStatus GetManagedApplication(ManagedApplicationInfo& managedApplicationInfo) const = 0;

    /**
     * \brief Store a group. If a group with the same keys was stored before,
     * it will be updated.
     *
     * \param[in] groupInfo  the info of a group that needs to be stored;
     *                       both authority and guid must be provided
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus StoreGroup(const GroupInfo& groupInfo) = 0;

    /**
     * \brief Remove a group from storage.
     *
     * \param[in] groupInfo  the info of a group that needs to be removed;
     *                       both authority and guid must be provided
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus RemoveGroup(const GroupInfo& groupInfo) = 0;

    /**
     * \brief Get the stored info for a provided group.
     *
     * \param[in, out] groupInfo  the info of a group that should be retrieved;
     *                            both authority and guid must be provided
     *
     * \retval ER_OK  on success
     * \retval ER_END_OF_DATA if no data is found
     * \retval others on failure
     */
    virtual QStatus GetGroup(GroupInfo& groupInfo) const = 0;

    /**
     * \brief Get all stored group information.
     *
     * \param[in, out] groupInfos  a vector to which any stored group info
     *                             object will be pushed
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus GetGroups(std::vector<GroupInfo>& groupInfos) const = 0;

    /**
     * \brief Store an identity. If an identity with the same keys was stored
     * before, it will be updated.
     *
     * \param[in] idInfo  the info of an identity that needs to be stored;
     *                    both authority and guid must be provided
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus StoreIdentity(const IdentityInfo& idInfo) = 0;

    /**
     * \brief Remove an identity from storage.
     *
     * \param[in] idInfo  the info of an identity that needs to be removed;
     *                    both authority and guid must be provided
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus RemoveIdentity(const IdentityInfo& idInfo) = 0;

    /**
     * \brief Get the stored info for a provided identity.
     *
     * \param[in, out] idInfo  the info of an identity that should be
     *                         retrieved; both authority and guid must be
     *                         provided
     *
     * \retval ER_OK  on success
     * \retval ER_END_OF_DATA if no data is found
     * \retval others on failure
     */
    virtual QStatus GetIdentity(IdentityInfo& idInfo) const = 0;

    /**
     * \brief Get all stored identity information.
     *
     * \param[in, out] idInfos  a vector to which any stored identity info
     *                          object will be pushed
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus GetIdentities(std::vector<IdentityInfo>& idInfos) const = 0;

    //========================================================================
    // Setup of local agent + Ca info
    //========================================================================

    /**
     * Fetches the CA linked to this storage.
     */
    virtual QStatus GetLocalCa(CA& localCa) const = 0;

    /**
     * Gets the security groups marked as admin groups for the local CA.
     */
    virtual QStatus GetAdminGroups(std::vector<GroupInfo>& groupInfos) const = 0;

    //NewApplication should be used to claim self.
    //AddApplicationToGroup to become member of the admin groups
    //GetMemberships to fetch the certificate(s)

    //========================================================================
    //Managing own applications
    //========================================================================

    /**
     * Informs the storage a new application is found and will be claimed.
     * This method is called prior to calling the claim method to actually claim the application.
     *
     * \param[out] idCert the identity certificate for
     */
    virtual QStatus NewApplication(const ManagedApplicationInfo& managedApplicationInfo,
                                   const IdentityInfo& idInfo,
                                   const Manifest mf,
                                   IdentityCertificate& idCert,
                                   bool isLocalAgent = false) = 0;

    /**
     * Call after NewApplication when claim is success, otherwise call Remove application.
     */
    virtual QStatus ApplicationClaimed(const ManagedApplicationInfo& managedApplicationInfo) = 0;

    /**
     * Fetches all Identity certificates known in the system.
     */
    //virtual QStatus GetIdentityCertificates(std::vector<IdentityCertificate>& idCerts) = 0;

    /**
     * Fetches the identity certificate and all delegated Identity certificates for a single ManagedApplication.
     */
    virtual QStatus GetIdentityCertificate(ManagedApplicationInfo& managedApplicationInfo,
                                           std::vector<IdentityCertificate>& idCerts) = 0;

    /** replaces existing certificate with new a one, reusing the existing manifest */
    virtual QStatus UpdateIndentity(ManagedApplicationInfo& managedApplicationInfo,
                                    const IdentityInfo& idInfo) = 0;

    virtual QStatus GetManifest(ManagedApplicationInfo& managedApplicationInfo,
                                Manifest& manifest) = 0;

    virtual QStatus UpdateManifest(ManagedApplicationInfo& managedApplicationInfo,
                                   const Manifest& manifest) = 0;

    virtual QStatus GetPolicy(ManagedApplicationInfo& managedApplicationInfo,
                              PermissionPolicy& policy) = 0;

    virtual QStatus UpdatePolicy(ManagedApplicationInfo& managedApplicationInfo,
                                 const PermissionPolicy& policy) = 0;

    /** Informs the storage that all updates are completed. It is important to provide a ManagedApplicationInfo
     * with a correct updateCount. An error will be reported if new changes were made and more updates are pending.
     */
    virtual QStatus UpdatesCompleted(ManagedApplicationInfo& managedApplicationInfo) = 0;

    /**
     * \brief Store the information pertaining to a managed application.
     *
     * \param[in] managedApplicationInfo the application info
     * \param[in] update a boolean to allow/deny application overwriting
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus StoreApplication(const ManagedApplicationInfo& managedApplicationInfo,
                                     const bool update = false) = 0;

    /**
     * Adding applications to group which is not defined by the localCA will result in a membership certificate
     * chain rather then a single certificate.
     */
    virtual QStatus AddApplicationToGroup(ManagedApplicationInfo& managedApplicationInfo,
                                          GroupInfo& groupInfo) = 0;

    virtual QStatus AddApplicationsToGroups(std::vector<ManagedApplicationInfo>& managedApplications,
                                            std::vector<GroupInfo>& groups) = 0;

    virtual QStatus RemoveApplicationFromGroup(ManagedApplicationInfo& managedApplicationInfo,
                                               GroupInfo& groupInfo) = 0;

    virtual QStatus RemoveApplicationsFromGroups(std::vector<ManagedApplicationInfo>& managedApplications,
                                                 std::vector<GroupInfo>& groups) = 0;

    virtual QStatus GetApplicationsInGroup(std::vector<ManagedApplicationInfo>& managedApplicationInfo,
                                           GroupInfo& groupInfo) = 0;

    virtual QStatus GetGroups(ManagedApplicationInfo& managedApplications,
                              std::vector<GroupInfo>& groups) = 0;

    virtual QStatus GetMemberShips(ManagedApplicationInfo& managedApplications,
                                   std::vector<MembershipCertificateChain>& memberShips) = 0;

    //========================================================================
    //Common inter security manager support
    // see PolicyTemplate doc for diff between local and not local.
    //========================================================================
    virtual QStatus AddLocalPolicyTemplate(const PolicyTemplate& pt) = 0;

    virtual QStatus GetLocalPolicyTemplates(std::vector<PolicyTemplate>& pts) const = 0;

    virtual QStatus GetLocalPolicyTemplate(const CA& ca,
                                           PolicyTemplate& pts) const = 0;

    virtual QStatus RemoveLocalPolicyTemplate(const CA& ca) = 0;

    virtual QStatus AddPolicyTemplate(const PolicyTemplate& pt) = 0;

    virtual QStatus GetPolicyTemplates(std::vector<PolicyTemplate>& pts) const = 0;

    virtual QStatus GetPolicyTemplate(const CA& ca,
                                      PolicyTemplate& pts) const = 0;

    virtual QStatus RemovePolicyTemplate(const CA& ca) = 0;

    //========================================================================
    //Restricted CA support
    //========================================================================
    /**
     * Add the CA to list of restricted CA. Adding the CA doesn't have any impact
     * on the existing policies.
     */
    virtual QStatus AddRestrictedCA(CA& ca) = 0;

    virtual QStatus RemoveRestrictedCA(CA& ca) = 0;

    virtual QStatus GetRestrictedCA(std::vector<CA>& cas) = 0;

    //========================================================================
    //Delegation support
    //========================================================================
    //Common API
    //-------------------------------------------------------------------------
    /** ca can point to a foreign CA to get the list of certificates delegated to it
     * or the local CA to get the delegated certificates it received and can be distributed to our own managed apps.
     */
    virtual QStatus GetCAIdentities(const CA& ca,
                                    std::vector<IdentityCertificate>& idCerts) const = 0;

    virtual QStatus GetCAMemberships(const CA& ca,
                                     std::vector<MembershipCertificate>& membershipCerts) const = 0;

    virtual QStatus RemoveCAIdentity(const CA& ca,
                                     const IdentityCertificate& idCerts) = 0;

    virtual QStatus RemoveCAMembership(const CA& ca,
                                       const MembershipCertificate& membershipCerts) = 0;

    //Handing out delegated certificates
    //-------------------------------------------------------------------------
    /**
     * Generate an identity certificate for the CA.
     */
    virtual QStatus DelegateIdentity(const CA&,
                                     IdentityCertificate& idCert) = 0;

    /**
     * Create a Membership certificate for the CA for the given group. The group must be a local defined group.
     */
    virtual QStatus DelegateMembership(const CA&,
                                       const GroupInfo& group,
                                       MembershipCertificate& membershipCert) = 0;

    //Receiving and delegating certificates
    //-------------------------------------------------------------------------
    virtual QStatus AddLocalCAIdentity(const IdentityCertificate& idCerts,
                                       RemoteIdentity& ri) = 0;

    virtual QStatus AddIndentityToApplication(ManagedApplicationInfo& managedApplicationInfo,
                                              const RemoteIdentity& ri) = 0;

    virtual QStatus RemoveIndentityFromApplication(ManagedApplicationInfo& managedApplicationInfo,
                                                   const RemoteIdentity& ri) = 0;

    virtual QStatus RemoveLocalCAIdentity(const RemoteIdentity& ri) = 0;

    /**
     * Provides the local CA with rights to delegate memberships to the applications it manages.
     * A group will be create to represent this membership. This group will appear in the list of
     * groups retrieved with GetGroup. Applications can be added to this group by calling AddApplicationToGroup
     * or AddApplicationsToGroups.
     */
    virtual QStatus AddLocalCAMembership(const MembershipCertificate& membershipCerts,
                                         GroupInfo& group) = 0;

    virtual QStatus RemoveLocalCAMembership(const GroupInfo& group);

    //========================================================================
    // Transaction support
    //========================================================================
    virtual QStatus StartTransAction() = 0;

    virtual QStatus Commit() = 0;

    virtual void AddStorageListener(const StorageListener* l) = 0;

    virtual void RemoveStorageListener(const StorageListener* l) = 0;

    virtual ~Storage()
    {
    }
};
}
}
#endif /* STORAGE_H_ */
