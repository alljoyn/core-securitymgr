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

#ifndef ALLJOYN_SECMGR_STORAGE_UISTORAGE_H_
#define ALLJOYN_SECMGR_STORAGE_UISTORAGE_H_

#include <alljoyn/securitymgr/Application.h>
#include <alljoyn/securitymgr/IdentityInfo.h>
#include <alljoyn/securitymgr/Manifest.h>
#include <alljoyn/securitymgr/GroupInfo.h>
#include <alljoyn/Status.h>

#include <qcc/String.h>
#include <qcc/CertificateECC.h>
#include <qcc/CryptoECC.h>

#include "ApplicationMetaData.h"

#include <vector>

namespace ajn {
namespace securitymgr {
/**
 * \class Storage
 * \brief An abstract class that is meant to define the interfacing with a persistent storage means.
 *
 *  Applications and Groups can be managed persistently through this API.
 *
 */
class UIStorage {
  public:

    virtual QStatus InstallMembership(const Application& app,
                                      const GroupInfo& groupInfo) = 0;

    virtual QStatus RemoveMembership(const Application& app,
                                     const GroupInfo& groupInfo) = 0;

    virtual QStatus UpdatePolicy(Application& app,
                                 PermissionPolicy& policy) = 0;

    virtual QStatus GetPolicy(const Application& app,
                              PermissionPolicy& policy) = 0;

    virtual QStatus UpdateIdentity(Application& app,
                                   const IdentityInfo identityInfo) = 0;

    /**
     * \brief Persist the meta application data relevant to the app passed in.
     *
     * \param[in] app               the application, ONLY the publicKey is mandatory here.
     * \param[in] appMetaData       the meta application data to presist.
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus SetAppMetaData(const Application& app,
                                   const ApplicationMetaData& appMetaData) = 0;

    /**
     * \brief Retrieve the persisted meta application data relevant to the app passed in.
     *
     * \param[in] app               the application, ONLY the publicKey is mandatory here.
     * \param[in, out] appMetaData  the retrieved meta application data.
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus GetAppMetaData(const Application& app,
                                   ApplicationMetaData& appMetaData) const = 0;

    /**
     * \brief Remove a previously managed application, including
     *        its certificates.
     *
     * \param[in] application the application, ONLY the publicKey is mandatory here
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus RemoveApplication(Application& app) = 0;

    /**
     * \brief Retrieve a list of managed applications.
     *
     * \param[in,out] apps a vector of managed applications
     *
     * \retval ER_OK  on success
     * \retval others on failure
     */
    virtual QStatus GetManagedApplications(std::vector<Application>& apps) const = 0;

    /**
     * \brief Get a managed application if it already exists.
     *
     *
     * \param[in] application the managed application to be filled in. Only the publicKey field is required
     *
     * \retval ER_OK  on success
     * \retval ER_END_OF_DATA if no data is found
     * \retval others on failure
     */
    virtual QStatus GetManagedApplication(Application& app) const = 0;

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
    virtual QStatus StoreGroup(GroupInfo& groupInfo) = 0;

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
    virtual QStatus StoreIdentity(IdentityInfo& idInfo) = 0;

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

    virtual QStatus GetManifest(const Application& app,
                                Manifest& manifest) const = 0;

    /**
     * \brief Reset the storage and delete the database.
     */
    virtual void Reset() = 0;

    virtual ~UIStorage()
    {
    }
};
}
}
#endif /* ALLJOYN_SECMGR_STORAGE_UISTORAGE_H_ */
