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

#ifndef ALLJOYN_SECMGR_MANIFEST_H_
#define ALLJOYN_SECMGR_MANIFEST_H_

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Status.h>
#include <qcc/Crypto.h>

#include <stdint.h>

using namespace std;
using namespace qcc;

namespace ajn {
namespace securitymgr {
/* \class Manifest
 * \brief A class that encapsulates manifest's byte data and the
 *        corresponding rules as well as the digest.
 *        A manifest object is always complete; the manifest is
 *        always matching the byte array representation.
 *        It uses the static Util class to achieve the needed
 *        serialization and de-serialization.
 */
class Manifest {
  public:

    Manifest();

    Manifest(const Manifest&);

    ~Manifest();

    /*\brief Construct manifest from a byte array.
     *
     * \param[in] manifestByteArray   A byte array representing a manifest.
     * \param[in] size                 Size of manifestByteArray.
     */
    Manifest(const uint8_t* manifestByteArray,
             const size_t size);

    /*\brief Construct manifest from an array of rules.
     *       The new object does NOT take ownership of the
     *       passed in rules.
     *
     * \param[in] manifestRules         An array of rules
     * \param[in] manifestRulesCount    The count of rules
     */
    Manifest(const PermissionPolicy::Rule* manifestRules,
             const size_t manifestRulesCount);

    /*\brief Retrieves the byte array representing the manifest.
     *
     * \param[in,out] manifestByteArray   A byte array to be filled-in.
     * \param[in,out] size                 Size of manifestByteArray to be filled-in.
     *
     * \return ER_OK          If a byte array can be returned.
     * \return ER_END_OF_DATA In case the manifest is empty.
     */
    QStatus GetByteArray(uint8_t** manifestByteArray,
                         size_t* size) const;

    /*\brief Retrieves the rules representing the manifest.
     *
     * \param[in, out] manifestRules        Pointer to an array of rules that
     *                                      will be newly allocated by this function.
     *                                      Manifest has no ownership on the returned array.
     * \param[in, out] manifestRulesCount   The count of rules that will be set by this function.
     *
     * \return ER_OK          If an array of rules can be returned.
     * \return ER_END_OF_DATA In case there are no rules.
     */
    QStatus GetRules(PermissionPolicy::Rule** manifestRules,
                     size_t* manifestRulesCount) const;

    /*\brief Retrieves the digest representing the manifest.
     *
     * \param[in, out] digest A previously allocated (new) byte array with the correct size.
     *
     * \return ER_OK          If the digest was computed correctly.
     * \return ER_END_OF_DATA In case the manifest is empty.
     * \return others
     */
    QStatus GetDigest(uint8_t* digest) const;

    /*\brief Populates the manifest based on the passed on byte array.
     *
     * \param[in] manifestByteArray   A byte array representing a manifest.
     * \param[in] size                 Size of manifestByteArray.
     *
     * \return ER_OK          If the manifest was populated successfully.
     * \return others
     */
    QStatus SetFromByteArray(const uint8_t* manifestByteArray,
                             const size_t size);

    /*\brief Populates the manifest from an array of rules.
     *       The object does NOT take ownership of the
     *       passed in rules.
     *
     * \param[in] manifestRules         An array of rules
     * \param[in] manifestRulesCount    The count of rules
     *
     * \return ER_OK          If the manifest was populated successfully.
     * \return others
     */
    QStatus SetFromRules(const PermissionPolicy::Rule* manifestRules,
                         const size_t manifestRulesCount);

    Manifest& operator=(const Manifest& rhs);

    bool operator==(const Manifest& other) const;

    bool operator!=(const Manifest& other) const;

  private:

    mutable PermissionPolicy manifest;
    uint8_t* byteArray;
    size_t size;
};
}
}

#endif /* ALLJOYN_SECMGR_MANIFEST_H_ */
