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

#ifndef ALLJOYN_SECMGR_STORAGE_STORAGEFACTORY_H_
#define ALLJOYN_SECMGR_STORAGE_STORAGEFACTORY_H_

/**
 * \class SQLStorageFactory
 * \brief We need a SQLStorageFactory because at run-time we are not sure which class (derived from Storage) we'll be using.
 *        Every implementation needs to provide their own implementation of this class.
 *
 */

#include <alljoyn/securitymgr/sqlstorage/UIStorage.h>
#include <alljoyn/securitymgr/CaStorage.h>

#include <memory>
#include <string>

namespace ajn {
namespace securitymgr {
class SQLStorageFactory {
  private:
    SQLStorageFactory() { }

    void operator=(SQLStorageFactory const&);

  public:
    /**
     * \brief Get a singleton instance of the storage factory.
     *
     * \retval SQLStorageFactory reference to the singleton storage factory.
     */
    static SQLStorageFactory& GetInstance()
    {
        static SQLStorageFactory sf;
        return sf;
    }

    QStatus GetStorages(std::string caName,
                        shared_ptr<CaStorage>& caStorage,
                        shared_ptr<UIStorage>& storage);
};
}
}
#endif /* ALLJOYN_SECMGR_STORAGE_STORAGEFACTORY_H_ */
