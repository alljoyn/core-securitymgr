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

#ifndef ALLJOYN_SECMGR_APPLICATION_H_
#define ALLJOYN_SECMGR_APPLICATION_H_

#include <vector>

#include <qcc/GUID.h>
#include <qcc/CryptoECC.h>
#include <qcc/String.h>

#include <alljoyn/PermissionConfigurator.h>

#include <alljoyn/securitymgr/ApplicationState.h>

using namespace qcc;

namespace ajn {
namespace securitymgr {
/*
 * \brief Application represents an application of a compound primary key;
 *        public key and AKI.
 */
struct Application {
  public:

    Application() : updatesPending(false) { }

    /**
     * \brief The public key of the remote application. It is the unique
     * key to identify an application.
     */
    ECCPublicKey publicKey;

    /**
     * \brief Authority Key Identifier (AKI) as per RFC5280, AKI is a standard
     * extension field into the X.509 certificate to identify the public
     * key of the issuer.
     */
    String aki;

    /**
     * \brief Indicates whether there are still changes to the security
     * configuration of the application that are known to the security manager
     * but have not yet been applied to the remote application itself. It is
     * set to true whenever an administrator changes the configuration of
     * an application, and set to false when the configuration of the remote
     * application matches the configuration known to the security manager.
     */
    bool updatesPending;

    bool operator==(const Application& rhs) const
    {
        if ((publicKey != rhs.publicKey) && (aki != rhs.aki)) {
            return false;
        }

        return true;
    }
};

/*
 * \brief OnlineApplication adds the online info as it inherits from Application.
 */
struct OnlineApplication :
    public Application {
    OnlineApplication(PermissionConfigurator::ApplicationState _claimState, qcc::String _busName) : claimState(
            _claimState), busName(_busName) { }

    OnlineApplication() : claimState(PermissionConfigurator::NOT_CLAIMABLE) { }

    /**
     * \brief The claim state of the application. An application can only be
     * claimed if it is in the CLAIMABLE state, and can only be managed by a
     * security manager if it is is in the CLAIMED state.
     */
    PermissionConfigurator::ApplicationState claimState;

    /**
     * \brief The bus name of the running application.
     */
    String busName;

  private:
    OnlineApplication(const Application& app);
    OnlineApplication& operator=(const Application& app);
};
}
}

#endif /* ALLJOYN_SECMGR_APPLICATION_H_ */
