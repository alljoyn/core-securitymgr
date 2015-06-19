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

#ifndef APPLICATIONMETADATA_H_
#define APPLICATIONMETADATA_H_

/*
 * \brief ApplicationMetaData should include extra information that could be fetched from About.
 */
struct ApplicationMetaData {
    qcc::String userDefinedName;
    qcc::String deviceName;
    qcc::String appName;

    bool operator==(const ApplicationMetaData& rhs) const
    {
        if (userDefinedName != rhs.userDefinedName) {
            return false;
        }
        if (deviceName != rhs.deviceName) {
            return false;
        }
        if (appName != rhs.appName) {
            return false;
        }

        return true;
    }
};

#endif /* APPLICATIONMETADATA_H_ */
