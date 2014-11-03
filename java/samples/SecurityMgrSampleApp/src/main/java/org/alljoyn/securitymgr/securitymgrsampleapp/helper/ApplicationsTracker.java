/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
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

package org.alljoyn.securitymgr.securitymgrsampleapp.helper;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.alljoyn.securitymgr.ApplicationEventListener;
import org.alljoyn.securitymgr.ApplicationInfo;

import android.util.Log;


public class ApplicationsTracker implements ApplicationEventListener
{
    private static final String TAG = "ApplicationsTracker";
    private Map<String, AppInfoItem> appsInfo = new HashMap<>();

    private MyAdapter mAdapter;

    @Override
    public void onApplicationEvent(ApplicationInfo newInfo, ApplicationInfo oldInfo)
    {
        /*
        * Don't care about the old info;
        * Always add/update with the newInfo
        */
        AppInfoItem item = new AppInfoItem(newInfo);
        synchronized (appsInfo) {
            Log.d(TAG, "New App Info: " + newInfo);
            appsInfo.put(newInfo.getApplicationId(), item);
            if (mAdapter != null) {
                mAdapter.addItem(item);
            }
        }
    }

    public void addApplications(Collection<ApplicationInfo> apps)
    {
        for (ApplicationInfo app : apps) {
            onApplicationEvent(app, null);
        }
    }

    public void setAdapter(MyAdapter adapter)
    {
        mAdapter = adapter;
        if (mAdapter != null) {
            //populate
            synchronized (appsInfo) {
                Log.d(TAG, "Setting new adapter, adding " + appsInfo.size() + " items");
                mAdapter.setItems(appsInfo.values());
            }
        }
    }


    /**
     * An item representing an app
     */
    public static class AppInfoItem
    {
        public ApplicationInfo content;

        public AppInfoItem(ApplicationInfo appInfo)
        {
            content = appInfo;
        }

        @Override
        public int hashCode()
        {
            final int prime = 31;
            int result = 1;
            result = prime * result
                + ((content.getApplicationId() == null) ? 0 : content.getApplicationId().hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj)
        {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            AppInfoItem other = (AppInfoItem) obj;
            if (content.getApplicationId() == null) {
                if (other.content.getApplicationId() != null) {
                    return false;
                }
            }
            else if (!content.getApplicationId().equals(other.content.getApplicationId())) {
                return false;
            }

            return true;
        }

        @Override
        public String toString()
        {
            String presentation;

            presentation = content.getApplicationName() + "@" + content.getDeviceName();
            presentation += "\nLast Claim Status : " + content.getClaimState();
            presentation += "\nLast Status : " + content.getRunningState();
            return presentation;
        }
    }

}