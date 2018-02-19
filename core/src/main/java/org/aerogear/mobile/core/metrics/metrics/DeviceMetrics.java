package org.aerogear.mobile.core.metrics.metrics;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import org.aerogear.mobile.core.MobileCore;
import org.aerogear.mobile.core.metrics.Metrics;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Collects device metrics
 */
public class DeviceMetrics implements Metrics {

    private final String platform;
    private final String platformVersion;

    public DeviceMetrics(final Context context) {

        this.platform = "android";
        this.platformVersion = String.valueOf(Build.VERSION.SDK_INT);
    }

    @Override
    public String identifier() {
        return "device";
    }

    @Override
    public Map<String, String> data() {
        Map<String, String> data = new HashMap<>();
        data.put("platform", platform);
        data.put("platformVersion", platformVersion);
        return data;
    }



}
