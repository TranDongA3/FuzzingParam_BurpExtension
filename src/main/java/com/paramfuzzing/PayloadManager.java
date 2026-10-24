package com.paramfuzzing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * PayloadManager is a central store for managing all payloads.
 */
public class PayloadManager {

    private static final List<PayloadEntry> payloads = new ArrayList<>();

    static {
        payloads.add(new PayloadEntry("null", true));
        payloads.add(new PayloadEntry("true", true));
        payloads.add(new PayloadEntry("false", true));
        payloads.add(new PayloadEntry("0", true));
        payloads.add(new PayloadEntry("1", true));
        payloads.add(new PayloadEntry("[]", true));
        payloads.add(new PayloadEntry("{}", true));
    }

    public static List<PayloadEntry> getAllPayloads() {
        return Collections.unmodifiableList(payloads);
    }

    public static List<String> getEnabledPayloads() {
        List<String> result = new ArrayList<>();
        for (PayloadEntry p : payloads) {
            if (p.enabled()) {
                result.add(p.payload());
            }
        }
        return result;
    }

    public static void addPayload(String payload, boolean enabled) {
        payloads.add(new PayloadEntry(payload, enabled));
    }

    public static void removePayloadAt(int index) {
        if (index >= 0 && index < payloads.size()) {
            payloads.remove(index);
        }
    }

    public static void updatePayloadAt(int index, String payload, boolean enabled) {
        if (index >= 0 && index < payloads.size()) {
            payloads.set(index, new PayloadEntry(payload, enabled));
        }
    }

    public static void clearAll() {
        payloads.clear();
    }
}
