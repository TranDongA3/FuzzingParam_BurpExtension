package com.paramfuzzing;

import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.HashMap;
import java.util.Map;

public class BaselineSnapshot {
    public final int statusCode;
    public final int length;
    public final String body;
    public final Map<String, String> interestingHeaders;

    public BaselineSnapshot(HttpResponse response) {
        this.statusCode = response.statusCode();
        this.body = response.bodyToString();
        this.length = body.length();
        this.interestingHeaders = extractInterestingHeaders(response);
    }

    private Map<String, String> extractInterestingHeaders(HttpResponse response) {
        Map<String, String> result = new HashMap<>();
        for (var h : response.headers()) {
            String name = h.name().toLowerCase();
            if (name.equals("set-cookie") || name.equals("location") || name.equals("content-type")) {
                result.put(name, h.value());
            }
        }
        return result;
    }
}
