package com.paramfuzzing;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class FuzzResultDetail {
    private final HttpRequest request;
    private final HttpResponse response;
    private final String fuzzedParam;
    private final String payload;

    public FuzzResultDetail(HttpRequest request, HttpResponse response, String fuzzedParam, String payload) {
        this.request = request;
        this.response = response;
        this.fuzzedParam = fuzzedParam;
        this.payload = payload;
    }

    public String getRequestText() {
        return request.toString();
    }

    public String getResponseText() {
        return response != null ? response.toString() : "(No response)";
    }

    public String getFuzzedParam() {
        return fuzzedParam;
    }

    public String getPayload() {
        return payload;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }
}
