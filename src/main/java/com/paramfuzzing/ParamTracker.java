package com.paramfuzzing;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import javax.swing.*;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;

/**
 * Tracks parameters seen in proxy traffic and updates the UI in real-time.
 */
public class ParamTracker implements ProxyRequestHandler {

    private final Set<String> paramNames = new CopyOnWriteArraySet<>();
    private final DefaultListModel<String> paramListModel;
    private final Consumer<String> onNewParamCallback;

    public ParamTracker(MontoyaApi api, DefaultListModel<String> paramListModel, Consumer<String> onNewParamCallback) {
        this.paramListModel = paramListModel;
        this.onNewParamCallback = onNewParamCallback;

        // Register this tracker to listen to proxy traffic
        api.proxy().registerRequestHandler(this);
    }

    public Set<String> getTrackedParamNames() {
        return paramNames;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        List<ParsedHttpParameter> params = request.parameters();

        for (ParsedHttpParameter p : params) {
            String name = p.name();
            if (paramNames.add(name)) {
                SwingUtilities.invokeLater(() -> {
                    paramListModel.addElement(name);
                    onNewParamCallback.accept(name);
                });
            }
        }

        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return null;
    }
}

