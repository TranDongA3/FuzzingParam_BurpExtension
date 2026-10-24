package com.paramfuzzing;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This class builds the main UI panel for ParamFuzzing.
 */
public class ParamFuzzingUI {

    private final JPanel mainPanel;
    private final MontoyaApi api;
    private final JTextArea requestTextArea = new JTextArea();
    private final JTextArea responseTextArea = new JTextArea();
    private final java.util.List<ProxyHttpRequestResponse> matchingRequests = new java.util.ArrayList<>();
    private final RequestResponseViewer viewer = new RequestResponseViewer();
    private final DefaultListModel<String> paramListModel = new DefaultListModel<>();
    private DefaultTableModel fuzzResultModel;
    List<FuzzResultDetail> fuzzDetails = new ArrayList<>();
    private final FuzzResultPanel fuzzResultPanel;
    final Set<String> alreadyScanned = new HashSet<>();

    private volatile boolean isFuzzing = true;

    public void stopFuzzing() {
        isFuzzing = false;
    }

    public void resumeFuzzing() {
        isFuzzing = true;
    }

    public boolean isFuzzingRunning() {
        return isFuzzing;
    }



    public void setFuzzResultModel(DefaultTableModel model) {
        this.fuzzResultModel = model;
    }

    public ParamFuzzingUI(MontoyaApi api, FuzzResultPanel fuzzResultPanel) {
        this.api = api;
        this.fuzzResultPanel = fuzzResultPanel;
        this.fuzzResultModel = fuzzResultPanel.getTableModel();
        this.mainPanel = buildUI();
        new ParamTracker(api, paramListModel, (newParam) -> {
            System.out.println("[Realtime] New param: " + newParam);
        });

    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    /**
     * Builds the left-side parameter list and center placeholder.
     */

    private JPanel buildUI() {
        JPanel panel = new JPanel(new BorderLayout());

        // === LEFT SIDE: Parameter list + Payload Manager ===

        // JList for parameters
        JList<String> paramList = new JList<>(paramListModel);
        JScrollPane paramScrollPane = new JScrollPane(paramList);
        paramScrollPane.setBorder(new TitledBorder("Detected Parameters"));
        paramScrollPane.setPreferredSize(new Dimension(200, 300));

        // Payload manager panel
        PayloadManagerPanel payloadManagerPanel = new PayloadManagerPanel();
        payloadManagerPanel.setPreferredSize(new Dimension(200, 200)); // or adjust later



        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.add(paramScrollPane);
        leftPanel.add(payloadManagerPanel);

        // Populate parameter list from Proxy history
        Set<String> paramNames = collectAllParameterNames();
        for (String name : paramNames) {
            paramListModel.addElement(name);
        }

        // === Right panel: Table of matching requests ===
        String[] columnNames = {"Method", "URL", "Status Code"};
        DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0);

        JTable requestTable = new JTable(tableModel);

        JButton manualFuzzButton = new JButton("Manual Fuzz");
        JPanel fuzzButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        fuzzButtonPanel.add(manualFuzzButton);


        JCheckBox includeEmptyCheckbox = new JCheckBox("Include empty value");
        JCheckBox includeDuplicateCheckbox = new JCheckBox("Include duplicate");
        JCheckBox includeRemovedCheckbox = new JCheckBox("Include removed param");

        fuzzButtonPanel.add(includeEmptyCheckbox);
        fuzzButtonPanel.add(includeDuplicateCheckbox);
        fuzzButtonPanel.add(includeRemovedCheckbox);



        JCheckBox autoScanCheckbox = new JCheckBox("Enable Auto Scan");
        fuzzButtonPanel.add(autoScanCheckbox);


        AtomicBoolean alreadyRegistered = new AtomicBoolean(false);

        autoScanCheckbox.addActionListener(e -> {
            if (autoScanCheckbox.isSelected() && !alreadyRegistered.get()) {
                int confirm = JOptionPane.showConfirmDialog(null,
                        "Auto Scan will monitor all new proxy requests and fuzz any parameters found.\nProceed?",
                        "Enable Auto Scan",
                        JOptionPane.YES_NO_OPTION);

                if (confirm == JOptionPane.YES_OPTION) {
                    ParamFuzzingUI self = ParamFuzzingUI.this;
                    api.proxy().registerRequestHandler(new ProxyRequestHandler() {
                        @Override
                        public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                            String requestId = interceptedRequest.method() + "::" + interceptedRequest.url() + "::" + interceptedRequest.bodyToString();

                            if (!autoScanCheckbox.isSelected() || alreadyScanned.contains(requestId)) {
                                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
                            }

                            alreadyScanned.add(requestId);

                            List<ParsedHttpParameter> params = interceptedRequest.parameters();
                            

                            // === Baseline
                            HttpRequest originalRequest = interceptedRequest;
                            HttpResponse originalResponse = api.http().sendRequest(originalRequest).response();
                            BaselineSnapshot baseline = new BaselineSnapshot(originalResponse);

                            if (!isFuzzingRunning()) {
                                api.logging().logToOutput("[x] Fuzzing stopped by user.");
                                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
                            }

                            // === Fuzz
                            for (ParsedHttpParameter param : params) {
                                String paramName = param.name();
                                HttpParameterType paramType = param.type();

                                // --- Normal payloads ---
                                for (String payload : PayloadManager.getEnabledPayloads()) {
                                    HttpParameter modified = HttpParameter.parameter(paramName, payload, paramType);
                                    HttpRequest modifiedRequest = originalRequest.withUpdatedParameters(modified);
                                    sendFuzzedRequest(api, modifiedRequest, fuzzResultModel, fuzzResultPanel, paramName, payload, baseline);
                                }

                                // --- Include empty ---
                                if (includeEmptyCheckbox.isSelected()) {
                                    HttpParameter emptyParam = HttpParameter.parameter(paramName, "", paramType);
                                    HttpRequest emptyRequest = originalRequest.withUpdatedParameters(emptyParam);
                                    sendFuzzedRequest(api, emptyRequest, fuzzResultModel, fuzzResultPanel, paramName, "[EMPTY]", baseline);
                                }

                                // --- Include duplicate ---
                                if (includeDuplicateCheckbox.isSelected()) {
                                    for (String payload : PayloadManager.getEnabledPayloads()) {
                                        HttpParameter duplicateParam = HttpParameter.parameter(paramName, payload, paramType);
                                        HttpRequest dupRequest = originalRequest.withAddedParameters(duplicateParam);
                                        sendFuzzedRequest(api, dupRequest, fuzzResultModel, fuzzResultPanel, paramName, "[DUPLICATE: " + payload + "]", baseline);
                                    }
                                }

                                // --- Include removed ---
                                if (includeRemovedCheckbox.isSelected()) {
                                    HttpRequest removedRequest = originalRequest.withRemovedParameters(param);
                                    sendFuzzedRequest(api, removedRequest, fuzzResultModel, fuzzResultPanel, paramName, "[REMOVED]", baseline);
                                }
                            }



                            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
                        }

                        @Override
                        public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                        }
                    });
                    alreadyRegistered.set(true);
                    int historyConfirm = JOptionPane.showConfirmDialog(null,
                            "Do you also want to scan all existing proxy history requests?",
                            "Scan Proxy History",
                            JOptionPane.YES_NO_OPTION);

                    if (historyConfirm == JOptionPane.YES_OPTION) {
                        new Thread(self::performInitialScanFromHistory).start();
                    }
                } else {
                    autoScanCheckbox.setSelected(false);
                }
            } else {
                api.logging().logToOutput("[AutoScan] Disabled by user.");
            }
        });




        JScrollPane tableScrollPane = new JScrollPane(requestTable);
        tableScrollPane.setBorder(new TitledBorder("Matching Requests"));

        JPanel requestTableWithButton = new JPanel(new BorderLayout());
        requestTableWithButton.add(tableScrollPane, BorderLayout.CENTER);
        requestTableWithButton.add(fuzzButtonPanel, BorderLayout.SOUTH);



        requestTable.getSelectionModel().addListSelectionListener(event -> {
            int selectedIndex = requestTable.getSelectedRow();
            if (selectedIndex >= 0 && selectedIndex < matchingRequests.size()) {
                ProxyHttpRequestResponse entry = matchingRequests.get(selectedIndex);
                viewer.display(entry);
//                displayRequestResponse(entry);
            }
        });

        manualFuzzButton.addActionListener(e -> {
            new Thread(() -> {
                List<String> selectedParams = paramList.getSelectedValuesList();
                int[] selectedRows = requestTable.getSelectedRows();

                List<ProxyHttpRequestResponse> selectedRequests = new ArrayList<>();
                for (int row : selectedRows) {
                    if (row >= 0 && row < matchingRequests.size()) {
                        selectedRequests.add(matchingRequests.get(row));
                    }
                }

                List<String> activePayloads = PayloadManager.getEnabledPayloads();

                api.logging().logToOutput("Manual Fuzz Triggered:");
                api.logging().logToOutput("- Params: " + selectedParams);
                api.logging().logToOutput("- Requests: " + selectedRequests.size());

                api.logging().logToOutput("- Payloads: " + activePayloads);

                for (ProxyHttpRequestResponse original : selectedRequests) {
                    api.logging().logToOutput("[Modified Request]");
                    HttpRequest originalRequest = original.request();

                    // === BASELINE  ===
                    HttpResponse baselineResponse = api.http().sendRequest(originalRequest).response();
                    BaselineSnapshot baseline = new BaselineSnapshot(baselineResponse);

                    if (!isFuzzingRunning()) {
                        api.logging().logToOutput("[x] Manual Fuzzing stopped by user.");
                        return;
                    }

                    for (String paramName : selectedParams) {
                        api.logging().logToOutput("[Param Selected]: " + paramName);

                        List<ParsedHttpParameter> allParams = originalRequest.parameters();
                        boolean found = false;

                        for (ParsedHttpParameter originalParam : allParams) {
                            if (originalParam.name().equals(paramName)) {
                                found = true;
                                api.logging().logToOutput("- Original Param in Request: " + originalParam);

                                for (String payload : activePayloads) {
                                    // == NORMAL PAYLOAD ==
                                    HttpParameter modifiedParam = HttpParameter.parameter(
                                            originalParam.name(),
                                            payload,
                                            originalParam.type()
                                    );

                                    HttpRequest modifiedRequest = originalRequest.withUpdatedParameters(modifiedParam);
                                    sendFuzzedRequest(api, modifiedRequest, fuzzResultModel, fuzzResultPanel, paramName, payload, baseline);
                                }

                                // == EMPTY VALUE ==
                                if (includeEmptyCheckbox.isSelected()) {
                                    HttpParameter emptyParam = HttpParameter.parameter(originalParam.name(), "", originalParam.type());
                                    HttpRequest emptyRequest = originalRequest.withUpdatedParameters(emptyParam);
                                    sendFuzzedRequest(api, emptyRequest, fuzzResultModel, fuzzResultPanel, paramName, "[EMPTY]", baseline);
                                }

                                // == DUPLICATE PARAM ==
                                if (includeDuplicateCheckbox.isSelected()) {
                                    for (String payload : activePayloads) {
                                        HttpParameter dupParam = HttpParameter.parameter(originalParam.name(), payload, originalParam.type());
                                        HttpRequest dupRequest = originalRequest.withAddedParameters(dupParam);
                                        sendFuzzedRequest(api, dupRequest, fuzzResultModel, fuzzResultPanel, paramName, "[DUPLICATE: " + payload + "]", baseline);
                                    }
                                }

                                // == REMOVED PARAM ==
                                if (includeRemovedCheckbox.isSelected()) {
                                    HttpRequest removedRequest = originalRequest.withRemovedParameters(originalParam);
                                    sendFuzzedRequest(api, removedRequest, fuzzResultModel, fuzzResultPanel, paramName, "[REMOVED]", baseline);
                                }
                            }
                        }

                        if (!found) {
                            api.logging().logToOutput("- Param not found in request: " + paramName);
                        }
                    }
                }
            }).start();
        });


        // Allow column resizing by user
        requestTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

        // Set preferred widths (initial values)
        requestTable.getColumnModel().getColumn(0).setPreferredWidth(60);   // Method
        requestTable.getColumnModel().getColumn(1).setPreferredWidth(500);  // URL
        requestTable.getColumnModel().getColumn(2).setPreferredWidth(80);   // Status Code


        JSplitPane rightPanel = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                requestTableWithButton,
                viewer.getComponent()
        );
        rightPanel.setResizeWeight(0.4);


        // === Event: when user selects a parameter ===
        paramList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    String selectedParam = paramList.getSelectedValue();
                    if (selectedParam != null) {
                        updateRequestTable(selectedParam, tableModel);
                    }
                }
            }
        });

        // Use JSplitPane for resizable left-right layout
        JSplitPane splitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                leftPanel,
                rightPanel
        );

        splitPane.setResizeWeight(0.2);
        splitPane.setDividerSize(5);

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }



    /**
     * Function to display request/response content
     */

    private void displayRequestResponse(ProxyHttpRequestResponse entry) {
        HttpRequest request = entry.request();
        byte[] requestBytes = request.toByteArray().getBytes();
        requestTextArea.setText(new String(requestBytes));

        if (entry.response() != null) {
            byte[] responseBytes = entry.response().toByteArray().getBytes();
            responseTextArea.setText(new String(responseBytes));
        } else {
            responseTextArea.setText("[No Response]");
        }
    }

    /**
     * Collects unique parameter names from all HTTP requests in proxy history.
     */
    private Set<String> collectAllParameterNames() {
        Set<String> paramNames = new LinkedHashSet<>();
        List<ProxyHttpRequestResponse> history = api.proxy().history();

        for (ProxyHttpRequestResponse entry : history) {
            HttpRequest request = entry.request();
            List<ParsedHttpParameter> parameters = request.parameters();

            for (HttpParameter param : parameters) {
                paramNames.add(param.name());
            }
        }

        return paramNames;
    }

    /**
     * Show requests contain the parameter selected.
     */
    private void updateRequestTable(String selectedParam, DefaultTableModel tableModel) {
        matchingRequests.clear();

        tableModel.setRowCount(0); // Clear old data

        List<ProxyHttpRequestResponse> history = api.proxy().history();

        for (ProxyHttpRequestResponse entry : history) {
            HttpRequest request = entry.request();
            List<ParsedHttpParameter> parameters = request.parameters();

            boolean found = false;
            for (HttpParameter param : parameters) {
                if (param.name().equals(selectedParam)) {
                    found = true;
                    break;
                }
            }

            if (found) {
                String method = request.method();
                String url = request.url().toString();
                int statusCode = entry.response() != null
                        ? entry.response().statusCode()
                        : -1;

                tableModel.addRow(new Object[]{method, url, statusCode});
                matchingRequests.add(entry);
            }
        }
    }


    private void performInitialScanFromHistory() {
        api.logging().logToOutput("[InitialScan] Starting scan of proxy history...");

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        Set<String> requestSignatures = new HashSet<>();

        for (ProxyHttpRequestResponse entry : history) {

            if (!isFuzzingRunning()) {
                api.logging().logToOutput("[x] Initial Scan stopped by user.");
                break;
            }

            HttpRequest request = entry.request();

            HttpResponse baselineResponse = api.http().sendRequest(request).response();
            BaselineSnapshot baseline = new BaselineSnapshot(baselineResponse);

            List<ParsedHttpParameter> params = request.parameters();

            for (ParsedHttpParameter param : params) {
                String paramName = param.name();
                HttpParameterType paramType = param.type();

                String signature = request.method() + "::" + request.url() + "::" + paramName;
                if (alreadyScanned.contains(signature)) continue;

                alreadyScanned.add(signature);

                // == NORMAL PAYLOADS ==
                for (String payload : PayloadManager.getEnabledPayloads()) {
                    HttpParameter modified = HttpParameter.parameter(paramName, payload, paramType);
                    HttpRequest modifiedRequest = request.withUpdatedParameters(modified);
                    sendFuzzedRequest(api, modifiedRequest, fuzzResultModel, fuzzResultPanel, paramName, payload, baseline);
                }

                // == EMPTY ==
                HttpParameter emptyParam = HttpParameter.parameter(paramName, "", paramType);
                HttpRequest emptyRequest = request.withUpdatedParameters(emptyParam);
                sendFuzzedRequest(api, emptyRequest, fuzzResultModel, fuzzResultPanel, paramName, "[EMPTY]", baseline);

                // == DUPLICATE ==
                for (String payload : PayloadManager.getEnabledPayloads()) {
                    HttpParameter dupParam = HttpParameter.parameter(paramName, payload, paramType);
                    HttpRequest dupRequest = request.withAddedParameters(dupParam);
                    sendFuzzedRequest(api, dupRequest, fuzzResultModel, fuzzResultPanel, paramName, "[DUPLICATE: " + payload + "]", baseline);
                }

                // == REMOVED ==
                HttpRequest removedRequest = request.withRemovedParameters(param);
                sendFuzzedRequest(api, removedRequest, fuzzResultModel, fuzzResultPanel, paramName, "[REMOVED]", baseline);
            }
        }

        api.logging().logToOutput("[InitialScan] Completed scanning proxy history.");
    }


    private void sendFuzzedRequest(MontoyaApi api,
                                   HttpRequest request,
                                   DefaultTableModel tableModel,
                                   FuzzResultPanel panel,
                                   String paramName,
                                   String payloadLabel,
                                   BaselineSnapshot baseline) {
        try {
            var response = api.http().sendRequest(request);

            if (response.hasResponse()) {
                int status = response.response().statusCode();
                String url = request.url();
                String body = response.response().bodyToString();
                int length = body.length();

                // === RULE CHECK ===
                boolean suspicious = false;
                if (status != baseline.statusCode) suspicious = true;
                if (Math.abs(length - baseline.length) > 30) suspicious = true;
                if (body.matches("(?i).*\\b(error|exception|sql|traceback|invalid|denied)\\b.*")) suspicious = true;

                boolean finalSuspicious = suspicious;

                SwingUtilities.invokeLater(() -> {
                    tableModel.addRow(new Object[]{paramName, payloadLabel, status, url});
                    int row = tableModel.getRowCount() - 1;

                    if (finalSuspicious) {
                        // Mark suspicious row (store for highlight later)
                        panel.markSuspiciousRow(row);
                    }
                    panel.getFuzzDetails().add(new FuzzResultDetail(request, response.response(), paramName, payloadLabel));

                });

                api.logging().logToOutput("[✓] Sent " + paramName + "=" + payloadLabel + " -> " + status);
            } else {
                api.logging().logToOutput("[!] No response for: " + paramName + "=" + payloadLabel);
            }
        } catch (Exception ex) {
            api.logging().logToError("[ERROR] sendFuzzedRequest: " + ex.getMessage());
        }
    }




}
