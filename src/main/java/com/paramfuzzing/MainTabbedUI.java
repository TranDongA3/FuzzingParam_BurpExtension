package com.paramfuzzing;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;

public class MainTabbedUI {
    private final JTabbedPane tabbedPane;
    private final FuzzResultPanel fuzzResultPanel;
    private final ParamFuzzingUI paramFuzzingUI;

    public MainTabbedUI(MontoyaApi api) {
        this.tabbedPane = new JTabbedPane();

        this.fuzzResultPanel = new FuzzResultPanel();

        this.paramFuzzingUI = new ParamFuzzingUI(api, fuzzResultPanel);

        paramFuzzingUI.setFuzzResultModel(fuzzResultPanel.getTableModel());

        // Rất quan trong: thiết lập ngược để ResultPanel có thể goi stopFuzzing()
        fuzzResultPanel.setFuzzingUI(paramFuzzingUI);

        tabbedPane.addTab("Param Scanner", paramFuzzingUI.getMainPanel());
        tabbedPane.addTab("Fuzz Results", fuzzResultPanel.getPanel());
    }

    public JTabbedPane getTabbedPane() {
        return tabbedPane;
    }
}
