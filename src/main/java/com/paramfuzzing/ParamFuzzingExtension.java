package com.paramfuzzing;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;

/**
 * Entry point for the ParamFuzzing Burp extension.
 */
public class ParamFuzzingExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        // Set extension name
        api.extension().setName("ParamFuzzing - Auto/Manual Param Scanner");

        // Log to Burp's Output tab
        api.logging().logToOutput("[+] ParamFuzzing loaded");

        // Create and register custom UI tab
//        ParamFuzzingUI ui = new ParamFuzzingUI(api);
//        api.userInterface().registerSuiteTab("ParamFuzzing", ui.getMainPanel());

        MainTabbedUI mainTabbedUI = new MainTabbedUI(api);
        api.userInterface().registerSuiteTab("ParamFuzz", mainTabbedUI.getTabbedPane());
    }
}
