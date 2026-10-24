package com.paramfuzzing;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;


import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;
import java.awt.*;

public class RequestResponseViewer {

    private final JTextPane requestTextPane = new JTextPane();
    private final JTextArea responseTextArea = new JTextArea();
    private final JSplitPane splitPane;

    public RequestResponseViewer() {

        requestTextPane.setEditable(false);
        requestTextPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane requestScroll = new JScrollPane(requestTextPane);
        requestScroll.setBorder(new TitledBorder("HTTP Request"));


        responseTextArea.setEditable(false);
        responseTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane responseScroll = new JScrollPane(responseTextArea);
        responseScroll.setBorder(new TitledBorder("HTTP Response"));

        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestScroll, responseScroll);
        splitPane.setResizeWeight(0.5);
    }

    public JSplitPane getComponent() {
        return splitPane;
    }

    public void display(ProxyHttpRequestResponse entry) {
        HttpRequest request = entry.request();
        String requestText = new String(request.toByteArray().getBytes());

        // Extract param names
        java.util.List<String> paramNames = request.parameters().stream()
                .map(ParsedHttpParameter::name)
                .distinct()
                .toList();

        highlightParamsInRequest(requestText, paramNames);

        if (entry.response() != null) {
            byte[] responseBytes = entry.response().toByteArray().getBytes();
            responseTextArea.setText(new String(responseBytes));
        } else {
            responseTextArea.setText("[No Response]");
        }
    }

    private void highlightParamsInRequest(String requestText, java.util.List<String> paramNames) {
        StyledDocument doc = requestTextPane.getStyledDocument();
        doc.removeUndoableEditListener(e -> {}); // clear undo listener
        requestTextPane.setText(""); // clear nội dung cũ

        StyleContext context = new StyleContext();
        Style defaultStyle = context.addStyle("default", null);
        StyleConstants.setForeground(defaultStyle, Color.BLACK);
        StyleConstants.setFontFamily(defaultStyle, "Monospaced");
        StyleConstants.setFontSize(defaultStyle, 12);

        Style highlightStyle = context.addStyle("highlight", null);
        StyleConstants.setForeground(highlightStyle, Color.BLUE);
        StyleConstants.setBold(highlightStyle, true);

        try {
            doc.insertString(0, requestText, defaultStyle);

            for (String param : paramNames) {
                int index = 0;
                while ((index = requestText.indexOf(param + "=", index)) >= 0) {
                    doc.setCharacterAttributes(index, param.length(), highlightStyle, false);
                    index += param.length();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
