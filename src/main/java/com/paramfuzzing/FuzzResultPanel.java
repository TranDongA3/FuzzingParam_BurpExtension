package com.paramfuzzing;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;

public class FuzzResultPanel {
    private final JPanel panel;
    private final DefaultTableModel tableModel;
    private final java.util.List<FuzzResultDetail> fuzzDetails = new java.util.ArrayList<>();
    private final java.util.Set<Integer> suspiciousRows = new java.util.HashSet<>();
    private ParamFuzzingUI fuzzingUI;

    public FuzzResultPanel() {
        panel = new JPanel(new BorderLayout());

        String[] cols = {"Param", "Payload", "Status", "URL"};
        tableModel = new DefaultTableModel(cols, 0);
        JTable table = new JTable(tableModel);

        table.getSelectionModel().addListSelectionListener(event -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0 && selectedRow < fuzzDetails.size()) {
                FuzzResultDetail detail = fuzzDetails.get(selectedRow);

                String requestText = detail.getRequestText();
                String responseText = detail.getResponseText();

                String paramName = detail.getFuzzedParam();
                String payload = detail.getPayload();

                JTextPane requestArea = createHighlightedTextPane(requestText, paramName, payload);
                JTextPane responseArea = createHighlightedTextPane(responseText, paramName, payload);

                requestArea.setCaretPosition(0);
                responseArea.setCaretPosition(0);


                JScrollPane requestScroll = new JScrollPane(requestArea);
                JScrollPane responseScroll = new JScrollPane(responseArea);

                JTabbedPane tabbedPane = new JTabbedPane();
                tabbedPane.addTab("Request", requestScroll);
                tabbedPane.addTab("Response", responseScroll);

                tabbedPane.setPreferredSize(new Dimension(800, 600));

                JOptionPane.showMessageDialog(
                        null,
                        tabbedPane,
                        "Request/Response Detail",
                        JOptionPane.INFORMATION_MESSAGE
                );
            }
        });

        // ======= Highlight màu lỗi =======
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                try {
                    if (suspiciousRows.contains(row)) {
                        c.setBackground(Color.PINK);
                    } else {
                        c.setBackground(isSelected ? table.getSelectionBackground() : Color.WHITE);
                    }
                } catch (Exception ex) {
                    c.setBackground(Color.WHITE);
                }
                return c;
            }
        });

        JButton clearButton = new JButton("Clear Results");
        JButton stopButton = new JButton("Stop Fuzzing");

        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    panel,
                    "Are you sure you want to clear all fuzzing results?",
                    "Confirm Clear",
                    JOptionPane.YES_NO_OPTION
            );

            if (confirm == JOptionPane.YES_OPTION) {
                tableModel.setRowCount(0);
                fuzzDetails.clear();
            }
        });

        stopButton.addActionListener(e -> {
            if (fuzzingUI != null) {
                fuzzingUI.stopFuzzing();
                stopButton.setEnabled(false);
                JOptionPane.showMessageDialog(panel, "Fuzzing has been stopped.");
            } else {
                JOptionPane.showMessageDialog(panel, "Fuzzing controller not linked.");
            }
        });

        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottomPanel.add(stopButton);
        bottomPanel.add(clearButton);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(new TitledBorder("Fuzzing Results"));

        panel.add(scroll, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
    }

    public void setFuzzingUI(ParamFuzzingUI fuzzingUI) {
        this.fuzzingUI = fuzzingUI;
    }

    public java.util.List<FuzzResultDetail> getFuzzDetails() {
        return fuzzDetails;
    }

    public JPanel getPanel() {
        return panel;
    }

    public DefaultTableModel getTableModel() {
        return tableModel;
    }

    public void markSuspiciousRow(int row) {
        suspiciousRows.add(row);
    }

    private JTextPane createHighlightedTextPane(String text, String param, String payload) {
        JTextPane textPane = new JTextPane();
        textPane.setContentType("text/plain");
        textPane.setText(text);
        textPane.setEditable(false);

        if (param == null || payload == null) {
            return textPane;
        }

        Highlighter highlighter = textPane.getHighlighter();
        Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW);

        try {
            // Highlight param=value nếu có
            String toFind = param + "=" + payload;
            int index = text.indexOf(toFind);
            while (index >= 0) {
                highlighter.addHighlight(index, index + toFind.length(), painter);
                index = text.indexOf(toFind, index + 1);
            }

            // Nếu không tìm thấy, thử chỉ highlight payload
            if (index == -1 && payload.length() > 1) {
                index = text.indexOf(payload);
                while (index >= 0) {
                    highlighter.addHighlight(index, index + payload.length(), painter);
                    index = text.indexOf(payload, index + 1);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return textPane;
    }

}


