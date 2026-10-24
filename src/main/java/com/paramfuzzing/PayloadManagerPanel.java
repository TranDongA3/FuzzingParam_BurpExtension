package com.paramfuzzing;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

/**
 * A panel for managing fuzzing payloads: add/remove/enable/disable.
 */
public class PayloadManagerPanel extends JPanel {

    private final DefaultTableModel tableModel;
    private final JTable payloadTable;

    public PayloadManagerPanel() {
        setLayout(new BorderLayout());
        setBorder(new TitledBorder("Payload Manager"));

        String[] columnNames = {"Payload", "Enabled"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return (columnIndex == 1) ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int col) {
                return col == 1;
            }
        };

        payloadTable = new JTable(tableModel);
        JScrollPane scrollPane = new JScrollPane(payloadTable);
        add(scrollPane, BorderLayout.CENTER);

        // Load payloads from PayloadManager
        reloadFromManager();

        // === Add Buttons ===
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton deleteButton = new JButton("Delete");
        JButton clearButton = new JButton("Clear All");

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(clearButton);

        add(buttonPanel, BorderLayout.SOUTH);

        // === Button actions ===

        addButton.addActionListener(e -> {
            String newPayload = JOptionPane.showInputDialog(this, "Enter new payload:");
            if (newPayload != null && !newPayload.trim().isEmpty()) {
                PayloadManager.addPayload(newPayload.trim(), true);
                reloadFromManager();
            }
        });

        editButton.addActionListener(e -> {
            int row = payloadTable.getSelectedRow();
            if (row >= 0) {
                String current = (String) tableModel.getValueAt(row, 0);
                Boolean enabled = (Boolean) tableModel.getValueAt(row, 1);

                String newPayload = JOptionPane.showInputDialog(this, "Edit payload:", current);
                if (newPayload != null && !newPayload.trim().isEmpty()) {
                    PayloadManager.updatePayloadAt(row, newPayload.trim(), enabled);
                    reloadFromManager();
                }
            }
        });

        deleteButton.addActionListener(e -> {
            int row = payloadTable.getSelectedRow();
            if (row >= 0) {
                int confirm = JOptionPane.showConfirmDialog(this, "Delete this payload?", "Confirm", JOptionPane.YES_NO_OPTION);
                if (confirm == JOptionPane.YES_OPTION) {
                    PayloadManager.removePayloadAt(row);
                    reloadFromManager();
                }
            }
        });

        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Clear ALL payloads?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                PayloadManager.clearAll();
                reloadFromManager();
            }
        });


        tableModel.addTableModelListener(e -> {
            int col = e.getColumn();
            if (col == 1) { // Chỉ cập nhật nếu là cột "Enabled"
                int row = e.getFirstRow();
                String payload = (String) tableModel.getValueAt(row, 0);
                Boolean enabled = (Boolean) tableModel.getValueAt(row, 1);
                PayloadManager.updatePayloadAt(row, payload, enabled);
            }
        });

    }

    private void reloadFromManager() {
        tableModel.setRowCount(0);
        for (PayloadEntry entry : PayloadManager.getAllPayloads()) {
            tableModel.addRow(new Object[]{entry.payload(), entry.enabled()});
        }
    }

    private void syncToManager() {
        PayloadManager.clearAll();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String payload = (String) tableModel.getValueAt(i, 0);
            Boolean enabled = (Boolean) tableModel.getValueAt(i, 1);
            PayloadManager.addPayload(payload, enabled);
        }
    }

    public JTable getTable() {
        return payloadTable;
    }
}
