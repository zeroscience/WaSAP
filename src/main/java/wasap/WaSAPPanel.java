package wasap;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.net.URI;
import java.awt.datatransfer.StringSelection;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.util.concurrent.atomic.AtomicInteger;

public class WaSAPPanel extends JPanel {
    private DefaultTableModel tableModel;
    private JTable resultTable;
    private AtomicInteger rowCount = new AtomicInteger(0);

    public WaSAPPanel() {
        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel title = new JLabel("WaSAP - SAP Enumerator");
        title.setFont(new Font("SansSerif", Font.BOLD, 16));

        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clear());

        topPanel.add(title, BorderLayout.WEST);
        topPanel.add(clearButton, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);

        String[] columnNames = { "#", "URL", "Status", "Length", "MIME Type", "Notes" };

        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 2 || columnIndex == 3) {
                    return Integer.class;
                }
                return String.class;
            }
        };

        resultTable = new JTable(tableModel) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                if (!isRowSelected(row)) {
                    int modelRow = convertRowIndexToModel(row);
                    int status = (int) tableModel.getValueAt(modelRow, 2);

                    if (status >= 200 && status < 300) {
                        c.setBackground(new Color(144, 238, 144));
                    } else if (status >= 300 && status < 400) {
                        c.setBackground(new Color(255, 218, 185));
                    } else if (status >= 400 && status < 500) {
                        c.setBackground(new Color(255, 182, 193));
                    } else if (status >= 500) {
                        c.setBackground(new Color(255, 99, 71));
                    } else {
                        c.setBackground(Color.WHITE);
                    }
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        };

        resultTable.setAutoCreateRowSorter(true);
        resultTable.setFillsViewportHeight(true);

        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        JMenuItem openBrowserItem = new JMenuItem("Open in Browser");
        JMenuItem exportCsvItem = new JMenuItem("Export to CSV");

        copyUrlItem.addActionListener(e -> {
            int row = resultTable.getSelectedRow();
            if (row != -1) {
                String url = (String) resultTable.getValueAt(row, 1);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
            }
        });

        openBrowserItem.addActionListener(e -> {
            int row = resultTable.getSelectedRow();
            if (row != -1) {
                String url = (String) resultTable.getValueAt(row, 1);
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        exportCsvItem.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                exportToCsv(file);
            }
        });

        popupMenu.add(copyUrlItem);
        popupMenu.add(openBrowserItem);
        popupMenu.addSeparator();
        popupMenu.add(exportCsvItem);
        resultTable.setComponentPopupMenu(popupMenu);

        JScrollPane scrollPane = new JScrollPane(resultTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    private void exportToCsv(File file) {
        try (FileWriter writer = new FileWriter(file)) {
            for (int i = 0; i < tableModel.getColumnCount(); i++) {
                writer.append(tableModel.getColumnName(i)).append(",");
            }
            writer.append("\n");

            for (int i = 0; i < tableModel.getRowCount(); i++) {
                for (int j = 0; j < tableModel.getColumnCount(); j++) {
                    Object val = tableModel.getValueAt(i, j);
                    writer.append(val != null ? val.toString().replace(",", " ") : "").append(",");
                }
                writer.append("\n");
            }
            JOptionPane.showMessageDialog(this, "Export successful!");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error exporting CSV: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    public void addResult(String url, int status, int length, String mime, String notes) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[] { rowCount.incrementAndGet(), url, status, length, mime, notes });
        });
    }

    public void clear() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            rowCount.set(0);
        });
    }
}
