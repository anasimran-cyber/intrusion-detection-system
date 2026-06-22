import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class IDSFrontend extends JFrame {
    private JTextField csvPathField;
    private JTextField outputPathField;
    private JTextField searchIPField;
    private JTextField backendPathField;
    private JTextArea consoleArea;
    private JTable alertsTable;
    private JTable ipStatsTable;
    private JTable topThreatsTable;
    private JTable priorityDispatchTable;
    private DefaultTableModel alertsModel;
    private DefaultTableModel ipStatsModel;
    private DefaultTableModel topThreatsModel;
    private DefaultTableModel priorityDispatchModel;
    private DefaultTableModel searchResultsModel;
    private JTextArea auditLogArea;
    private JLabel searchResultsLabel;
    private JButton runButton;
    private JButton sampleButton;
    private JButton openSummaryButton;
    private JButton openOutputButton;
    private JTabbedPane tabs;
    private JTextArea summaryArea;

    private final Color deepInk;
    private final Color twilightBlue;
    private final Color nightSky;
    private final Color lightText;

    public IDSFrontend() {
        deepInk = new Color(27, 32, 49);
        twilightBlue = new Color(46, 56, 91);
        nightSky = new Color(13, 16, 28);
        lightText = new Color(235, 238, 245);

        initializeFrame();
        initializeComponents();
    }

    private void initializeFrame() {
        setTitle("Simplified IDS Frontend (DS Edition)");
        setSize(1050, 720);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        try {
            ImageIcon icon;
            icon = new ImageIcon("icon.png");
            setIconImage(icon.getImage());
        } catch (Exception exception) {
            // Icon is optional. Program will still run without it.
        }
    }

    private void initializeComponents() {
        JPanel mainPanel;
        JLabel titleLabel;

        mainPanel = new JPanel(new BorderLayout(12, 12));
        mainPanel.setBorder(new EmptyBorder(14, 14, 14, 14));
        mainPanel.setBackground(nightSky);

        titleLabel = new JLabel("Intrusion Detection System");
        titleLabel.setForeground(lightText);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        titleLabel.setBorder(new EmptyBorder(0, 0, 8, 0));

        tabs = new JTabbedPane();
        tabs.addTab("Control Panel", createControlPanel());
        tabs.addTab("Summary", createSummaryPanel());
        tabs.addTab("Alerts", createAlertsPanel());
        tabs.addTab("IP Statistics", createStatsPanel());
        tabs.addTab("Top Threats", createTopThreatsPanel());
        tabs.addTab("Priority Dispatch", createPriorityDispatchPanel());
        tabs.addTab("Audit Log", createAuditLogPanel());
        tabs.addTab("Console", createConsolePanel());

        mainPanel.add(titleLabel, BorderLayout.NORTH);
        mainPanel.add(tabs, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);
    }

    private JPanel createControlPanel() {
        JPanel panel;
        JPanel formPanel;
        JPanel buttonPanel;

        panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(18, 18, 18, 18));

        backendPathField = new JTextField(defaultBackendName());
        csvPathField = new JTextField();
        outputPathField = new JTextField(defaultOutputFolder());
        searchIPField = new JTextField();

        formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(deepInk);

        addFormRow(formPanel, 0, "Backend executable:", backendPathField, createBrowseFileButton(backendPathField));
        addFormRow(formPanel, 1, "CSV packet file:", csvPathField, createBrowseFileButton(csvPathField));
        addFormRow(formPanel, 2, "Output folder:", outputPathField, createBrowseFolderButton(outputPathField));
        addFormRow(formPanel, 3, "Search IP optional:", searchIPField, null);

        runButton = createActionButton("Run IDS Analysis");
        sampleButton = createActionButton("Generate Sample CSV");
        openSummaryButton = createActionButton("Open Summary");
        openOutputButton = createActionButton("Open Output Folder");

        runButton.addActionListener(this::runAnalysis);
        sampleButton.addActionListener(this::generateSampleCSV);
        openSummaryButton.addActionListener(this::openSummaryFile);
        openOutputButton.addActionListener(this::openOutputFolder);

        buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 12));
        buttonPanel.setBackground(deepInk);
        buttonPanel.add(runButton);
        buttonPanel.add(sampleButton);
        buttonPanel.add(openSummaryButton);
        buttonPanel.add(openOutputButton);

        panel.add(formPanel, BorderLayout.NORTH);
        panel.add(buttonPanel, BorderLayout.CENTER);
        panel.add(createHelpBox(), BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createSummaryPanel() {
        JPanel panel;
        JPanel summarySection;
        JPanel searchSection;
        JScrollPane summaryScroll;
        JScrollPane searchScroll;
        JSplitPane splitPane;
        JTable searchResultsTable;

        panel = new JPanel(new BorderLayout());
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        summaryArea = new JTextArea();
        summaryArea.setEditable(false);
        summaryArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        summaryArea.setBackground(new Color(4, 5, 11));
        summaryArea.setForeground(lightText);
        summaryArea.setText("Run IDS Analysis to see the summary report here.\n");
        summaryScroll = new JScrollPane(summaryArea);
        summarySection = new JPanel(new BorderLayout());
        summarySection.setBackground(deepInk);
        summarySection.add(summaryScroll, BorderLayout.CENTER);

        searchResultsLabel = new JLabel("Search Results - enter an IP in Control Panel and re-run to populate");
        searchResultsLabel.setForeground(lightText);
        searchResultsLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        searchResultsLabel.setBorder(new EmptyBorder(6, 4, 6, 4));

        searchResultsModel = new DefaultTableModel();
        searchResultsModel.setColumnIdentifiers(new String[]{"ID", "Type", "Source IP", "Destination IP", "Message", "Risk", "Score"});
        searchResultsTable = new JTable(searchResultsModel);
        searchResultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        searchScroll = new JScrollPane(searchResultsTable);

        searchSection = new JPanel(new BorderLayout());
        searchSection.setBackground(deepInk);
        searchSection.add(searchResultsLabel, BorderLayout.NORTH);
        searchSection.add(searchScroll, BorderLayout.CENTER);

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, summarySection, searchSection);
        splitPane.setResizeWeight(0.55);
        splitPane.setDividerSize(6);
        splitPane.setBorder(null);

        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createAlertsPanel() {
        JPanel panel;
        JScrollPane scrollPane;

        panel = new JPanel(new BorderLayout());
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        alertsModel = new DefaultTableModel();
        alertsModel.setColumnIdentifiers(new String[]{"ID", "Type", "Source IP", "Destination IP", "Message", "Risk", "Score"});
        alertsTable = new JTable(alertsModel);
        alertsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        scrollPane = new JScrollPane(alertsTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createStatsPanel() {
        JPanel panel;
        JScrollPane scrollPane;

        panel = new JPanel(new BorderLayout());
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        ipStatsModel = new DefaultTableModel();
        ipStatsModel.setColumnIdentifiers(new String[]{"Rank", "IP", "Packets", "SYN", "Suspicious Ports", "Large Packets", "Keywords", "Score", "Risk"});
        ipStatsTable = new JTable(ipStatsModel);
        ipStatsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        scrollPane = new JScrollPane(ipStatsTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createTopThreatsPanel() {
        JPanel panel;
        JScrollPane scrollPane;
        JLabel noteLabel;

        panel = new JPanel(new BorderLayout(0, 6));
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        noteLabel = new JLabel("Top 5 most threatening IPs ranked by score (Max-Heap output)");
        noteLabel.setForeground(lightText);
        noteLabel.setFont(new Font("Segoe UI", Font.ITALIC, 13));
        noteLabel.setBorder(new EmptyBorder(0, 2, 4, 0));

        topThreatsModel = new DefaultTableModel();
        topThreatsModel.setColumnIdentifiers(new String[]{"Rank", "IP", "Score", "Risk"});
        topThreatsTable = new JTable(topThreatsModel);
        topThreatsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        scrollPane = new JScrollPane(topThreatsTable);
        panel.add(noteLabel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createPriorityDispatchPanel() {
        JPanel panel;
        JScrollPane scrollPane;
        JLabel noteLabel;

        panel = new JPanel(new BorderLayout(0, 6));
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        noteLabel = new JLabel("Alerts ordered by urgency - highest score dispatched first (Priority Queue output)");
        noteLabel.setForeground(lightText);
        noteLabel.setFont(new Font("Segoe UI", Font.ITALIC, 13));
        noteLabel.setBorder(new EmptyBorder(0, 2, 4, 0));

        priorityDispatchModel = new DefaultTableModel();
        priorityDispatchModel.setColumnIdentifiers(new String[]{"Dispatch Order", "Alert ID", "Type", "Source IP", "Score", "Risk Level"});
        priorityDispatchTable = new JTable(priorityDispatchModel);
        priorityDispatchTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        scrollPane = new JScrollPane(priorityDispatchTable);
        panel.add(noteLabel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createAuditLogPanel() {
        JPanel panel;
        JScrollPane scrollPane;
        JLabel noteLabel;

        panel = new JPanel(new BorderLayout(0, 6));
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        noteLabel = new JLabel("Engine event trail - most recent event first (Stack output)");
        noteLabel.setForeground(lightText);
        noteLabel.setFont(new Font("Segoe UI", Font.ITALIC, 13));
        noteLabel.setBorder(new EmptyBorder(0, 2, 4, 0));

        auditLogArea = new JTextArea();
        auditLogArea.setEditable(false);
        auditLogArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        auditLogArea.setBackground(new Color(4, 5, 11));
        auditLogArea.setForeground(lightText);
        auditLogArea.setText("Run IDS Analysis to see the audit log here.\n");

        scrollPane = new JScrollPane(auditLogArea);
        panel.add(noteLabel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createConsolePanel() {
        JPanel panel;
        JScrollPane scrollPane;

        panel = new JPanel(new BorderLayout());
        panel.setBackground(deepInk);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        consoleArea = new JTextArea();
        consoleArea.setEditable(false);
        consoleArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        consoleArea.setBackground(new Color(4, 5, 11));
        consoleArea.setForeground(lightText);
        consoleArea.setText("Console output will appear here.\n");

        scrollPane = new JScrollPane(consoleArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createHelpBox() {
        JPanel panel;
        JTextArea helpText;

        panel = new JPanel(new BorderLayout());
        panel.setBackground(twilightBlue);
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));

        helpText = new JTextArea();
        helpText.setEditable(false);
        helpText.setLineWrap(true);
        helpText.setWrapStyleWord(true);
        helpText.setBackground(twilightBlue);
        helpText.setForeground(lightText);
        helpText.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        helpText.setText("IDS as a group project for Data Structures and algorithms by \n SP25-BCT-001: Abdul Saboor Hasan, SP25-BCT-005: Anas Imran, SP25-BCT-030: Muhammad Adeen Khan");

        panel.add(helpText, BorderLayout.CENTER);
        return panel;
    }

    private void addFormRow(JPanel panel, int row, String labelText, JTextField textField, JButton button) {
        GridBagConstraints labelConstraints;
        GridBagConstraints fieldConstraints;
        GridBagConstraints buttonConstraints;
        JLabel label;

        label = new JLabel(labelText);
        label.setForeground(lightText);
        label.setFont(new Font("Segoe UI", Font.BOLD, 14));

        textField.setFont(new Font("Segoe UI", Font.PLAIN, 14));

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridx = 0;
        labelConstraints.gridy = row;
        labelConstraints.insets = new Insets(8, 8, 8, 8);
        labelConstraints.anchor = GridBagConstraints.WEST;

        fieldConstraints = new GridBagConstraints();
        fieldConstraints.gridx = 1;
        fieldConstraints.gridy = row;
        fieldConstraints.insets = new Insets(8, 8, 8, 8);
        fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
        fieldConstraints.weightx = 1.0;

        buttonConstraints = new GridBagConstraints();
        buttonConstraints.gridx = 2;
        buttonConstraints.gridy = row;
        buttonConstraints.insets = new Insets(8, 8, 8, 8);

        panel.add(label, labelConstraints);
        panel.add(textField, fieldConstraints);

        if (button != null) {
            panel.add(button, buttonConstraints);
        }
    }

    private JButton createBrowseFileButton(JTextField targetField) {
        JButton button;

        button = createActionButton("Browse");
        button.addActionListener(event -> chooseFile(targetField));

        return button;
    }

    private JButton createBrowseFolderButton(JTextField targetField) {
        JButton button;

        button = createActionButton("Browse");
        button.addActionListener(event -> chooseFolder(targetField));

        return button;
    }

    private JButton createActionButton(String text) {
        JButton button;

        button = new JButton(text);
        button.setFont(new Font("Segoe UI", Font.BOLD, 13));
        button.setBackground(twilightBlue);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);

        return button;
    }

    private void chooseFile(JTextField targetField) {
        JFileChooser chooser;
        int result;

        chooser = new JFileChooser();
        result = chooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            targetField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void chooseFolder(JTextField targetField) {
        JFileChooser chooser;
        int result;

        chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        result = chooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            targetField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void runAnalysis(ActionEvent event) {
        String backendPath;
        String csvPath;
        String outputPath;
        String searchIP;
        File outputFolder;
        List<String> command;

        backendPath = backendPathField.getText().trim();
        csvPath = csvPathField.getText().trim();
        outputPath = outputPathField.getText().trim();
        searchIP = searchIPField.getText().trim();
        outputFolder = new File(outputPath);
        command = new ArrayList<>();

        if (backendPath.isEmpty() || csvPath.isEmpty() || outputPath.isEmpty()) {
            showMessage("Please select backend executable, CSV file, and output folder.");
            return;
        }

        if (!outputFolder.exists()) {
            outputFolder.mkdirs();
        }

        command.add(backendPath);
        command.add(csvPath);
        command.add(outputPath);

        if (!searchIP.isEmpty()) {
            command.add("--search-ip");
            command.add(searchIP);
        }

        executeCommand(command, true, null, searchIP);
    }

    private void generateSampleCSV(ActionEvent event) {
        String backendPath;
        String outputPath;
        String samplePath;
        File outputFolder;
        List<String> command;

        backendPath = backendPathField.getText().trim();
        outputPath = outputPathField.getText().trim();
        outputFolder = new File(outputPath);
        samplePath = outputPath + File.separator + "sample_packets.csv";
        command = new ArrayList<>();

        if (backendPath.isEmpty() || outputPath.isEmpty()) {
            showMessage("Please select backend executable and output folder first.");
            return;
        }

        if (!outputFolder.exists()) {
            outputFolder.mkdirs();
        }

        command.add(backendPath);
        command.add("--make-sample");
        command.add(samplePath);

        // FIX 3: Don't set csvPathField here — the process is async.
        // It is set inside done() only after the process exits successfully.
        executeCommand(command, false, samplePath, "");
    }

    private void executeCommand(List<String> command, boolean loadReportsAfterRun) {
        executeCommand(command, loadReportsAfterRun, null, "");
    }

    private void executeCommand(List<String> command, boolean loadReportsAfterRun, String samplePathOnSuccess, String searchIP) {
        SwingWorker<Integer, String> worker;

        runButton.setEnabled(false);
        sampleButton.setEnabled(false);
        consoleArea.setText("Running command:\n" + String.join(" ", command) + "\n\n");

        worker = new SwingWorker<Integer, String>() {
            @Override
            protected Integer doInBackground() {
                ProcessBuilder processBuilder;
                Process process;
                BufferedReader reader;
                String line;
                int exitCode;

                exitCode = -1;

                try {
                    processBuilder = new ProcessBuilder(command);
                    processBuilder.redirectErrorStream(true);
                    process = processBuilder.start();
                    reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

                    while ((line = reader.readLine()) != null) {
                        publish(line + "\n");
                    }

                    exitCode = process.waitFor();
                    publish("\nProcess finished with exit code: " + exitCode + "\n");
                } catch (Exception exception) {
                    publish("Error: " + exception.getMessage() + "\n");
                }

                return exitCode;
            }

            @Override
            protected void process(List<String> chunks) {
                for (String chunk : chunks) {
                    consoleArea.append(chunk);
                }
            }

            @Override
            protected void done() {
                int exitCode;

                runButton.setEnabled(true);
                sampleButton.setEnabled(true);

                try {
                    exitCode = get();
                } catch (Exception exception) {
                    exitCode = -1;
                }

                if (samplePathOnSuccess != null && exitCode == 0) {
                    csvPathField.setText(samplePathOnSuccess);
                }

                if (loadReportsAfterRun) {
                    loadReportsIntoTables(searchIP);
                }
            }
        };

        worker.execute();
    }

    private void loadReportsIntoTables(String searchIP) {
        String outputPath;
        File alertsFile;
        File statsFile;
        File summaryFile;
        File topThreatsFile;
        File priorityDispatchFile;
        File auditLogFile;
        File searchResultsFile;

        outputPath = outputPathField.getText().trim();
        alertsFile = new File(outputPath, "alerts.csv");
        statsFile = new File(outputPath, "ip_statistics.csv");
        summaryFile = new File(outputPath, "summary.txt");
        topThreatsFile = new File(outputPath, "top_threats.csv");
        priorityDispatchFile = new File(outputPath, "priority_dispatch.csv");
        auditLogFile = new File(outputPath, "audit_log.txt");
        searchResultsFile = new File(outputPath, "search_results.csv");

        loadSummaryIntoPanel(summaryFile);
        loadCSVIntoTable(alertsFile, alertsModel);
        loadCSVIntoTable(statsFile, ipStatsModel);
        loadCSVIntoTable(topThreatsFile, topThreatsModel);
        loadCSVIntoTable(priorityDispatchFile, priorityDispatchModel);
        loadAuditLogIntoPanel(auditLogFile);

        if (!searchIP.isEmpty()) {
            searchResultsLabel.setText("Search Results for IP: " + searchIP);
            searchResultsModel.setRowCount(0);
            loadCSVIntoTable(searchResultsFile, searchResultsModel);
        } else {
            searchResultsLabel.setText("Search Results — enter an IP in Control Panel and re-run to populate");
            searchResultsModel.setRowCount(0);
        }

        tabs.setSelectedIndex(1);
    }

    private void loadSummaryIntoPanel(File summaryFile) {
        List<String> lines;
        StringBuilder content;
        int i;

        summaryArea.setText("");

        if (!summaryFile.exists()) {
            summaryArea.setText("summary.txt not found at: " + summaryFile.getAbsolutePath() + "\n");
            return;
        }

        try {
            lines = Files.readAllLines(summaryFile.toPath());
            content = new StringBuilder();

            for (i = 0; i < lines.size(); i++) {
                content.append(lines.get(i)).append("\n");
            }

            summaryArea.setText(content.toString());
            summaryArea.setCaretPosition(0);
        } catch (Exception exception) {
            summaryArea.setText("Could not load summary: " + exception.getMessage() + "\n");
        }
    }

    private void loadAuditLogIntoPanel(File auditLogFile) {
        List<String> lines;
        StringBuilder content;
        int i;

        auditLogArea.setText("");

        if (!auditLogFile.exists()) {
            auditLogArea.setText("audit_log.txt not found at: " + auditLogFile.getAbsolutePath() + "\n");
            return;
        }

        try {
            lines = Files.readAllLines(auditLogFile.toPath());
            content = new StringBuilder();

            for (i = 0; i < lines.size(); i++) {
                content.append(lines.get(i)).append("\n");
            }

            auditLogArea.setText(content.toString());
            auditLogArea.setCaretPosition(0);
        } catch (Exception exception) {
            auditLogArea.setText("Could not load audit log: " + exception.getMessage() + "\n");
        }
    }

    // FIX 4: Replaced split(",") with a proper CSV parser that handles quoted
    // fields containing commas, which the C++ backend can produce via csvEscape().
    private String[] parseCSVLine(String line) {
        List<String> fields;
        StringBuilder current;
        boolean inQuotes;
        int i;
        char c;

        fields = new ArrayList<>();
        current = new StringBuilder();
        inQuotes = false;

        for (i = 0; i < line.length(); i++) {
            c = line.charAt(i);

            if (inQuotes) {
                if (c == '"') {
                    // Peek ahead: "" inside quotes is an escaped quote character
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        current.append('"');
                        i++; // Skip the second quote
                    } else {
                        inQuotes = false;
                    }
                } else {
                    current.append(c);
                }
            } else {
                if (c == '"') {
                    inQuotes = true;
                } else if (c == ',') {
                    fields.add(current.toString());
                    current.setLength(0);
                } else {
                    current.append(c);
                }
            }
        }

        fields.add(current.toString()); // Last field

        return fields.toArray(new String[0]);
    }

    private void loadCSVIntoTable(File csvFile, DefaultTableModel model) {
        List<String> lines;
        String[] values;
        int i;

        model.setRowCount(0);

        if (!csvFile.exists()) {
            consoleArea.append("Report not found: " + csvFile.getAbsolutePath() + "\n");
            return;
        }

        try {
            lines = Files.readAllLines(csvFile.toPath());

            for (i = 1; i < lines.size(); i++) {
                // FIX 4: Use the proper CSV parser instead of split(",", -1)
                values = parseCSVLine(lines.get(i));
                model.addRow(values);
            }
        } catch (Exception exception) {
            consoleArea.append("Could not load report: " + exception.getMessage() + "\n");
        }
    }

    private void openSummaryFile(ActionEvent event) {
        File summaryFile;

        summaryFile = new File(outputPathField.getText().trim(), "summary.txt");
        openDesktopFile(summaryFile);
    }

    private void openOutputFolder(ActionEvent event) {
        File outputFolder;

        outputFolder = new File(outputPathField.getText().trim());
        openDesktopFile(outputFolder);
    }

    private void openDesktopFile(File file) {
        try {
            if (!file.exists()) {
                showMessage("File or folder does not exist yet: " + file.getAbsolutePath());
                return;
            }

            Desktop.getDesktop().open(file);
        } catch (Exception exception) {
            showMessage("Could not open: " + exception.getMessage());
        }
    }

    private void showMessage(String message) {
        JOptionPane.showMessageDialog(this, message);
    }

    private String defaultBackendName() {
        String osName;

        osName = System.getProperty("os.name").toLowerCase();

        if (osName.contains("win")) {
            return "ids_engine.exe";
        }

        return "./ids_engine";
    }

    private String defaultOutputFolder() {
        Path path;

        path = Path.of(System.getProperty("user.dir"), "ids_output");
        return path.toString();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            IDSFrontend frontend;

            frontend = new IDSFrontend();
            frontend.setVisible(true);
        });
    }
}
