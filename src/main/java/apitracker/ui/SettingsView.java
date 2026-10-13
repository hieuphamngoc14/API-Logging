package apitracker.ui;

import apitracker.App;
import apitracker.core.Settings;
import apitracker.store.Db;
import apitracker.store.DbWriter;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Map;

/** Settings tab: saved to Burp's Preferences (shared by all Burp projects). */
final class SettingsView extends JPanel {
    private final App app;
    private final JTextField storageDir = new JTextField(36);
    private final JLabel dbFile = new JLabel("-");
    private final JCheckBox tracking = new JCheckBox("Log sends from Repeater");
    private final JCheckBox highlight = new JCheckBox("Highlight untested APIs yellow in Proxy history");
    private final JCheckBox markerNote = new JCheckBox("Add a note to the Notes column of highlighted entries:");
    private final JTextField marker = new JTextField(12);
    private final JCheckBox ai = new JCheckBox("Accept AI requests sent through Proxy with header:");
    private final JTextField aiHeader = new JTextField(12);
    private final JCheckBox intruder = new JCheckBox("Log Intruder: one row per attack (payload positions and stats, not every request)");
    private final JCheckBox storeRaw = new JCheckBox("Store raw requests, and each original's request + response (context for AI)");
    private final JCheckBox tabHook = new JCheckBox("Auto-rename Repeater tabs on Ctrl+R (requires reloading the extension)");
    private final JTextField hotkey = new JTextField(12);
    private final JTextField excludedExt = new JTextField(36);
    private final JTextField excludedPath = new JTextField(36);
    private final JTextField ignoredHeaders = new JTextField(36);
    private final JTextField sensitive = new JTextField(36);
    private final JCheckBox keepTemp = new JCheckBox("Keep the temporary project's log when closing Burp (renamed to temp-<time>.db)");
    private final DefaultListModel<String> labelModel = new DefaultListModel<>();
    private final JList<String> labelList = new JList<>(labelModel);
    private Map<String, String> labelMap = Map.of();
    private final JLabel saved = new JLabel(" ");

    SettingsView(App app) {
        super(new BorderLayout());
        this.app = app;
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        GridBagConstraints g = new GridBagConstraints();
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(3, 4, 3, 4);
        g.gridy = 0;

        section(form, g, "Storage");
        row(form, g, "Log directory", storageDir, "applies when the project is reopened");
        row(form, g, "Current DB file", dbFile, null);
        full(form, g, keepTemp);

        section(form, g, "Logging and highlighting");
        full(form, g, tracking);
        full(form, g, highlight);
        markerNote.setToolTipText("Only highlights entries with no color or note. Once an API is tested, the yellow highlight is cleared only from"
                + " entries with exactly this note, so yellow you set yourself is kept. If off, any yellow entry without a note counts as the extension's.");
        full(form, g, inline(markerNote, marker));
        full(form, g, inline(ai, aiHeader));
        full(form, g, intruder);
        full(form, g, storeRaw);
        full(form, g, tabHook);
        row(form, g, "Send to Repeater (tracked) hotkey", hotkey, "same format as Burp's Settings, requires reloading the extension");

        section(form, g, "Filters");
        row(form, g, "Ignored extensions", excludedExt, "static files are not highlighted");
        row(form, g, "Ignored paths (regex)", excludedPath, null);
        row(form, g, "Headers ignored in diff", ignoredHeaders, null);
        row(form, g, "Masked fields", sensitive, "only these fields are masked in the log, everything else is cleartext (comma-separated, e.g. password, otp)");

        section(form, g, "Token labels");
        JLabel hint = new JLabel("Select a value in a request → right-click → \"API Logging: label the selected value…\"");
        full(form, g, hint);
        labelList.setVisibleRowCount(5);
        JScrollPane ls = new JScrollPane(labelList);
        JButton del = new JButton("Delete selected label");
        del.addActionListener(e -> deleteLabel());
        JPanel lp = new JPanel(new BorderLayout(6, 0));
        lp.add(ls, BorderLayout.CENTER);
        lp.add(del, BorderLayout.EAST);
        g.gridx = 0; g.gridwidth = 3; g.fill = GridBagConstraints.HORIZONTAL;
        form.add(lp, g);
        g.gridy++; g.gridwidth = 1; g.fill = GridBagConstraints.NONE;

        JButton save = new JButton("Save");
        save.addActionListener(e -> save());
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottom.add(save);
        bottom.add(saved);
        g.gridx = 0; g.gridwidth = 3;
        form.add(bottom, g);
        g.gridy++;
        g.weighty = 1;
        form.add(new JLabel(" "), g);

        add(new JScrollPane(form), BorderLayout.CENTER);
        load();
    }

    private static JPanel inline(JCheckBox c, JTextField f) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        p.add(c);
        p.add(f);
        return p;
    }

    private static void section(JPanel form, GridBagConstraints g, String title) {
        JLabel l = new JLabel(title);
        l.setFont(l.getFont().deriveFont(java.awt.Font.BOLD, l.getFont().getSize2D() + 1f));
        l.setBorder(BorderFactory.createEmptyBorder(10, 0, 2, 0));
        g.gridx = 0; g.gridwidth = 3;
        form.add(l, g);
        g.gridy++; g.gridwidth = 1;
    }

    private static void row(JPanel form, GridBagConstraints g, String label, java.awt.Component field, String note) {
        g.gridx = 0;
        form.add(new JLabel(label), g);
        g.gridx = 1;
        form.add(field, g);
        if (note != null) {
            JLabel n = new JLabel(note);
            Color c = UIManager.getColor("Label.disabledForeground");
            if (c != null) n.setForeground(c);
            g.gridx = 2;
            form.add(n, g);
        }
        g.gridy++;
    }

    private static void full(JPanel form, GridBagConstraints g, java.awt.Component c) {
        g.gridx = 0; g.gridwidth = 3;
        form.add(c, g);
        g.gridy++; g.gridwidth = 1;
    }

    private void load() {
        Settings s = app.settings;
        storageDir.setText(s.storageDir);
        tracking.setSelected(s.trackingEnabled);
        highlight.setSelected(s.highlightEnabled);
        markerNote.setSelected(s.markerNote);
        marker.setText(s.marker);
        ai.setSelected(s.aiEnabled);
        aiHeader.setText(s.aiHeader);
        intruder.setSelected(s.intruderEnabled);
        storeRaw.setSelected(s.storeRaw);
        tabHook.setSelected(s.tabHook);
        hotkey.setText(s.hotkey);
        excludedExt.setText(String.join(",", s.excludedExt));
        excludedPath.setText(s.excludedPath == null ? "" : s.excludedPath.pattern());
        ignoredHeaders.setText(String.join(",", s.ignoredHeaders));
        sensitive.setText(String.join(",", s.sensitiveTokens));
        keepTemp.setSelected(app.keepTempLog);
    }

    void onReady() {
        Db db = app.db();
        if (db != null) dbFile.setText(db.file.toString() + (db.readOnly ? "  (read-only: open in another Burp)" : ""));
        keepTemp.setEnabled(db != null && db.temp);
        refreshLabels();
    }

    private void refreshLabels() {
        labelMap = app.labels.all();
        labelModel.clear();
        for (String k : labelMap.keySet()) labelModel.addElement(k);
    }

    private void deleteLabel() {
        String sel = labelList.getSelectedValue();
        if (sel == null) return;
        String hmac = labelMap.get(sel);
        app.labels.remove(hmac);
        DbWriter w = app.writer();
        if (w != null) w.submit(DbWriter.deleteLabel(hmac));
        refreshLabels();
    }

    private void save() {
        Settings s = app.settings;
        s.storageDir = storageDir.getText().trim().isEmpty() ? s.storageDir : storageDir.getText().trim();
        s.trackingEnabled = tracking.isSelected();
        s.highlightEnabled = highlight.isSelected();
        s.markerNote = markerNote.isSelected();
        s.marker = marker.getText().trim().isEmpty() ? Settings.DEFAULT_MARKER : marker.getText().trim();
        s.aiEnabled = ai.isSelected();
        s.aiHeader = aiHeader.getText().trim().isEmpty() ? Settings.DEFAULT_AI_HEADER : aiHeader.getText().trim();
        s.intruderEnabled = intruder.isSelected();
        s.storeRaw = storeRaw.isSelected();
        s.tabHook = tabHook.isSelected();
        s.hotkey = hotkey.getText().trim();
        s.excludedExt = Settings.parseList(excludedExt.getText());
        s.excludedPath = Settings.compileOrNull(excludedPath.getText());
        s.ignoredHeaders = java.util.Set.copyOf(Settings.parseList(ignoredHeaders.getText()));
        s.sensitiveTokens = java.util.List.copyOf(Settings.parseList(sensitive.getText()));
        app.keepTempLog = keepTemp.isSelected();
        app.saveSettings(excludedExt.getText(), excludedPath.getText(), ignoredHeaders.getText(), sensitive.getText());
        String warn = (!excludedPath.getText().isBlank() && s.excludedPath == null) ? "  (invalid path regex, ignored)" : "";
        saved.setText("Saved." + warn);
        refreshLabels();
    }
}
