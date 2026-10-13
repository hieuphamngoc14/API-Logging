package apitracker.ui;

import apitracker.App;
import apitracker.core.Tracker;
import apitracker.store.Db;
import apitracker.store.DbWriter;
import apitracker.store.Rows;
import apitracker.util.HandlerStats;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.KeyStroke;
import javax.swing.Timer;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;

/** Main extension tab: "APIs" (list + log) and "Settings", with a status bar at the bottom. */
public final class TrackerTab extends JPanel {
    private final App app;
    private final ApiView apiView;
    private final SettingsView settingsView;
    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel status = new JLabel("Opening DB…");
    private final JLabel breaker = new JLabel();
    private final JButton breakerReset = new JButton("Re-enable");
    private final Timer statusTimer;

    public TrackerTab(App app) {
        super(new BorderLayout());
        this.app = app;
        this.apiView = new ApiView(app);
        this.settingsView = new SettingsView(app);
        tabs.addTab("APIs", apiView);
        tabs.addTab("Settings", settingsView);
        add(tabs, BorderLayout.CENTER);

        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        status.setFont(status.getFont().deriveFont(status.getFont().getSize2D() - 1f));
        bar.add(status, BorderLayout.CENTER);
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        Color err = UIManager.getColor("Component.error.focusedBorderColor");
        breaker.setForeground(err != null ? err : new Color(0xC0392B));
        breaker.setVisible(false);
        breakerReset.setVisible(false);
        breakerReset.addActionListener(e -> { app.resetBreakers(); refreshStatus(); });
        right.add(breaker);
        right.add(breakerReset);
        bar.add(right, BorderLayout.EAST);
        add(bar, BorderLayout.SOUTH);

        bindKeys();
        statusTimer = new Timer(1000, e -> refreshStatus());
        statusTimer.start();
        try { app.api.userInterface().applyThemeToComponent(this); } catch (Throwable ignored) { }
    }

    private void bindKeys() {
        int when = JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT;
        getInputMap(when).put(KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK), "logSearch");
        getInputMap(when).put(KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), "apiSearch");
        getActionMap().put("logSearch", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { tabs.setSelectedIndex(0); apiView.focusLogSearch(); }
        });
        getActionMap().put("apiSearch", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { tabs.setSelectedIndex(0); apiView.focusApiSearch(); }
        });
    }

    public void onReady(List<Rows.ApiRow> rows) {
        apiView.onReady(rows);
        settingsView.onReady();
        refreshStatus();
    }

    public void onError(String msg) {
        status.setText("Error opening DB: " + msg + " — logging is unavailable for now, see the extension's Output tab.");
    }

    public void copyLogForAi(String apiKey) { apiView.copyForAi(apiKey); }

    public void openApi(String apiKey) {
        tabs.setSelectedIndex(0);
        apiView.openApi(apiKey);
    }

    private void refreshStatus() {
        if (!app.ready()) {
            if (app.error() == null) status.setText("Opening DB…");
            return;
        }
        Db db = app.db();
        Tracker t = app.tracker();
        DbWriter w = app.writer();
        StringBuilder b = new StringBuilder();
        b.append(db.file.getFileName());
        if (db.readOnly) b.append(" (read-only)");
        if (db.temp) b.append(" (temporary project)");
        long n = t.processed.sum();
        b.append("  ·  queue ").append(t.queueSize()).append('/').append(w.queueSize());
        long drop = t.dropped.sum() + w.dropped.sum() + 0;
        if (drop > 0) b.append("  ·  dropped ").append(drop);
        var it = app.intruder();
        if (it != null && it.processed.sum() > 0) {
            b.append("  ·  Intruder ").append(String.format("%,d", it.processed.sum())).append(it.processed.sum() == 1 ? " request" : " requests");
            if (it.queueSize() > 0) b.append(", queued ").append(it.queueSize());
            if (it.dropped.sum() > 0) b.append(", dropped ").append(String.format("%,d", it.dropped.sum()));
        }
        if (n > 0) b.append(String.format("  ·  avg processing %.0f µs", t.processNs.sum() / 1000.0 / Math.max(1, n)));
        for (HandlerStats s : app.stats()) {
            if (s.calls() == 0) continue;
            b.append(String.format("  ·  %s %.1f/%.0f µs", s.name, s.avgMicros(), s.maxMicros()));
        }
        var h = app.history();
        if (h != null && h.lastPassMs > 0) b.append("  ·  history ").append(h.lastPassMs).append(" ms");
        if (!app.settings.trackingEnabled) b.append("  ·  LOGGING OFF");
        status.setText(b.toString());
        status.setToolTipText("worker/DB queue · avg/max time of handlers running on Burp threads");
        List<String> tripped = app.tripped();
        breaker.setVisible(!tripped.isEmpty());
        breakerReset.setVisible(!tripped.isEmpty());
        if (!tripped.isEmpty()) breaker.setText("Circuit breakers tripped: " + String.join(", ", tripped));
    }

    public void dispose() {
        statusTimer.stop();
        apiView.dispose();
    }
}
