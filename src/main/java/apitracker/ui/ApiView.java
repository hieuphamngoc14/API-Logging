package apitracker.ui;

import apitracker.App;
import apitracker.core.TabNames;
import apitracker.core.StatusIndex;
import apitracker.store.Repo;
import apitracker.store.Rows;
import apitracker.store.Zip;
import apitracker.util.Log;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.AbstractListModel;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListSelectionModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListCellRenderer;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Left: API list (filtered in RAM, grouped by host, log search via FTS on a background thread).
 * Right: full log of the selected API (paged, each entry shows all changes, new sends appear by themselves at
 * the top of the list) and a Send to Repeater button.
 * All DB queries run on tracker-search; the EDT only receives results.
 */
final class ApiView extends JPanel {
    private static final int PAGE = 200;
    /** Max sends kept in the log list (scroll down to load more from the DB). */
    private static final int MAX_ROWS = 2_000;
    /** Log cell lines longer than this are truncated (values are shortened on write, so this is rarely hit). */
    private static final int MAX_LINE_CHARS = 1_000;

    private final App app;

    // ---- left ----
    private final JTextField apiSearch = new JTextField();
    /** On: the list shows untested APIs from Proxy history that are in Burp's current scope. */
    private final JCheckBox untestedMode = new JCheckBox("Untested APIs in scope (Proxy history)");
    private final ApiListModel apiModel = new ApiListModel();
    private final LockedList<Object> apiList = new LockedList<>(apiModel);
    private ApiRenderer apiRenderer;
    private final JLabel apiFooter = new JLabel(" ");
    private final Map<Integer, Rows.ApiRow> apis = new HashMap<>();
    private Timer apiDebounce;

    // ---- right ----
    private final JLabel title = new JLabel("Select an API");
    private final JLabel subtitle = new JLabel(" ");
    private final LogListModel logModel = new LogListModel();
    private final LockedList<LogItem> logList = new LockedList<>(logModel);
    private final JScrollPane logScroll = new JScrollPane(logList);
    private final JTextField logSearch = new JTextField(22);
    private final JLabel logFooter = new JLabel(" ");
    private final JButton newButton = new JButton();
    private int currentApi = -1;
    private final java.util.Set<Long> countedNew = new java.util.HashSet<>();
    private int newCount;
    private boolean hasMore, loadingMore;
    private final AtomicInteger logGen = new AtomicInteger();
    private Timer logDebounce;
    /** Burp's UI font (User options → Display → font), used for API names, titles and log cells. */
    private final Font uiFont;

    ApiView(App app) {
        super(new BorderLayout());
        this.app = app;
        uiFont = burpDisplayFont(app);

        JComponent right = buildLogPanel();
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildApiPanel(), right);
        split.setDividerLocation(420);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
    }

    // =========================================================== left

    private JComponent buildApiPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 4));
        p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 0));
        JPanel top = new JPanel(new BorderLayout(0, 4));
        apiSearch.putClientProperty("JTextField.placeholderText", "Search");
        apiSearch.setToolTipText("Filter APIs by method/path/host, multiple words = AND (Ctrl+Shift+F, Esc to clear).");
        apiSearch.setFont(uiFont);
        apiFooter.setFont(uiFont);
        top.add(apiSearch, BorderLayout.NORTH);
        JPanel opts = new JPanel();
        opts.setLayout(new BoxLayout(opts, BoxLayout.X_AXIS));
        untestedMode.setFont(uiFont);
        untestedMode.setToolTipText("<html>Finds APIs in Proxy history that are <b>untested</b> (no send with changes yet)<br>"
                + "and in the <b>current scope</b> (Target → Scope, or right-click → Add to scope in HTTP history).<br>"
                + "The list updates automatically when the scope changes.</html>");
        opts.add(untestedMode);
        opts.add(Box.createHorizontalGlue());
        top.add(opts, BorderLayout.CENTER);
        p.add(top, BorderLayout.NORTH);

        apiRenderer = new ApiRenderer();
        apiList.lockRenderer(apiRenderer);
        // fixed cell size: JList need not re-measure every row on each list change (O(1) instead of O(n) on the EDT);
        // width = longest row (computed on list change) so long paths get a horizontal scrollbar instead of being cut
        apiList.setFixedCellHeight(apiRenderer.rowHeight());
        apiList.setFixedCellWidth(120);
        apiList.setSelectionModel(new HeaderSkippingSelection(apiModel));
        apiList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        apiList.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            Object v = apiList.getSelectedValue();
            if (v instanceof ApiItem ai && ai.row != null && ai.row.id() != currentApi) selectApi(ai.row);
            else if (v instanceof ApiItem ai && ai.row == null) showUntested(ai);
        });
        apiList.addMouseListener(popup(apiList, () -> {
            javax.swing.JPopupMenu m = new javax.swing.JPopupMenu();
            Object v = apiList.getSelectedValue();
            javax.swing.JMenuItem one = new javax.swing.JMenuItem("Copy log for AI (this API)");
            one.setEnabled(v instanceof ApiItem a && a.row != null);
            one.addActionListener(e -> { if (apiList.getSelectedValue() instanceof ApiItem a && a.row != null) copyForAi(a.row); });
            javax.swing.JMenuItem all = new javax.swing.JMenuItem("Export all logs for AI…");
            all.addActionListener(e -> exportAllForAi());
            m.add(one);
            m.add(all);
            return m;
        }));
        p.add(new JScrollPane(apiList), BorderLayout.CENTER);
        p.add(apiFooter, BorderLayout.SOUTH);

        apiDebounce = new Timer(150, e -> rebuildApiList());
        apiDebounce.setRepeats(false);
        onChange(apiSearch, () -> apiDebounce.restart());
        untestedMode.addActionListener(e -> { requestUntested(); rebuildApiList(); });
        try {                                                                 // scope added / removed: rescan now
            app.api.scope().registerScopeChangeHandler(ev -> SwingUtilities.invokeLater(() -> {
                if (untestedMode.isSelected()) requestUntested();
            }));
        } catch (Throwable ignored) { }
        apiSearch.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "clear");
        apiSearch.getActionMap().put("clear", action(() -> apiSearch.setText("")));
        return p;
    }

    void onReady(List<Rows.ApiRow> rows) {
        for (Rows.ApiRow r : rows) { apis.put(r.id(), r); indexApi(r); }
        app.bus.setSink(this::applyUpdates);
        rebuildApiList();
    }

    // ---- API list filtering ----
    /** Lowercase search key "method path host" per API, computed once when the API appears / changes. */
    private final Map<Integer, String> searchKeys = new HashMap<>();
    private int membership;                       // bumped when the API set or search keys change
    private String[] lastTerms = new String[0];
    private List<Integer> lastMatches;            // ids matching lastTerms, reused as the user keeps typing
    private int lastMatchMembership = -1;

    private void indexApi(Rows.ApiRow r) {
        String k = (r.method() + " " + r.pathKey() + " " + r.hostKey()).toLowerCase(Locale.ROOT);
        String old = searchKeys.put(r.id(), k);
        if (!k.equals(old)) membership++;
    }

    private void applyUpdates(List<Rows.ApiRow> changed, List<Rows.SendRow> sends) {
        boolean listChanged = false;
        for (Rows.ApiRow r : changed) {
            Rows.ApiRow old = apis.put(r.id(), r);
            indexApi(r);
            if (old == null || old.tested() != r.tested() || old.sendCount() != r.sendCount() || old.originals() != r.originals()) listChanged = true;
        }
        if (listChanged && !untestedMode.isSelected()) rebuildApiList();
        Rows.ApiRow cur = apis.get(currentApi);
        if (cur != null) updateHeader(cur);
        List<Rows.SendRow> mine = new ArrayList<>();
        for (Rows.SendRow s : sends) {
            if (s.apiId() != currentApi) continue;
            if (s.originalId() > 0 && !origSeqById.containsKey(s.originalId())) {   // new original, or log still loading
                if (!logLoading) reloadLog();
                return;
            }
            if (logModel.replace(sendItem(s))) continue;                     // running Intruder attack updated
            mine.add(s);
        }
        if (mine.isEmpty()) return;
        // a running Intruder row not loaded yet (filtered / not scrolled to) is updated many times: count it as new once
        mine.removeIf(s -> isIntruder(s) && !countedNew.add(s.id()));
        if (mine.isEmpty()) return;
        if (searching()) { newCount += mine.size(); updateNewButton(); return; }   // searching: don't insert unfiltered rows
        mine.sort(Comparator.comparingLong(Rows.SendRow::id));
        boolean atTop = logScroll.getVerticalScrollBar().getValue() < 20;
        if (atTop) {
            for (Rows.SendRow s : mine) logModel.addSendTop(sendItem(s));
            if (logModel.trimTo(MAX_ROWS)) hasMore = true;
            updateLogFooter();
        } else {
            newCount += mine.size();
            updateNewButton();
        }
    }

    private void rebuildApiList() {
        Object sel = apiList.getSelectedValue();
        String q = apiSearch.getText().trim().toLowerCase(Locale.ROOT);
        String[] ts = SearchTerms.terms(q);
        List<Object> items = new ArrayList<>();
        int shown = 0, total;
        if (untestedMode.isSelected()) {
            total = buildUntested(items, ts);
            shown = (int) items.stream().filter(o -> o instanceof ApiItem).count();
        } else {
            total = apis.size();
            TreeMap<String, List<ApiItem>> byHost = new TreeMap<>();
            // more chars typed: refilter only the previous matches (O(matches) instead of O(APIs))
            Collection<Integer> pool = (lastMatches != null && lastMatchMembership == membership
                    && SearchTerms.narrows(lastTerms, ts)) ? lastMatches : apis.keySet();
            List<Integer> matched = new ArrayList<>();
            for (Integer id : pool) {
                Rows.ApiRow r = apis.get(id);
                if (r == null) continue;
                String key = searchKeys.get(id);
                boolean match = ts.length == 0 || (key != null && SearchTerms.matchesAll(key, ts));
                if (!match) continue;
                matched.add(id);
                byHost.computeIfAbsent(r.hostKey(), k -> new ArrayList<>()).add(new ApiItem(r, null, 0));
            }
            lastTerms = ts; lastMatches = matched; lastMatchMembership = membership;
            for (Map.Entry<String, List<ApiItem>> e : byHost.entrySet()) {
                List<ApiItem> list = e.getValue();
                list.sort(Comparator.comparingLong((ApiItem a) -> -a.row.lastSeen()));
                items.add(new HostHeader(e.getKey(), list.size()));
                items.addAll(list);
                shown += list.size();
            }
        }
        apiModel.set(items);
        apiList.setFixedCellWidth(Math.max(120, apiRenderer.widthFor(items)));
        if (!untestedMode.isSelected()) apiFooter.setText(shown + "/" + total + " API");
        else if (untestedPending && total == 0) apiFooter.setText("Scanning Proxy history…");
        else if (total == 0) apiFooter.setText("No untested APIs in scope (is the host in Target → Scope?)");
        else apiFooter.setText(shown + "/" + total + (total == 1 ? " untested API in scope" : " untested APIs in scope"));
        if (sel instanceof ApiItem s) {
            for (int i = 0; i < items.size(); i++) {
                if (items.get(i) instanceof ApiItem a && sameItem(a, s)) { apiList.setSelectedIndex(i); break; }
            }
        }
    }

    private static boolean sameItem(ApiItem a, ApiItem b) {
        if (a.row != null && b.row != null) return a.row.id() == b.row.id();
        return a.row == null && b.row == null && a.statusKey != null && a.statusKey.equals(b.statusKey);
    }

    private Map<Integer, Integer> untestedCounts = Map.of();
    private boolean untestedPending;
    private int untestedGen;

    /** Re-query the history thread (scans the current scope); when results arrive, rebuild the list if changed. */
    private void requestUntested() {
        var h = app.history();
        if (h == null) return;
        int gen = ++untestedGen;
        untestedPending = true;
        h.snapshotUntestedInScope(m -> SwingUtilities.invokeLater(() -> {
            if (gen != untestedGen) return;
            boolean changed = untestedPending || !m.equals(untestedCounts);
            untestedPending = false;
            untestedCounts = m;
            if (changed && untestedMode.isSelected()) rebuildApiList();
        }));
    }

    /** Pre-split statusKey {method, host, path, lowercase} by id, so the untested list doesn't re-split strings. */
    private final Map<Integer, String[]> skParts = new HashMap<>();

    private String[] skPartsOf(int skId) {
        String[] p = skParts.get(skId);
        if (p != null) return p;
        String sk = app.registry.keyOf(skId);
        if (sk == null) return null;
        int sp = sk.indexOf(' ');
        if (sp < 0) return null;
        String method = sk.substring(0, sp), apiKey = sk.substring(sp + 1);
        int pathStart = apiKey.indexOf('/', apiKey.indexOf("://") + 3);
        if (pathStart < 0) return null;
        p = new String[]{method, apiKey.substring(0, pathStart), apiKey.substring(pathStart), sk.toLowerCase(Locale.ROOT), sk};
        skParts.put(skId, p);
        return p;
    }

    private int buildUntested(List<Object> items, String[] ts) {
        TreeMap<String, List<ApiItem>> byHost = new TreeMap<>();
        int total = 0;
        for (Map.Entry<Integer, Integer> e : untestedCounts.entrySet()) {
            String[] p = skPartsOf(e.getKey());
            if (p == null || app.status.get(p[4]) == StatusIndex.TESTED) continue;
            if (app.settings.excluded(p[0], p[2])) continue;
            total++;
            if (!SearchTerms.matchesAll(p[3], ts)) continue;
            byHost.computeIfAbsent(p[1], k -> new ArrayList<>()).add(new ApiItem(null, p[4], e.getValue()));
        }
        for (Map.Entry<String, List<ApiItem>> e : byHost.entrySet()) {
            e.getValue().sort(Comparator.comparing(a -> a.statusKey));
            items.add(new HostHeader(e.getKey(), e.getValue().size()));
            items.addAll(e.getValue());
        }
        return total;
    }

    private void showUntested(ApiItem ai) {
        currentApi = -1;
        logGen.incrementAndGet();
        logModel.clear();
        title.setText(ai.statusKey.substring(0, ai.statusKey.indexOf(' ')) + " " + pathOf(ai.statusKey));
        subtitle.setText(hostOf(ai.statusKey) + "  ·  " + ai.proxyCount + (ai.proxyCount == 1 ? " request" : " requests") + " in Proxy history  ·  untested");
        logFooter.setText("Click Send to Repeater to open this API's latest request from Proxy history (it becomes the original).");
    }

    private static String hostOf(String sk) {
        String apiKey = sk.substring(sk.indexOf(' ') + 1);
        int p = apiKey.indexOf('/', apiKey.indexOf("://") + 3);
        return p < 0 ? apiKey : apiKey.substring(0, p);
    }

    private static String pathOf(String sk) {
        String apiKey = sk.substring(sk.indexOf(' ') + 1);
        int p = apiKey.indexOf('/', apiKey.indexOf("://") + 3);
        return p < 0 ? "/" : apiKey.substring(p);
    }

    // =========================================================== export for AI

    /** Right-click: selects the row under the mouse, then shows the menu. */
    private static MouseAdapter popup(JList<?> list, java.util.function.Supplier<javax.swing.JPopupMenu> menu) {
        return new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }
            private void maybeShow(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int i = list.locationToIndex(e.getPoint());
                if (i >= 0 && list.getCellBounds(i, i).contains(e.getPoint())) list.setSelectedIndex(i);
                menu.get().show(list, e.getX(), e.getY());
            }
        };
    }

    /** Copies the Markdown log of an API (original request + response, tests, coverage) for pasting into an AI. */
    void copyForAi(Rows.ApiRow api) {
        Repo repo = app.repo();
        var t = app.tracker();
        if (repo == null || t == null) return;
        apitracker.core.Redactor r = t.redactor();
        java.util.Set<String> ignored = app.settings.ignoredHeaders;
        logFooter.setText("Building the log for AI…");
        app.searchExec.submit(() -> {
            try {
                String md = app.labels.apply(Markdown.legend() + "\n" + Markdown.api(repo, api, r, ignored));
                SwingUtilities.invokeLater(() -> {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(md), null);
                    String msg = "Copied the log of " + api.method() + " " + api.pathKey() + " for AI ("
                            + String.format("%,d", md.length()) + " characters).";
                    logFooter.setText(msg);
                    Log.info(msg);
                });
            } catch (Throwable ex) {
                Log.error("building the log for AI", ex);
                SwingUtilities.invokeLater(() -> logFooter.setText("Could not build the log: " + ex.getMessage()));
            }
        });
    }

    /** Same, by API key (host + path key), for Burp's context menu. */
    public void copyForAi(String apiKey) {
        for (Rows.ApiRow a : apis.values()) {
            if ((a.hostKey() + a.pathKey()).equals(apiKey)) { copyForAi(a); return; }
        }
        Log.info("No log yet for " + apiKey + ".");
        logFooter.setText("No log yet for " + apiKey + ".");
    }

    /** Writes the log of every API, plus the untested in-scope APIs from Proxy history, to one Markdown file. */
    private void exportAllForAi() {
        Repo repo = app.repo();
        var t = app.tracker();
        if (repo == null || t == null) return;
        String base = app.db() == null ? "api-logging" : app.db().file.getFileName().toString().replaceFirst("\\.db$", "");
        java.io.File dir = new java.io.File(app.settings.storageDir);
        javax.swing.JFileChooser fc = new javax.swing.JFileChooser(dir);
        fc.setDialogTitle("Export all logs for AI");
        fc.setSelectedFile(new java.io.File(dir, base + "-ai-log.md"));
        if (fc.showSaveDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) return;
        exportAllForAi(fc.getSelectedFile());
    }

    void exportAllForAi(java.io.File out) {
        Repo repo = app.repo();
        var t = app.tracker();
        if (repo == null || t == null) return;
        String base = app.db() == null ? "api-logging" : app.db().file.getFileName().toString().replaceFirst("\\.db$", "");
        List<Rows.ApiRow> list = new ArrayList<>(apis.values());
        list.sort(Comparator.comparing(Rows.ApiRow::hostKey).thenComparing(Rows.ApiRow::pathKey).thenComparing(Rows.ApiRow::method));
        apitracker.core.Redactor r = t.redactor();
        java.util.Set<String> ignored = app.settings.ignoredHeaders;
        apiFooter.setText("Exporting…");
        java.util.function.Consumer<List<Markdown.Untested>> write = untested -> app.searchExec.submit(() -> {
            try {
                String md = app.labels.apply(Markdown.all(repo, base, list, untested, r, ignored));
                java.nio.file.Files.writeString(out.toPath(), md, java.nio.charset.StandardCharsets.UTF_8);
                String msg = "Exported " + list.size() + (list.size() == 1 ? " API" : " APIs") + " for AI to " + out;
                SwingUtilities.invokeLater(() -> apiFooter.setText(msg));
                Log.info(msg);
            } catch (Throwable ex) {
                Log.error("exporting logs for AI", ex);
                SwingUtilities.invokeLater(() -> apiFooter.setText("Export failed: " + ex.getMessage()));
            }
        });
        var h = app.history();
        if (h == null) { write.accept(List.of()); return; }
        h.snapshotUntestedInScope(m -> SwingUtilities.invokeLater(() -> write.accept(untestedList(m))));
    }

    private List<Markdown.Untested> untestedList(Map<Integer, Integer> counts) {
        List<Markdown.Untested> out = new ArrayList<>();
        for (Map.Entry<Integer, Integer> e : counts.entrySet()) {
            String[] p = skPartsOf(e.getKey());
            if (p == null || app.status.get(p[4]) == StatusIndex.TESTED || app.settings.excluded(p[0], p[2])) continue;
            out.add(new Markdown.Untested(p[0], p[1] + p[2], e.getValue()));
        }
        out.sort(Comparator.comparing(Markdown.Untested::url).thenComparing(Markdown.Untested::method));
        return out;
    }

    void openApi(String apiKey) {
        untestedMode.setSelected(false);
        apiSearch.setText("");
        rebuildApiList();
        for (int i = 0; i < apiModel.getSize(); i++) {
            if (apiModel.getElementAt(i) instanceof ApiItem a && a.row != null
                    && (a.row.hostKey() + a.row.pathKey()).equals(apiKey)) {
                apiList.setSelectedIndex(i);
                apiList.ensureIndexIsVisible(i);
                return;
            }
        }
        title.setText("No log for this API yet");
        subtitle.setText(apiKey);
        logModel.clear();
        currentApi = -1;
    }

    void focusApiSearch() { apiSearch.requestFocusInWindow(); apiSearch.selectAll(); }
    void focusLogSearch() { logSearch.requestFocusInWindow(); logSearch.selectAll(); }

    private boolean searching() { return !logSearch.getText().trim().isEmpty(); }

    // =========================================================== right: log

    private JComponent buildLogPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 4));
        p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        JPanel titles = new JPanel();
        titles.setLayout(new BoxLayout(titles, BoxLayout.Y_AXIS));
        title.setFont(uiFont.deriveFont(Font.BOLD, uiFont.getSize2D() + 1f));
        subtitle.setFont(uiFont);
        title.setAlignmentX(LEFT_ALIGNMENT);
        subtitle.setAlignmentX(LEFT_ALIGNMENT);
        titles.add(title);
        titles.add(subtitle);
        JButton rep = new JButton("Send to Repeater");
        rep.setToolTipText("Reopen the selected request in a new Repeater tab (or double-click)");
        rep.addActionListener(e -> sendSelectedToRepeater());
        logSearch.putClientProperty("JTextField.placeholderText", "Search");
        logSearch.setToolTipText("Search this API's log, multiple words = AND (Ctrl+F, Esc to clear). Type a label name (userA) to find labeled tokens.");
        logSearch.setFont(uiFont);
        JPanel tools = new JPanel(new java.awt.GridBagLayout());     // search box + button, vertically centered on the title
        java.awt.GridBagConstraints gc = new java.awt.GridBagConstraints();
        gc.gridy = 0;
        gc.anchor = java.awt.GridBagConstraints.CENTER;
        gc.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gc.insets = new java.awt.Insets(0, 0, 0, 6);
        tools.add(logSearch, gc);
        gc.insets = new java.awt.Insets(0, 0, 0, 0);
        gc.fill = java.awt.GridBagConstraints.NONE;
        tools.add(rep, gc);
        JPanel head = new JPanel(new BorderLayout(8, 0));
        head.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        head.add(titles, BorderLayout.CENTER);
        head.add(tools, BorderLayout.EAST);
        p.add(head, BorderLayout.NORTH);

        logList.lockRenderer(new LogCell());
        logList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logList.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) { if (e.getClickCount() == 2) sendSelectedToRepeater(); }
        });
        logList.addMouseListener(popup(logList, () -> {
            javax.swing.JPopupMenu m = new javax.swing.JPopupMenu();
            javax.swing.JMenuItem toRep = new javax.swing.JMenuItem("Send to Repeater");
            toRep.setEnabled(logList.getSelectedValue() != null);
            toRep.addActionListener(e -> sendSelectedToRepeater());
            javax.swing.JMenuItem one = new javax.swing.JMenuItem("Copy log for AI (this API)");
            Rows.ApiRow cur = apis.get(currentApi);
            one.setEnabled(cur != null);
            one.addActionListener(e -> { Rows.ApiRow c = apis.get(currentApi); if (c != null) copyForAi(c); });
            m.add(toRep);
            m.add(one);
            return m;
        }));
        logScroll.getVerticalScrollBar().setUnitIncrement(16);
        logScroll.getVerticalScrollBar().addAdjustmentListener(e -> maybeLoadMore());
        p.add(logScroll, BorderLayout.CENTER);

        JPanel foot = new JPanel(new BorderLayout());
        logFooter.setFont(uiFont);
        foot.add(logFooter, BorderLayout.CENTER);
        newButton.setVisible(false);
        newButton.addActionListener(e -> { newCount = 0; updateNewButton(); reloadLog(); });
        foot.add(newButton, BorderLayout.EAST);
        p.add(foot, BorderLayout.SOUTH);

        logDebounce = new Timer(250, e -> reloadLog());
        logDebounce.setRepeats(false);
        onChange(logSearch, () -> logDebounce.restart());
        logSearch.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "clear");
        logSearch.getActionMap().put("clear", action(() -> logSearch.setText("")));
        return p;
    }

    private void selectApi(Rows.ApiRow r) {
        currentApi = r.id();
        newCount = 0;
        updateNewButton();
        updateHeader(r);
        reloadLog();
    }

    private void updateHeader(Rows.ApiRow r) {
        title.setText(r.method() + " " + r.pathKey());
        subtitle.setText(r.hostKey() + "  ·  " + r.sendCount() + (r.sendCount() == 1 ? " send  ·  " : " sends  ·  ") + r.originals()
                + (r.originals() == 1 ? " original  ·  " : " originals  ·  ") + (r.tested() ? "tested" : "untested"));
    }

    private void reloadLog() {
        if (currentApi < 0) return;
        countedNew.clear();
        Repo repo = app.repo();
        if (repo == null) return;
        int api = currentApi, gen = logGen.incrementAndGet();
        String q = logSearch.getText();
        boolean plain = q.trim().isEmpty();
        List<String> alts = plain ? List.of() : app.labels.alternativesFor(q);
        Rows.ApiRow ar = apis.get(api);
        int size = ar == null ? Integer.MAX_VALUE : ar.sendCount();
        logFooter.setText(plain ? "Loading…" : "Searching…");
        logLoading = true;
        app.searchExec.submit(() -> {
            try {
                List<Rows.OriginalRow> origs = repo.originals(api);
                List<Rows.SendRow> rows = plain ? repo.page(api, Long.MAX_VALUE, PAGE, Repo.Filter.ALL)
                        : repo.search(api, q, alts, Repo.Filter.ALL, Long.MAX_VALUE, PAGE, size);
                SwingUtilities.invokeLater(() -> {
                    if (gen != logGen.get()) return;
                    logLoading = false;
                    origSeqById.clear();
                    for (Rows.OriginalRow o : origs) origSeqById.put(o.id(), number(o));
                    List<LogItem> items = new ArrayList<>();
                    for (Rows.SendRow s : rows) items.add(sendItem(s));
                    List<LogItem> og = new ArrayList<>();
                    for (Rows.OriginalRow o : origs) og.add(new LogItem(o, null));
                    logModel.set(og, items);
                    hasMore = rows.size() == PAGE;
                    newCount = 0;
                    updateNewButton();
                    updateLogFooter();
                    logScroll.getVerticalScrollBar().setValue(0);
                });
            } catch (Throwable t) {
                Log.rateLimited(t);
                SwingUtilities.invokeLater(() -> { logLoading = false; logFooter.setText("Query error: " + t.getMessage()); });
            }
        });
    }

    private void maybeLoadMore() {
        if (!hasMore || loadingMore || currentApi < 0) return;
        var sb = logScroll.getVerticalScrollBar();
        if (sb.getValue() + sb.getVisibleAmount() < sb.getMaximum() - 200) return;
        long before = logModel.lastSendId();
        if (before <= 0) return;
        Repo repo = app.repo();
        if (repo == null) return;
        int api = currentApi, gen = logGen.get();
        String q = logSearch.getText();
        boolean plain = q.trim().isEmpty();
        List<String> alts = plain ? List.of() : app.labels.alternativesFor(q);
        Rows.ApiRow ar = apis.get(api);
        int size = ar == null ? Integer.MAX_VALUE : ar.sendCount();
        loadingMore = true;
        app.searchExec.submit(() -> {
            try {
                List<Rows.SendRow> rows = plain ? repo.page(api, before, PAGE, Repo.Filter.ALL)
                        : repo.search(api, q, alts, Repo.Filter.ALL, before, PAGE, size);
                SwingUtilities.invokeLater(() -> {
                    loadingMore = false;
                    if (gen != logGen.get()) return;
                    for (Rows.SendRow s : rows) logModel.addSendBottom(sendItem(s));
                    hasMore = rows.size() == PAGE;
                    updateLogFooter();
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> loadingMore = false);
                Log.rateLimited(t);
            }
        });
    }

    private void updateLogFooter() {
        Rows.ApiRow r = apis.get(currentApi);
        int n = logModel.sendCount();
        String total = r == null ? "" : "/" + r.sendCount();
        logFooter.setText(searching() ? n + (hasMore ? "+" : "") + (n == 1 ? " matching send" : " matching sends")
                : n + total + ((r == null ? n : r.sendCount()) == 1 ? " send" : " sends") + " · diff vs original request");
    }

    private void updateNewButton() {
        newButton.setVisible(newCount > 0);
        newButton.setText("↓ " + newCount + (newCount == 1 ? " new send" : " new sends"));
    }

    /** Reads a log row's raw request from the DB (tracker-search thread), delivers it on the EDT (null if none). */
    private void loadRequest(LogItem it, Rows.ApiRow api, java.util.function.Consumer<HttpRequest> onEdt) {
        Repo repo = app.repo();
        if (repo == null) return;
        app.searchExec.submit(() -> {
            try {
                byte[] raw;
                String host;
                int port;
                boolean secure;
                if (it.original != null) {
                    Repo.RawReq rr = repo.originalRaw(it.original.id());
                    raw = rr == null ? null : Zip.inflate(rr.requestZ());
                    host = rr == null ? null : rr.host(); port = rr == null ? 0 : rr.port(); secure = rr != null && rr.secure();
                } else {
                    raw = repo.sendRaw(it.send.id());
                    String[] hp = parseHostKey(api.hostKey());
                    host = hp[1]; port = Integer.parseInt(hp[2]); secure = hp[0].equals("https");
                }
                HttpRequest req = (raw == null || host == null) ? null
                        : HttpRequest.httpRequest(HttpService.httpService(host, port, secure), ByteArray.byteArray(raw));
                SwingUtilities.invokeLater(() -> onEdt.accept(req));
            } catch (Throwable t) {
                Log.rateLimited(t);
            }
        });
    }

    static String[] parseHostKey(String hostKey) {
        int s = hostKey.indexOf("://");
        String scheme = hostKey.substring(0, s);
        String rest = hostKey.substring(s + 3);
        int colon = rest.lastIndexOf(':');
        String host = rest.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        return new String[]{scheme, host, rest.substring(colon + 1)};
    }

    /** Sends exactly the selected row (raw request re-read from the DB). */
    private void sendSelectedToRepeater() {
        if (apiList.getSelectedValue() instanceof ApiItem ai && ai.row == null) { sendUntestedToRepeater(ai); return; }
        LogItem it = logList.getSelectedValue();
        Rows.ApiRow api = apis.get(currentApi);
        if (it == null || api == null) return;
        String suffix = " #" + (it.send != null ? number(it.send) : number(it.original));
        loadRequest(it, api, req -> {
            if (req == null) { logFooter.setText("No raw request for this row."); return; }
            try {
                // Name = the request's real method + path (no query), not the {id}-normalized pathKey.
                String line = firstLine(req.toByteArray().getBytes());
                String name = (line.isEmpty() ? TabNames.tabName(api.method(), api.pathKey(), java.util.Set.of())
                        : TabNames.fromRequestLine(line, java.util.Set.of())) + suffix;
                app.api.repeater().sendToRepeater(req, name);
            } catch (Throwable t) {
                Log.error("send to Repeater", t);
            }
        });
    }

    /** Untested API (no log yet): takes its latest request from Proxy history and sends it like Send to Repeater (tracked). */
    private void sendUntestedToRepeater(ApiItem ai) {
        var h = app.history();
        if (h == null) return;
        logFooter.setText("Fetching request from Proxy history…");
        h.latestItem(ai.statusKey, item -> {
            burp.api.montoya.http.message.requests.HttpRequest req = null;
            burp.api.montoya.http.message.responses.HttpResponse resp = null;
            try {
                if (item != null) {
                    req = item.finalRequest();
                    resp = item.hasResponse() ? item.response() : null;
                }
            } catch (Throwable t) { Log.rateLimited(t); }
            final var fReq = req;
            final var fResp = resp;
            SwingUtilities.invokeLater(() -> afterUntestedFetch(fReq, fResp));
        });
    }

    private void afterUntestedFetch(burp.api.montoya.http.message.requests.HttpRequest req,
                                    burp.api.montoya.http.message.responses.HttpResponse resp) {
        if (req == null) { logFooter.setText("This request is no longer in Proxy history."); return; }
        app.sendTracked(req, resp);
        logFooter.setText("Sent to Repeater. Edit and send it in Repeater to start logging.");
    }

    private static String firstLine(byte[] b) {
        if (b == null) return "";
        int end = 0, max = Math.min(b.length, 8192);
        while (end < max && b[end] != '\r' && b[end] != '\n') end++;
        return new String(b, 0, end, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    void dispose() {
        SwingUtilities.invokeLater(() -> {
            if (apiDebounce != null) apiDebounce.stop();
            if (logDebounce != null) logDebounce.stop();
        });
    }

    // =========================================================== models & renderers

    record HostHeader(String host, int count) {
        @Override public String toString() { return host + "  (" + count + ")"; }
    }

    static final class ApiItem {
        final Rows.ApiRow row;       // null for "untested" items from Proxy
        final String statusKey;
        final int proxyCount;
        ApiItem(Rows.ApiRow row, String statusKey, int proxyCount) {
            this.row = row; this.statusKey = statusKey; this.proxyCount = proxyCount;
        }
        private String label;
        /** Text shown in the list: the API's method + full path (no query). */
        String label() {
            if (label == null) {
                label = row != null ? TabNames.tabName(row.method(), row.pathKey(), null)
                        : TabNames.tabName(statusKey.substring(0, statusKey.indexOf(' ')), pathOf(statusKey), null);
            }
            return label;
        }
        @Override public String toString() { return label(); }
    }

    static final class ApiListModel extends AbstractListModel<Object> {
        private List<Object> items = List.of();
        void set(List<Object> it) {
            int old = items.size();
            items = it;
            if (old > 0) fireIntervalRemoved(this, 0, old - 1);
            if (!it.isEmpty()) fireIntervalAdded(this, 0, it.size() - 1);
        }
        @Override public int getSize() { return items.size(); }
        @Override public Object getElementAt(int i) { return items.get(i); }
    }

    /** Prevents selecting host header rows. */
    static final class HeaderSkippingSelection extends DefaultListSelectionModel {
        private final ApiListModel m;
        HeaderSkippingSelection(ApiListModel m) { this.m = m; }
        @Override public void setSelectionInterval(int a, int b) {
            if (b >= 0 && b < m.getSize() && m.getElementAt(b) instanceof HostHeader) {
                int next = b + 1 < m.getSize() ? b + 1 : b - 1;
                if (next >= 0 && next < m.getSize() && !(m.getElementAt(next) instanceof HostHeader)) super.setSelectionInterval(next, next);
                return;
            }
            super.setSelectionInterval(a, b);
        }
    }

    /** One row per API: yellow dot (untested) + method + full path. Send count and time go in the tooltip and log header. */
    private final class ApiRenderer implements ListCellRenderer<Object> {
        private static final int PAD_X = 6;
        private final JPanel row = new JPanel(new BorderLayout(6, 0));
        private final JLabel dot = new JLabel("●");
        private final JLabel main = new JLabel();
        private final JLabel header = new JLabel();
        private final Color untested;
        private final FontMetrics mainFm, headerFm;
        private final Map<String, Integer> widths = new HashMap<>();
        private final SimpleDateFormat when = new SimpleDateFormat("HH:mm dd/MM");   // EDT only

        ApiRenderer() {
            row.add(dot, BorderLayout.WEST);
            row.add(main, BorderLayout.CENTER);
            row.setBorder(BorderFactory.createEmptyBorder(4, PAD_X, 4, PAD_X));
            main.setFont(uiFont);
            header.setFont(uiFont.deriveFont(Font.BOLD));
            header.setVerticalAlignment(JLabel.BOTTOM);
            header.setBorder(BorderFactory.createEmptyBorder(6, PAD_X, 2, PAD_X));
            header.setOpaque(true);
            mainFm = main.getFontMetrics(main.getFont());
            headerFm = header.getFontMetrics(header.getFont());
            Color c;
            try { c = app.api.userInterface().swingUtils().colorForHighLight(HighlightColor.YELLOW); } catch (Throwable t) { c = null; }
            untested = c != null ? c.darker() : new Color(0xD4A017);
        }

        /** Fixed height for every cell (API rows and host headers equally tall, no extra gaps). */
        int rowHeight() {
            main.setText("GET /x");
            header.setText("https://x");
            return Math.max(row.getPreferredSize().height, header.getPreferredSize().height);
        }

        /** Width needed to show the longest row in full (cached per string, not re-measured on each list change). */
        int widthFor(List<Object> items) {
            if (widths.size() > 20_000) widths.clear();
            int dotW = mainFm.stringWidth("●") + 6, w = 0;
            for (Object o : items) {
                if (o instanceof ApiItem a) {
                    w = Math.max(w, dotW + widths.computeIfAbsent(a.label(), mainFm::stringWidth));
                } else if (o instanceof HostHeader h) {
                    w = Math.max(w, widths.computeIfAbsent("\u0000" + h, k -> headerFm.stringWidth(h.toString())));
                }
            }
            return w + 2 * PAD_X + 4;
        }

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
            Color quietC = UIManager.getColor("Label.disabledForeground") != null ? UIManager.getColor("Label.disabledForeground") : Color.GRAY;
            if (value instanceof HostHeader h) {
                header.setText(h.toString());
                header.setBackground(list.getBackground());
                header.setForeground(quietC);
                return header;
            }
            ApiItem a = (ApiItem) value;
            Color fg = selected ? list.getSelectionForeground() : list.getForeground();
            row.setBackground(selected ? list.getSelectionBackground() : list.getBackground());
            main.setForeground(fg);
            main.setText(a.label());
            String l1, l2;
            if (a.row != null) {
                dot.setForeground(a.row.tested() ? row.getBackground() : untested);
                l1 = a.row.method() + " " + a.row.hostKey() + a.row.pathKey();
                l2 = a.row.sendCount() + (a.row.sendCount() == 1 ? " send" : " sends")
                        + "  ·  " + when.format(new Date(a.row.lastSeen())) + (a.row.tested() ? "  ·  tested" : "  ·  untested");
            } else {
                dot.setForeground(untested);
                l1 = a.statusKey;
                l2 = a.proxyCount + (a.proxyCount == 1 ? " request" : " requests") + " in Proxy history  ·  untested  ·  in scope";
            }
            row.setToolTipText("<html>" + html(l1) + "<br>" + html(l2) + "</html>");
            return row;
        }
    }

    /** Burp's current display font; if missing (mock / old Burp), the look-and-feel Label font (also set by Burp). */
    static Font burpDisplayFont(App app) {
        Font f = null;
        try { f = app.api.userInterface().currentDisplayFont(); } catch (Throwable ignored) { }
        if (f == null) f = UIManager.getFont("Label.font");
        return f != null ? f : new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    }

    private static String html(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Number of the API's originals (id → #), to show "(vs original #n)" in the API's own numbering. */
    private final Map<Integer, Integer> origSeqById = new HashMap<>();
    private boolean logLoading;

    private LogItem sendItem(Rows.SendRow s) {
        LogItem it = new LogItem(null, s);
        it.origSeq = origSeqById.getOrDefault(s.originalId(), 0);
        return it;
    }

    /** Entry number in its API's log (#1, #2…); the global id on an old DB without numbers. */
    static long number(Rows.SendRow s) { return s.seq() > 0 ? s.seq() : s.id(); }
    static int number(Rows.OriginalRow o) { return o.seq() > 0 ? o.seq() : o.id(); }

    static final class LogItem {
        final Rows.OriginalRow original;
        final Rows.SendRow send;
        int origSeq;                 // # of the original this send is compared against (0 = unknown)
        String[] lines;              // lines shown in the cell (labels applied, truncated)
        Dimension size;              // cell size, computed once
        int cachedLabels = -1;
        LogItem(Rows.OriginalRow o, Rows.SendRow s) { original = o; send = s; }
        @Override public String toString() { return headLine(this); }
    }

    static final class LogListModel extends AbstractListModel<LogItem> {
        private final List<LogItem> originals = new ArrayList<>();
        private final List<LogItem> sends = new ArrayList<>();

        void set(List<LogItem> og, List<LogItem> s) {
            int old = getSize();
            originals.clear(); originals.addAll(og);
            sends.clear(); sends.addAll(s);
            if (old > 0) fireIntervalRemoved(this, 0, old - 1);
            if (getSize() > 0) fireIntervalAdded(this, 0, getSize() - 1);
        }
        void clear() { set(List.of(), List.of()); }
        void addSendTop(LogItem it) {
            int n = Math.min(sends.size(), 50);
            for (int i = 0; i < n; i++) if (sends.get(i).send.id() == it.send.id()) return;
            sends.add(0, it);
            fireIntervalAdded(this, originals.size(), originals.size());
        }
        /** Replaces the row with the same id (summary row of a running Intruder attack). Returns true if it was listed. */
        boolean replace(LogItem it) {
            long id = it.send.id();
            for (int i = 0; i < sends.size(); i++) {
                if (sends.get(i).send.id() != id) continue;
                sends.set(i, it);
                int idx = originals.size() + i;
                fireContentsChanged(this, idx, idx);
                return true;
            }
            return false;
        }
        void addSendBottom(LogItem it) {
            sends.add(it);
            int i = getSize() - 1;
            fireIntervalAdded(this, i, i);
        }
        /** Drops the oldest sends at the end of the list beyond {@code max}. Returns true if any were dropped. */
        boolean trimTo(int max) {
            if (sends.size() <= max) return false;
            int from = originals.size() + max, to = getSize() - 1;
            sends.subList(max, sends.size()).clear();
            fireIntervalRemoved(this, from, to);
            return true;
        }
        long lastSendId() { return sends.isEmpty() ? -1 : sends.get(sends.size() - 1).send.id(); }
        int sendCount() { return sends.size(); }
        @Override public int getSize() { return originals.size() + sends.size(); }
        @Override public LogItem getElementAt(int i) {
            return i < originals.size() ? originals.get(i) : sends.get(i - originals.size());
        }
    }

    private static final SimpleDateFormat TIME = new SimpleDateFormat("HH:mm:ss");   // EDT only

    /** First line of a log entry: time, source, first line, original compared against. */
    private static String headLine(LogItem it) {
        if (it.original != null) {
            Rows.OriginalRow o = it.original;
            return "#" + number(o) + "  " + TIME.format(new Date(o.ts())) + "  (" + Rows.originalSourceName(o.source()) + ")";
        }
        Rows.SendRow s = it.send;
        StringBuilder b = new StringBuilder(128);
        b.append('#').append(number(s)).append("  ").append(TIME.format(new Date(s.ts()))).append("  ");
        if (isIntruder(s)) {
            b.append((s.flags() & Rows.FLAG_RUNNING) != 0 ? "[Intruder · running]  " : "[Intruder]  ").append(s.firstLine());
            return b.toString();
        }
        if (!"repeater".equals(s.source())) {
            b.append(s.source().startsWith("ai:") ? "[AI:" + s.source().substring(3) + "]  " : "[AI]  ");
        }
        b.append(s.firstLine());
        if (s.originalId() > 0) {
            if (it.origSeq > 0) b.append("   (vs original #").append(it.origSeq).append(')');
            else if (s.seq() == 0) b.append("   (vs original #").append(s.originalId()).append(')');   // old DB: global ids
            else b.append("   (vs original)");
        }
        return b.toString();
    }

    static boolean isIntruder(Rows.SendRow s) { return (s.flags() & Rows.FLAG_INTRUDER) != 0; }

    private static String emptyChangesText(Rows.SendRow s) {
        if ((s.flags() & Rows.FLAG_ORIGINAL_UNAVAILABLE) != 0) return "(original request unreadable: diff skipped)";
        if ((s.flags() & Rows.FLAG_NO_ORIGINAL) != 0) return "(no original yet: AI requests are never used as the original)";
        if ((s.flags() & Rows.FLAG_SELF_ORIGINAL) != 0) return "(first send, used as the original)";
        return "(no change vs original)";
    }

    private static String responseLine(Rows.SendRow s) {
        StringBuilder b = new StringBuilder("→ ");
        if ((s.flags() & Rows.FLAG_NO_RESPONSE) != 0 || s.status() <= 0) b.append("no response");
        else {
            b.append(s.status()).append(" · ").append(String.format("%,d B", Math.max(0, s.length())));
            if (s.ms() >= 0) b.append(" · ").append(s.ms()).append(" ms");
        }
        if ((s.flags() & Rows.FLAG_REDIRECT) != 0) b.append("   [auto-followed redirect, not counted as a test]");
        return b.toString();
    }

    /** Lines shown in a cell: all changes (full log), each at most {@link #MAX_LINE_CHARS} chars. */
    static String[] cellLines(LogItem it, Labels labels) {
        List<String> out = new ArrayList<>(8);
        out.add(headLine(it));
        if (it.original != null) out.add("    " + it.original.firstLine());
        else {
            Rows.SendRow s = it.send;
            String ch = s.changes();
            boolean intr = isIntruder(s);
            if (ch == null || ch.isEmpty()) out.add("    " + emptyChangesText(s));
            else for (String line : ch.split("\n")) out.add("    " + line);
            if (!intr) out.add("    " + responseLine(s));     // Intruder: the stats line is in changes
        }
        String[] lines = new String[out.size()];
        for (int i = 0; i < lines.length; i++) {
            String l = labels.apply(out.get(i));
            lines[i] = l.length() > MAX_LINE_CHARS ? l.substring(0, MAX_LINE_CHARS) + "…" : l;
        }
        return lines;
    }

    /**
     * Custom-painted log cell: no JTextArea (building a document and layout on every measure is costly). Lines and size
     * are computed once per entry and cached, so JList re-measuring the whole list just reads the cache.
     */
    private final class LogCell extends JComponent implements ListCellRenderer<LogItem> {
        private static final int PAD_X = 8, PAD_Y = 4;
        private final FontMetrics fm;
        private final int lineH;
        /** Columns (pixels) for proportional fonts: indent, position column (header/body…), name + value column. */
        private final int indentX, locX, restX;
        private final Color sep;
        private final Map<?, ?> hints;
        private LogItem item;
        private boolean selected;
        private Color bg, fg;
        private Color add, del, mod, pos, quiet;

        LogCell() {
            fm = logList.getFontMetrics(uiFont);
            lineH = fm.getHeight() + 1;
            int em = fm.charWidth('m');
            indentX = PAD_X + 2 * em;
            int opW = 0;
            for (char c : CHANGE_OPS.toCharArray()) opW = Math.max(opW, fm.charWidth(c));
            locX = indentX + opW + Math.max(4, em / 2);
            int locW = 0;
            for (String l : LOC_NAMES) locW = Math.max(locW, fm.stringWidth(l));
            restX = locX + locW + em;
            Color s = UIManager.getColor("Separator.foreground");
            sep = s != null ? s : Color.LIGHT_GRAY;
            Object h = Toolkit.getDefaultToolkit().getDesktopProperty("awt.font.desktophints");
            hints = h instanceof Map<?, ?> m ? m : null;
            setOpaque(true);
        }

        @Override
        public Component getListCellRendererComponent(JList<? extends LogItem> list, LogItem it, int index, boolean sel, boolean focus) {
            if (it.lines == null || it.cachedLabels != app.labels.version()) {
                it.lines = cellLines(it, app.labels);
                it.cachedLabels = app.labels.version();
                int w = 0;
                for (int i = 0; i < it.lines.length; i++) w = Math.max(w, lineWidth(it.lines[i], i == 0));
                it.size = new Dimension(w + PAD_X, it.lines.length * lineH + 2 * PAD_Y + 1);
            }
            item = it;
            selected = sel;
            bg = sel ? list.getSelectionBackground() : list.getBackground();
            fg = sel ? list.getSelectionForeground() : list.getForeground();
            if (add == null || quiet == null) palette(list.getBackground());
            return this;
        }

        private void palette(Color background) {
            boolean dark = background != null
                    && (background.getRed() * 299 + background.getGreen() * 587 + background.getBlue() * 114) / 1000 < 128;
            add = dark ? new Color(0x81C995) : new Color(0x1E7E34);
            del = dark ? new Color(0xF28B82) : new Color(0xC5221F);
            mod = dark ? new Color(0xFDD663) : new Color(0xA35C00);
            pos = dark ? new Color(0xC58AF9) : new Color(0x7B1FA2);
            Color q = UIManager.getColor("Label.disabledForeground");
            quiet = q != null ? q : Color.GRAY;
        }

        @Override public Dimension getPreferredSize() { return item == null ? new Dimension(10, lineH) : item.size; }

        private int lineWidth(String l, boolean head) {
            if (head) return PAD_X + fm.stringWidth(l);
            int[] c = changeCols(l);
            if (c == null) return indentX + fm.stringWidth(l.stripLeading());
            return c[3] < l.length() ? restX + fm.stringWidth(l.substring(c[3])) : restX;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                if (hints != null) g2.addRenderingHints(hints);
                g2.setColor(bg);
                g2.fillRect(0, 0, getWidth(), getHeight());
                g2.setFont(uiFont);
                String[] lines = item == null ? new String[0] : item.lines;
                // cells can be very tall (full log): paint only the lines in the visible area
                Rectangle clip = g2.getClipBounds();
                int from = 0, to = lines.length;
                if (clip != null) {
                    from = Math.max(0, (clip.y - PAD_Y) / lineH);
                    to = Math.min(lines.length, (clip.y + clip.height - PAD_Y) / lineH + 1);
                }
                int y = PAD_Y + fm.getAscent() + from * lineH;
                for (int i = from; i < to; i++) {
                    String l = lines[i];
                    g2.setColor(selected || i == 0 ? fg : colorFor(l));
                    int[] c = i == 0 ? null : changeCols(l);
                    if (i == 0) g2.drawString(l, PAD_X, y);
                    else if (c == null) g2.drawString(l.stripLeading(), indentX, y);
                    else {
                        g2.drawString(l.substring(c[0], c[0] + 1), indentX, y);
                        g2.drawString(l.substring(c[1], c[2]), locX, y);
                        if (c[3] < l.length()) g2.drawString(l.substring(c[3]), restX, y);
                    }
                    y += lineH;
                }
                g2.setColor(sep);
                g2.drawLine(0, getHeight() - 1, getWidth(), getHeight() - 1);
            } finally {
                g2.dispose();
            }
        }

        private Color colorFor(String line) {
            int i = 0;
            while (i < line.length() && line.charAt(i) == ' ') i++;
            if (i + 1 >= line.length() || line.charAt(i + 1) != ' ') return line.startsWith("→", i) ? quiet : fg;
            switch (line.charAt(i)) {
                case '§': return pos;
                case '+': return add;
                case '-': return del;
                case '~': return mod;
                default: return fg;
            }
        }
    }

    static final String CHANGE_OPS = "+-~§";
    static final String[] LOC_NAMES = {"method", "path", "query", "header", "cookie", "body"};

    /**
     * Change line like {@code "    ~ header  Authorization   a → b"}: returns {op index, position name start, position name end,
     * rest start}, or null if not a change line. Used to paint aligned columns with proportional fonts.
     */
    static int[] changeCols(String l) {
        int n = l.length(), i = 0;
        while (i < n && l.charAt(i) == ' ') i++;
        if (i == 0 || i + 2 >= n || CHANGE_OPS.indexOf(l.charAt(i)) < 0 || l.charAt(i + 1) != ' ') return null;
        int ls = i + 2, le = ls;
        while (le < n && Character.isLetter(l.charAt(le))) le++;
        boolean known = false;
        for (String name : LOC_NAMES) {
            if (name.length() == le - ls && l.regionMatches(ls, name, 0, name.length())) { known = true; break; }
        }
        if (!known) return null;
        int rs = le;
        while (rs < n && l.charAt(rs) == ' ') rs++;
        return new int[]{i, ls, le, rs};
    }

    // =========================================================== utilities

    private static void onChange(JTextField f, Runnable r) {
        f.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { r.run(); }
            @Override public void removeUpdate(DocumentEvent e) { r.run(); }
            @Override public void changedUpdate(DocumentEvent e) { r.run(); }
        });
    }

    private static javax.swing.Action action(Runnable r) {
        return new javax.swing.AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { r.run(); }
        };
    }
}
