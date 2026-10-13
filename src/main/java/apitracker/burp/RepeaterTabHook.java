package apitracker.burp;

import apitracker.core.ApiKeys;
import apitracker.core.Events;
import apitracker.core.TabNames;
import apitracker.core.Tracker;
import apitracker.store.Rows;
import apitracker.util.Log;
import burp.api.montoya.MontoyaApi;

import javax.swing.JLabel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.ChangeListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import java.awt.Component;
import java.awt.Container;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Tiers 2–3 of Repeater tab renaming, for Ctrl+R / Burp's own menu. A Swing hack, so strictly best-effort:
 * <ul>
 *   <li>Runs only on the EDT, event-driven; each probe takes at most 2 ms, then yields; no polling.</li>
 *   <li>One shared Timer for all new tabs; ignores the first 10 seconds while Burp restores the project's tabs.</li>
 *   <li>Reads only the first 1 MB of the editor; only renames tabs with purely numeric names.</li>
 *   <li>Disables itself after 5 consecutive failures; never breaks Burp.</li>
 * </ul>
 */
public final class RepeaterTabHook {
    private static final long STEP_BUDGET_NS = 2_000_000;
    private static final int MAX_READ = 1024 * 1024;
    private static final Pattern REQUEST_LINE = Pattern.compile("^[A-Z]{3,10} \\S+ HTTP/[0-9.]+\\r?$");

    private final MontoyaApi api;
    private final Supplier<Tracker> tracker;
    private final ApiKeys keys;
    private final long loadedAt = System.currentTimeMillis();

    private JTabbedPane mainPane;
    private final List<JTabbedPane> subPanes = new ArrayList<>();
    private final Map<Component, Boolean> processed = new WeakHashMap<>();
    private final Map<Component, Integer> retries = new WeakHashMap<>();
    private final Set<String> usedNames = new HashSet<>();
    private ArrayDeque<Component> bfs;
    private Timer stepTimer, newTabTimer;
    private ChangeListener mainListener;
    private final ContainerListener containerListener = new ContainerListener() {
        @Override public void componentAdded(ContainerEvent e) { scheduleNewTabs(); }
        @Override public void componentRemoved(ContainerEvent e) { }
    };
    private final ChangeListener subListener = e -> scheduleNewTabs();
    private int consecutiveFailures;
    private volatile boolean disabled;

    public RepeaterTabHook(MontoyaApi api, Supplier<Tracker> tracker, ApiKeys keys) {
        this.api = api;
        this.tracker = tracker;
        this.keys = keys;
    }

    public boolean active() { return !disabled && mainPane != null; }

    /** Call on the EDT. Starts probing the component tree after 10 seconds. */
    public void start() {
        stepTimer = new Timer(10_000, e -> discoverStep());
        stepTimer.setRepeats(false);
        stepTimer.start();
        newTabTimer = new Timer(150, e -> processNewTabs());
        newTabTimer.setRepeats(false);
    }

    // ---------- find the main JTabbedPane holding the "Repeater" tab ----------

    private void discoverStep() {
        if (disabled) return;
        try {
            if (bfs == null) {
                bfs = new ArrayDeque<>();
                Component root = api.userInterface().swingUtils().suiteFrame();
                if (root == null) { fail("could not get the Burp window"); return; }
                bfs.add(root);
            }
            long t0 = System.nanoTime();
            while (!bfs.isEmpty() && System.nanoTime() - t0 < STEP_BUDGET_NS) {
                Component c = bfs.poll();
                if (c instanceof JTabbedPane tp) {
                    int idx = indexOfTitle(tp, "Repeater");
                    if (idx >= 0) { attachMain(tp, idx); bfs = null; return; }
                }
                if (c instanceof Container ct) Collections.addAll(bfs, ct.getComponents());
            }
            if (bfs.isEmpty()) {
                bfs = null;
                disabled = true;
                Log.warn("Repeater tab area not found in the Burp UI. Auto-rename for Ctrl+R is disabled;"
                        + " use \"Send to Repeater (tracked)\" (context menu or hotkey) to name tabs.");
                return;
            }
            stepTimer.setInitialDelay(200);
            stepTimer.restart();
        } catch (Throwable t) {
            fail(t.toString());
        }
    }

    private void attachMain(JTabbedPane tp, int idx) {
        mainPane = tp;
        mainListener = e -> {
            int i = indexOfTitle(mainPane, "Repeater");
            if (i >= 0 && mainPane.getSelectedIndex() == i) findSubPanes(i);
        };
        tp.addChangeListener(mainListener);
        findSubPanes(idx);
        Log.info("Attached to the Repeater tab area (" + subPanes.size() + (subPanes.size() == 1 ? " tab group)." : " tab groups)."));
    }

    /** Finds the child JTabbedPanes under the Repeater tab (supports tab groups). 2 ms budget. */
    private void findSubPanes(int idx) {
        try {
            Component root = mainPane.getComponentAt(idx);
            if (root == null) return;
            ArrayDeque<Component> q = new ArrayDeque<>();
            q.add(root);
            long t0 = System.nanoTime();
            while (!q.isEmpty() && System.nanoTime() - t0 < STEP_BUDGET_NS) {
                Component c = q.poll();
                if (c instanceof JTabbedPane tp && !subPanes.contains(tp) && looksLikeRepeaterTabs(tp)) {
                    subPanes.add(tp);
                    tp.addContainerListener(containerListener);
                    tp.addChangeListener(subListener);
                    // tabs present at attach time count as processed (old project tabs are not renamed)
                    for (int i = 0; i < tp.getTabCount(); i++) {
                        Component tc = tp.getComponentAt(i);
                        if (tc != null) processed.put(tc, Boolean.TRUE);
                    }
                    continue;   // don't descend into tabs
                }
                if (c instanceof Container ct) Collections.addAll(q, ct.getComponents());
            }
        } catch (Throwable t) {
            Log.rateLimited(t);
        }
    }

    private static boolean looksLikeRepeaterTabs(JTabbedPane tp) {
        for (int i = 0; i < tp.getTabCount(); i++) {
            String t = titleOf(tp, i);
            if (TabNames.isDefaultName(t) || (t != null && t.matches("^[A-Z]{3,10} /.*"))) return true;
        }
        return false;
    }

    // ---------- new tabs ----------

    private void scheduleNewTabs() {
        if (disabled || newTabTimer == null) return;
        if (System.currentTimeMillis() - loadedAt < 10_000) return;
        newTabTimer.restart();
    }

    private void processNewTabs() {
        if (disabled) return;
        long t0 = System.nanoTime();
        boolean pendingLeft = false;
        for (JTabbedPane tp : subPanes) {
            for (int i = 0; i < tp.getTabCount(); i++) {
                if (System.nanoTime() - t0 > STEP_BUDGET_NS) { pendingLeft = true; break; }
                Component tc = tp.getComponentAt(i);
                if (tc == null || processed.containsKey(tc)) continue;
                String title = titleOf(tp, i);
                if (!TabNames.isDefaultName(title)) { processed.put(tc, Boolean.TRUE); continue; }
                String text = readRequest(tc);
                if (text == null) {
                    int n = retries.merge(tc, 1, Integer::sum);
                    if (n >= 5) { processed.put(tc, Boolean.TRUE); onFailure(); }
                    else pendingLeft = true;
                    continue;
                }
                processed.put(tc, Boolean.TRUE);
                consecutiveFailures = 0;
                // on the EDT only read the first line for the name; request parsing / normalizing runs on the worker
                String[] mp = methodAndPath(text);
                String name = TabNames.tabName(mp[0], mp[1], usedNames);
                usedNames.add(name);
                setTitle(tp, i, title, name);
                Tracker t = tracker.get();
                if (t != null) {
                    // the editor doesn't reveal the service (host/port/scheme): the worker matches the first send with the same Host + path
                    t.submit(new Events.OriginalEvent(Rows.SRC_TABHOOK, System.currentTimeMillis(), new Events.HookText(text)));
                }
            }
        }
        if (pendingLeft) {
            newTabTimer.setInitialDelay(300);
            newTabTimer.restart();
        }
    }

    private void onFailure() {
        if (++consecutiveFailures >= 5) {
            disabled = true;
            Log.warn("Could not read the request in a new Repeater tab (5 times in a row). Auto-rename for Ctrl+R is disabled;"
                    + " use \"Send to Repeater (tracked)\" to name tabs.");
        }
    }

    /** Tier 3: renames the selected Repeater tab if the editor's first line matches the send. */
    public void renameSelected(String rawFirstLine, String tabName) {
        if (disabled || mainPane == null) return;
        SwingUtilities.invokeLater(() -> {
            try {
                for (JTabbedPane tp : subPanes) {
                    int i = tp.getSelectedIndex();
                    if (i < 0) continue;
                    String title = titleOf(tp, i);
                    if (!TabNames.isDefaultName(title)) continue;
                    Component tc = tp.getComponentAt(i);
                    String first = tc == null ? null : readFirstLine(tc);
                    if (first == null || !first.trim().equals(rawFirstLine.trim())) continue;
                    String name = uniqueName(tabName);
                    setTitle(tp, i, title, name);
                    processed.put(tc, Boolean.TRUE);
                    return;
                }
            } catch (Throwable t) {
                Log.rateLimited(t);
            }
        });
    }

    private String uniqueName(String base) {
        String name = base;
        for (int n = 2; usedNames.contains(name); n++) name = base + " (" + n + ")";
        usedNames.add(name);
        return name;
    }

    // ---------- Swing helpers ----------

    static int indexOfTitle(JTabbedPane tp, String title) {
        for (int i = 0; i < tp.getTabCount(); i++) if (title.equals(titleOf(tp, i))) return i;
        return -1;
    }

    static String titleOf(JTabbedPane tp, int i) {
        String t = tp.getTitleAt(i);
        if (t != null && !t.isBlank()) return t.trim();
        Component c = tp.getTabComponentAt(i);
        JLabel l = findLabel(c, 0);
        return l == null ? null : l.getText() == null ? null : l.getText().trim();
    }

    private static JLabel findLabel(Component c, int depth) {
        if (c == null || depth > 4) return null;
        if (c instanceof JLabel l && l.getText() != null && !l.getText().isBlank()) return l;
        if (c instanceof Container ct) {
            for (Component ch : ct.getComponents()) {
                JLabel l = findLabel(ch, depth + 1);
                if (l != null) return l;
            }
        }
        return null;
    }

    private static void setTitle(JTabbedPane tp, int i, String oldTitle, String name) {
        String t = tp.getTitleAt(i);
        if (t != null && !t.isBlank()) tp.setTitleAt(i, name);
        JLabel l = findLabel(tp.getTabComponentAt(i), 0);
        if (l != null && oldTitle != null && oldTitle.equals(l.getText().trim())) l.setText(name);
    }

    /** Method and path (no query) from the first line of the request text. */
    static String[] methodAndPath(String text) {
        int nl = text.indexOf('\n');
        String first = (nl < 0 ? text : text.substring(0, nl)).trim();
        int sp1 = first.indexOf(' ');
        int sp2 = sp1 < 0 ? -1 : first.indexOf(' ', sp1 + 1);
        String method = sp1 < 0 ? first : first.substring(0, sp1);
        String target = sp1 < 0 ? "/" : (sp2 < 0 ? first.substring(sp1 + 1) : first.substring(sp1 + 1, sp2));
        int q = target.indexOf('?');
        return new String[]{method, q >= 0 ? target.substring(0, q) : target};
    }

    /** First line (request line) of the tab's request editor; reads only 256 chars. */
    private static String readFirstLine(Component root) {
        String head = findRequest(root, 256);
        if (head == null) return null;
        int nl = head.indexOf('\n');
        return nl < 0 ? head : head.substring(0, nl);
    }

    /** Finds the tab's request editor: a text component whose first line looks like a request line. */
    private static String readRequest(Component root) {
        return findRequest(root, MAX_READ);
    }

    private static String findRequest(Component root, int maxRead) {
        ArrayDeque<Component> q = new ArrayDeque<>();
        q.add(root);
        int visited = 0;
        while (!q.isEmpty() && visited++ < 400) {
            Component c = q.poll();
            if (c instanceof JTextComponent tc) {
                Document d = tc.getDocument();
                try {
                    int len = d.getLength();
                    if (len > 10) {
                        String head = d.getText(0, Math.min(len, 256));
                        int nl = head.indexOf('\n');
                        String first = nl < 0 ? head : head.substring(0, nl);
                        if (REQUEST_LINE.matcher(first).matches()) return d.getText(0, Math.min(len, maxRead));
                    }
                } catch (BadLocationException ignored) {
                    // ignore
                }
            }
            if (c instanceof Container ct) Collections.addAll(q, ct.getComponents());
        }
        return null;
    }

    private void fail(String why) {
        disabled = true;
        Log.warn("Repeater tab auto-rename disabled: " + why);
    }

    /** Removes all listeners from Burp's components and stops the timers (called on unload, on any thread). */
    public void stop() {
        disabled = true;
        Runnable r = () -> {
            if (stepTimer != null) stepTimer.stop();
            if (newTabTimer != null) newTabTimer.stop();
            if (mainPane != null && mainListener != null) mainPane.removeChangeListener(mainListener);
            for (JTabbedPane tp : subPanes) {
                tp.removeContainerListener(containerListener);
                tp.removeChangeListener(subListener);
            }
            subPanes.clear();
            mainPane = null;
        };
        // don't wait for the EDT (unload may run on another thread while the EDT is busy): the disabled flag blocks all work
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }
}
