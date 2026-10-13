package apitracker;

import apitracker.burp.HistorySync;
import apitracker.burp.ProxyTagger;
import apitracker.burp.RepeaterTabHook;
import apitracker.burp.SettingsStore;
import apitracker.burp.TrackedSend;
import apitracker.burp.TrackerHttpHandler;
import apitracker.core.ApiKeys;
import apitracker.core.IntruderTracker;
import apitracker.core.KeyRegistry;
import apitracker.core.Redactor;
import apitracker.core.Settings;
import apitracker.core.StatusIndex;
import apitracker.core.Tracker;
import apitracker.store.Db;
import apitracker.store.DbWriter;
import apitracker.store.Repo;
import apitracker.store.Rows;
import apitracker.ui.Labels;
import apitracker.ui.TrackerTab;
import apitracker.ui.UiBus;
import apitracker.util.HandlerStats;
import apitracker.util.Log;
import burp.api.montoya.MontoyaApi;

import javax.swing.SwingUtilities;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Wires all components and manages the lifecycle (async startup, clean unload). */
public final class App {
    public final MontoyaApi api;
    public final Settings settings;
    public final ApiKeys keys = new ApiKeys();
    public final StatusIndex status = new StatusIndex();
    public final KeyRegistry registry = new KeyRegistry();
    public final Labels labels = new Labels();
    public final UiBus bus = new UiBus();
    public final TrackerHttpHandler httpHandler;
    public final ProxyTagger tagger;
    public final ExecutorService searchExec;
    private final ScheduledExecutorService maint;

    private volatile Db db;
    private volatile DbWriter writer;
    private volatile Tracker tracker;
    private volatile IntruderTracker intruder;
    private volatile Db.OriginalLoader originalLoader;
    private volatile Repo repo;
    private volatile HistorySync history;
    private volatile RepeaterTabHook hook;
    private volatile TrackedSend trackedSend;
    private volatile TrackerTab tab;
    private volatile boolean ready;
    private volatile boolean unloaded;
    private final Object lifecycle = new Object();      // syncs openStorage (tracker-init) with unload
    private volatile String error;
    public volatile boolean keepTempLog;

    App(MontoyaApi api) {
        this.api = api;
        this.settings = SettingsStore.load(api.persistence().preferences());
        this.httpHandler = new TrackerHttpHandler(() -> ready ? tracker : null, () -> ready ? intruder : null, settings);
        this.tagger = new ProxyTagger(() -> ready ? tracker : null, settings, keys, status);
        this.searchExec = Executors.newSingleThreadExecutor(r -> daemon(r, "tracker-search"));
        this.maint = Executors.newSingleThreadScheduledExecutor(r -> daemon(r, "tracker-maint"));
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    // ---------- startup ----------

    void initialize() {
        api.extension().registerUnloadingHandler(this::unload);          // before anything else: cleanup always works
        onEdt(() -> tab = new TrackerTab(this));
        api.userInterface().registerSuiteTab("API Logging", tab);
        api.http().registerHttpHandler(httpHandler);
        api.proxy().registerRequestHandler(tagger);
        api.proxy().registerResponseHandler(tagger);
        trackedSend = new TrackedSend(api, () -> tracker, () -> writer, labels, keys, this::openApi, this::copyLogForAi);
        api.userInterface().registerContextMenuItemsProvider(trackedSend);
        try {
            trackedSend.registerHotkeys(settings.hotkey);
        } catch (Throwable t) {                                           // older Burp without the hotkey API
            Log.warn("This Burp version does not support extension hotkeys; use the \"Send to Repeater (tracked)\" context menu.");
        }
        Thread init = daemon(this::openStorage, "tracker-init");
        init.start();
    }

    private void openStorage() {
        Db d = null;
        Db.OriginalLoader ldr = null;
        Repo rp = null;
        try {
            if (unloaded) return;
            String name = api.project().name();
            String id = api.project().id();
            boolean temp = isTemp(name, id);
            Path dir = Path.of(settings.storageDir);
            String remembered = null;
            try { remembered = api.persistence().extensionData().getString("dbFile"); } catch (Throwable ignored) { }
            Path file = temp ? Db.tempFile(dir) : Db.chooseFile(dir, name, id, remembered);
            d = Db.open(file, temp ? "temp-" + System.nanoTime() : id, temp);
            if (!temp) {
                try { api.persistence().extensionData().setString("dbFile", file.getFileName().toString()); } catch (Throwable ignored) { }
            }
            Db.State st = d.load();
            DbWriter w = new DbWriter(d.writeConnection(), d.readOnly);
            registry.setOnNew((i, k) -> w.submit(DbWriter.insertStatusKey(i, k)));
            Redactor red = new Redactor(d.hmacKey(), settings.sensitiveTokens);
            red.setLabeled(labels.fullKeys());                                // labeled values show as their label
            Tracker t = new Tracker(keys, status, registry, w, settings, red);
            Db.OriginalLoader loader = d.newOriginalLoader();
            ldr = loader;
            t.setOriginalLoader(loader::load);
            // Intruder must not hog the worker queue (shared with Repeater): interim snapshots are sent only when the
            // queue has plenty of room; the final one is always sent (IntruderTracker keeps and resends it if rejected)
            IntruderTracker it = new IntruderTracker(settings, e -> (e.finished() || t.queueSize() < 1_000) && t.submitInternal(e));
            t.load(st);
            labels.load(st.labels);
            Repo r = new Repo(d.newReadConnection());
            rp = r;
            HistorySync h = new HistorySync(api, keys, registry, status, settings, w, t, tagger.newProxyItems);
            h.load(st.proxyIds, st.proxySk, st.proxyLastId);
            t.setLookup(h);
            t.setTestedListener(h);
            t.setListener(bus);
            List<Rows.ApiRow> rows = t.snapshotRows();

            // publish and start atomically w.r.t. unload: either unload sees every component to stop,
            // or this thread sees the unloaded flag and cleans up itself
            synchronized (lifecycle) {
                if (unloaded) {
                    try { r.close(); } catch (Throwable ignored) { }
                    loader.close();
                    closeDb(d);
                    return;
                }
                db = d; writer = w; tracker = t; repo = r; history = h; intruder = it; originalLoader = loader;
                w.start();
                t.start();
                it.start();
                h.start();
                bus.start();
                tagger.setReady(true);
                ready = true;
                maint.scheduleWithFixedDelay(this::checkBreakers, 60, 60, TimeUnit.SECONDS);
                maint.scheduleWithFixedDelay(() -> tagger.sweep(System.nanoTime()), 30, 30, TimeUnit.SECONDS);
                maint.scheduleWithFixedDelay(() -> { DbWriter ww = writer; if (ww != null) ww.submit(DbWriter.mergeFts()); },
                        10, 10, TimeUnit.MINUTES);
            }

            Log.info("Opened " + file + (d.readOnly ? " (read-only)" : "") + ": " + st.apis.size() + (st.apis.size() == 1 ? " API, " : " APIs, ")
                    + st.maxSendId + (st.maxSendId == 1 ? " send." : " sends."));
            SwingUtilities.invokeLater(() -> {
                if (unloaded) return;
                tab.onReady(rows);
                if (settings.tabHook) {
                    RepeaterTabHook hk = new RepeaterTabHook(api, () -> tracker, keys);
                    hook = hk;
                    bus.setRenameHint(hk::renameSelected);
                    hk.start();
                    if (unloaded) hk.stop();                              // unload is running concurrently right now
                }
            });
        } catch (Throwable e) {
            if (db == null) {                                             // not yet published: clean up everything opened
                if (rp != null) { try { rp.close(); } catch (Throwable ignored) { } }
                if (ldr != null) ldr.close();
                if (d != null) closeDb(d);
            }
            if (unloaded) return;
            error = e.toString();
            Log.error("Could not open the log DB", e);
            SwingUtilities.invokeLater(() -> { if (tab != null) tab.onError(error); });
        }
    }

    private static void closeDb(Db d) {
        try {
            d.close();
            if (d.temp) d.deleteFiles();
        } catch (Throwable ignored) {
            // already closed
        }
    }

    static boolean isTemp(String name, String id) {
        return name == null || name.isBlank() || id == null || id.isBlank()
                || name.toLowerCase(Locale.ROOT).contains("temporary project");
    }

    // ---------- accessors for the UI ----------

    public boolean ready() { return ready; }
    public String error() { return error; }
    public Repo repo() { return repo; }
    public Tracker tracker() { return tracker; }
    public IntruderTracker intruder() { return intruder; }
    public DbWriter writer() { return writer; }
    public Db db() { return db; }
    public HistorySync history() { return history; }

    /** Send to Repeater (tracked): tab name = method + path, the request becomes the original request. Call on the EDT. */
    public void sendTracked(burp.api.montoya.http.message.requests.HttpRequest req,
                            burp.api.montoya.http.message.responses.HttpResponse resp) {
        TrackedSend ts = trackedSend;
        if (ts != null && req != null) ts.send(req, resp);
    }
    public boolean hookActive() { RepeaterTabHook h = hook; return h != null && h.active(); }

    /** Copies an API's log (with its original request + response) as Markdown for an AI. */
    public void copyLogForAi(String apiKey) {
        SwingUtilities.invokeLater(() -> { if (tab != null) tab.copyLogForAi(apiKey); });
    }

    public void openApi(String apiKey) {
        SwingUtilities.invokeLater(() -> { if (tab != null) tab.openApi(apiKey); });
    }

    public List<HandlerStats> stats() {
        return List.of(httpHandler.stats, tagger.requestStats, tagger.responseStats);
    }

    public List<String> tripped() {
        List<String> out = new ArrayList<>();
        for (HandlerStats s : stats()) if (s.tripped()) out.add(s.name);
        return out;
    }

    public void resetBreakers() {
        for (HandlerStats s : stats()) s.reset();
        Log.info("Handlers re-enabled.");
    }

    private void checkBreakers() {
        for (HandlerStats s : stats()) {
            if (s.checkWindow()) {
                Log.warn("Circuit breaker: handler \"" + s.name + "\" is slow (over 1% of calls took more than 1 ms in 60 s) and was disabled."
                        + " Re-enable it in the API Logging tab.");
            }
        }
    }

    public void saveSettings(String excludedExt, String excludedPath, String ignoredHeaders, String sensitiveTokens) {
        SettingsStore.save(api.persistence().preferences(), settings, excludedExt, excludedPath, ignoredHeaders, sensitiveTokens);
        Tracker t = tracker;
        Db d = db;
        if (t != null && d != null) {
            // HMAC key was loaded when the DB opened: no query on the write connection from the EDT
            Redactor red = new Redactor(d.hmacKey(), settings.sensitiveTokens);
            red.setLabeled(labels.fullKeys());
            t.setRedactor(red);
        }
        keys.clearCache();
    }

    // ---------- unload ----------

    /**
     * Unload: every step has a bounded wait (at most ~4 s total on a very slow disk, normally tens of ms), and never
     * waits for the EDT. Flushing the log is mandatory, so it still waits for the writer thread, but never closes the
     * connection under it.
     */
    private void unload() {
        synchronized (lifecycle) {
            unloaded = true;
            ready = false;
        }
        tagger.setReady(false);
        maint.shutdownNow();
        try {
            RepeaterTabHook h = hook;
            if (h != null) h.stop();
            TrackedSend ts = trackedSend;
            if (ts != null) ts.unregister();
            bus.stop();
            TrackerTab tb = tab;
            if (tb != null) tb.dispose();
            HistorySync hs = history;
            if (hs != null) hs.stop();
            Tracker t = tracker;
            IntruderTracker it = intruder;
            if (it != null) it.stop(800);                                 // write the final summary row of open attacks
            if (t != null) t.stop(500);
            searchExec.shutdownNow();
            Repo r = repo;
            if (r != null) r.close();                                     // cancel running queries, then close
            DbWriter w = writer;
            Db d = db;
            boolean writerDone = w == null || w.stop(3_000);
            Db.OriginalLoader ol = originalLoader;
            if (ol != null) ol.close();                                   // after the worker and writer thread have stopped
            if (d != null) {
                if (writerDone || !w.closeWhenDone(() -> finishDb(d))) {
                    finishDb(d);
                    Log.info("Unloaded; log saved.");
                } else {
                    Log.warn("Slow disk: the log is still being written in the background; the DB will close when done.");
                }
            }
        } catch (Throwable e) {
            Log.error("unload", e);
        }
    }

    private void finishDb(Db d) {
        d.close();
        if (!d.temp) return;
        try {
            if (keepTempLog) {
                String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
                Files.move(d.file, d.file.resolveSibling("temp-" + stamp + ".db"), StandardCopyOption.ATOMIC_MOVE);
            }
        } catch (Exception e) {
            Log.error("keeping the temporary project's log", e);
        }
        d.deleteFiles();
    }

    private static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else {
            try { SwingUtilities.invokeAndWait(r); }
            catch (Exception e) { throw new IllegalStateException("could not create the UI", e); }
        }
    }
}
