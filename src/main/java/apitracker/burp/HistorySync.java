package apitracker.burp;

import apitracker.core.ApiKeys;
import apitracker.core.Events;
import apitracker.core.KeyRegistry;
import apitracker.core.Settings;
import apitracker.core.StatusIndex;
import apitracker.core.Tracker;
import apitracker.store.DbWriter;
import apitracker.util.IntList;
import apitracker.util.Log;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

/**
 * The only thread that calls {@code api.proxy().history(...)} (tracker-history).
 * <ul>
 *   <li>Index entry id → statusKey, built incrementally and stored in the DB: each entry is parsed only once ever.</li>
 *   <li>Each pass scans history exactly once with a number-only filter; a large history is caught up in chunks of
 *       50,000 entries, spaced out so original request lookups can run in between.</li>
 *   <li>Recolors in batches of 200 in a separate task, 50 ms apart; re-checks color ownership at change time.</li>
 *   <li>Answers "latest Proxy request of this API" for the original request without running a full sync pass.</li>
 * </ul>
 */
public final class HistorySync implements Tracker.OriginalLookup, Tracker.TestedListener {
    static final int PASS_CAP = 50_000;
    static final int LOOKUP_CAP = 5_000;
    static final int LOOKBACK = 64;
    private static final int COLOR_BATCH = 200;

    private final MontoyaApi api;
    private final ApiKeys keys;
    private final KeyRegistry registry;
    private final StatusIndex status;
    private final Settings settings;
    private final DbWriter writer;
    private final Tracker tracker;
    private final LongAdder newItems;
    private final ScheduledExecutorService ex;

    // touched only by the history thread
    private final Map<Integer, IntList> idsBySk = new HashMap<>();
    private final Map<Integer, Integer> latestBySk = new HashMap<>();
    /** Real URL (no query) of a request for the statusKey, to ask Burp's scope ("" = no longer in history). */
    private final Map<Integer, String> urlBySk = new HashMap<>();
    /** statusKeys in history, grouped by host, segments pre-split: variant lookup scans only that host. */
    private record SkInfo(int skId, String method, String pathKey, String[] segs) {}
    private final Map<String, List<SkInfo>> skByHost = new HashMap<>();
    private final BitSet indexed = new BitSet();
    private int lastSeenId;
    private final IntList unsavedIds = new IntList(), unsavedSks = new IntList();
    private final ArrayDeque<Job> clearJobs = new ArrayDeque<>(), colorJobs = new ArrayDeque<>();
    private boolean applyScheduled;

    private record Job(ProxyHttpRequestResponse item, String statusKey) {}
    /** Stop indexing while the recolor backlog is too large (keeps memory bounded). */
    static final int MAX_BACKLOG = 20_000;
    private boolean catchUpScheduled;

    private final Set<String> dirty = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean scheduled = new AtomicBoolean();
    private volatile boolean stopped;
    public volatile long lastPassMs;
    public volatile int indexedTotal;

    public HistorySync(MontoyaApi api, ApiKeys keys, KeyRegistry registry, StatusIndex status, Settings settings,
                       DbWriter writer, Tracker tracker, LongAdder newItems) {
        this.api = api;
        this.keys = keys;
        this.registry = registry;
        this.status = status;
        this.settings = settings;
        this.writer = writer;
        this.tracker = tracker;
        this.newItems = newItems;
        this.ex = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "tracker-history");
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            return t;
        });
    }

    /** Loads the saved index (call before start, on the init thread). */
    public void load(int[] ids, int[] sks, long lastId) {
        for (int i = 0; i < ids.length; i++) {
            if (ids[i] < 0) continue;
            idsBySk.computeIfAbsent(sks[i], k -> new IntList()).add(ids[i]);
            noteLatest(sks[i], ids[i]);
            indexed.set(ids[i]);
        }
        lastSeenId = (int) Math.min(Integer.MAX_VALUE, lastId);
        indexedTotal = ids.length;
    }

    public void start() {
        ex.schedule(this::safePass, 3, TimeUnit.SECONDS);                     // catch up on new entries when the project opens
        ex.scheduleWithFixedDelay(() -> {
            if (newItems.sumThenReset() > 0) safePass();
        }, 30, 30, TimeUnit.SECONDS);
    }

    public void stop() {
        stopped = true;
        ex.shutdownNow();
        try { ex.awaitTermination(500, TimeUnit.MILLISECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ---------- API for the worker ----------

    @Override
    public void markTested(String statusKey) {
        dirty.add(statusKey);
        if (scheduled.compareAndSet(false, true)) {
            try { ex.schedule(this::safePass, 2, TimeUnit.SECONDS); }
            catch (RuntimeException e) { scheduled.set(false); }
        }
    }

    @Override
    public void lookup(String method, String hostKey, String pathKey, String parkedApiKey, long token) {
        try {
            ex.submit(() -> doLookup(method, hostKey, pathKey, parkedApiKey, token));
        } catch (RuntimeException e) {
            tracker.submitInternal(new Events.LookupResult(parkedApiKey, token, null, 0));
        }
    }

    // ---------- sync pass ----------

    private void safePass() {
        scheduled.set(false);
        if (clearJobs.size() + colorJobs.size() > MAX_BACKLOG && dirty.isEmpty()) {
            scheduleCatchUp(2_000);                                           // let the recolor backlog drain before scanning again
            return;
        }
        Set<String> tested = drainDirty();
        try {
            long t0 = System.currentTimeMillis();
            boolean more = indexNew(tested, PASS_CAP, null);
            lastPassMs = System.currentTimeMillis() - t0;
            scheduleApply();
            if (more) scheduleCatchUp(500);                                   // next chunk
        } catch (Throwable t) {
            dirty.addAll(tested);                                             // don't lose work if the pass fails
            Log.error("Proxy history sync", t);
        }
    }

    /** A single catch-up chain (scan passes never overlap). */
    private void scheduleCatchUp(long delayMs) {
        if (catchUpScheduled || stopped) return;
        catchUpScheduled = true;
        try {
            ex.schedule(() -> { catchUpScheduled = false; safePass(); }, delayMs, TimeUnit.MILLISECONDS);
        } catch (RuntimeException e) {
            catchUpScheduled = false;
        }
    }

    private Set<String> drainDirty() {
        Set<String> out = new HashSet<>();
        for (String s : dirty) if (dirty.remove(s)) out.add(s);
        return out;
    }

    /**
     * One history scan: indexes up to {@code cap} new entries (id &gt; lastSeenId) and collects entries whose yellow
     * highlight must be cleared for APIs that just became "tested". {@code keep} (nullable) receives new entries by id.
     * @return true if new entries remain unprocessed (over cap)
     */
    private boolean indexNew(Set<String> tested, int cap, Map<Integer, ProxyHttpRequestResponse> keep) {
        IntList clear = new IntList();
        for (String sk : tested) {
            Integer skId = registry.find(sk);
            IntList ids = skId == null ? null : idsBySk.get(skId);
            if (ids != null) for (int i = 0; i < ids.size(); i++) clear.add(ids.get(i));
        }
        int[] clearIds = clear.toArray();
        Arrays.sort(clearIds);

        // look back a little: a lower id may show up after a higher one (parallel requests);
        // the indexed BitSet ensures each entry is processed only once
        final int from = Math.max(0, lastSeenId - LOOKBACK);
        final long to = (long) lastSeenId + cap;
        AtomicInteger maxSeen = new AtomicInteger(from);
        List<ProxyHttpRequestResponse> hits = api.proxy().history(item -> {
            try {
                int id = item.id();                                           // number-only filter: a few ns per entry
                if (id > maxSeen.get()) maxSeen.set(id);                      // only this thread calls the filter
                return (id > from && id <= to && !indexed.get(id))
                        || (clearIds.length > 0 && Arrays.binarySearch(clearIds, id) >= 0);
            } catch (Throwable e) {
                return false;
            }
        });
        List<ProxyHttpRequestResponse> fresh = new ArrayList<>();
        for (ProxyHttpRequestResponse h : hits) {
            int id = h.id();
            if (id > from && !indexed.get(id)) fresh.add(h);
            else if (ours(h.annotations())) clearJobs.add(new Job(h, null));
        }
        int processedTo = indexFresh(fresh, keep);
        int max = maxSeen.get();
        boolean more = max > to;
        lastSeenId = Math.max(lastSeenId, more ? (int) to : Math.max(processedTo, max));
        persistIndex();
        return more;
    }

    /** Indexes new entries (parsed once). Returns the highest id processed. */
    private int indexFresh(List<ProxyHttpRequestResponse> fresh, Map<Integer, ProxyHttpRequestResponse> keep) {
        int max = 0;
        if (fresh.isEmpty()) return max;
        fresh.sort(Comparator.comparingInt(ProxyHttpRequestResponse::id));
        for (ProxyHttpRequestResponse h : fresh) {
            int id = h.id();
            max = Math.max(max, id);
            indexed.set(id);
            try {
                Annotations an = h.annotations();
                if (an.hasNotes() && an.notes().startsWith("[AI]")) continue;   // AI requests are not indexed
                HttpRequest q = h.finalRequest();
                String method = q.method(), path = q.pathWithoutQuery();
                if (settings.excluded(method, path)) continue;                // OPTIONS, static files, /health
                HttpService s = q.httpService();
                String sk = keys.statusKey(method, ApiKeys.hostKey(s.host(), s.port(), s.secure()), path);
                int skId = registry.idOf(sk);
                idsBySk.computeIfAbsent(skId, k -> new IntList()).add(id);
                noteLatest(skId, id);
                urlBySk.put(skId, ApiKeys.hostKey(s.host(), s.port(), s.secure()) + path);
                unsavedIds.add(id);
                unsavedSks.add(skId);
                indexedTotal++;
                if (keep != null) keep.put(id, h);
                if (status.isTested(sk)) {
                    if (ours(an)) clearJobs.add(new Job(h, null));
                } else if (settings.highlightEnabled && canColor(an) && q.isInScope()) {
                    colorJobs.add(new Job(h, sk));
                }
            } catch (Throwable e) {
                // broken entry: skip
            }
        }
        return max;
    }

    /** Writes the unsaved index; the stored lastSeenId never moves past what could not be written. */
    private void persistIndex() {
        int floor = lastSeenId;
        if (!unsavedIds.isEmpty()) {
            int[] ids = unsavedIds.toArray(), sks = unsavedSks.toArray();
            if (writer.submit(DbWriter.insertProxyIndex(ids, sks, ids.length), 2_000)) {
                unsavedIds.clear();
                unsavedSks.clear();
            } else {
                int min = Integer.MAX_VALUE;
                for (int id : ids) min = Math.min(min, id);
                floor = Math.min(floor, min - 1);
            }
        }
        writer.submit(DbWriter.setMeta("proxy_last_id", Integer.toString(Math.max(0, floor))), 2_000);
    }

    /**
     * The extension's color: yellow with exactly the marker note. With the marker note off: yellow with no note (then
     * the user's own note-less yellow also counts as the extension's; the README says so).
     */
    private boolean ours(Annotations an) {
        if (an.highlightColor() != HighlightColor.YELLOW) return false;
        String notes = an.hasNotes() ? an.notes() : "";
        return settings.markerNote ? settings.marker.equals(notes) : notes.isEmpty();
    }

    /** Only color entries with no color and no note (so the yellow highlight can always be cleared). */
    static boolean canColor(Annotations an) {
        return !an.hasHighlightColor() && !an.hasNotes();
    }

    // ---------- batched recoloring ----------

    private void scheduleApply() {
        if (applyScheduled || (clearJobs.isEmpty() && colorJobs.isEmpty()) || stopped) return;
        applyScheduled = true;
        try { ex.submit(this::applyChunk); } catch (RuntimeException e) { applyScheduled = false; }
    }

    /** Recolors up to 200 entries, then yields the thread (so original lookups can run); next batch in 50 ms. */
    private void applyChunk() {
        applyScheduled = false;
        int n = 0;
        while (n < COLOR_BATCH && !stopped && (!clearJobs.isEmpty() || !colorJobs.isEmpty())) {
            boolean clear = !clearJobs.isEmpty();
            Job j = clear ? clearJobs.poll() : colorJobs.poll();
            n++;
            try {
                Annotations an = j.item().annotations();
                if (clear) {
                    if (!ours(an)) continue;                                  // user just changed the color: leave it
                    an.setHighlightColor(HighlightColor.NONE);
                    if (an.hasNotes() && settings.marker.equals(an.notes())) an.setNotes("");
                } else {
                    if (!canColor(an) || status.isTested(j.statusKey()) || !settings.highlightEnabled) continue;
                    an.setHighlightColor(HighlightColor.YELLOW);
                    if (settings.markerNote) an.setNotes(settings.marker);
                }
            } catch (Throwable e) {
                Log.rateLimited(e);
            }
        }
        if ((!clearJobs.isEmpty() || !colorJobs.isEmpty()) && !stopped) {
            applyScheduled = true;
            try { ex.schedule(this::applyChunk, 50, TimeUnit.MILLISECONDS); } catch (RuntimeException e) { applyScheduled = false; }
        }
    }

    // ---------- original request lookup ----------

    private void doLookup(String method, String hostKey, String pathKey, String parkedApiKey, long token) {
        if (!tracker.lookupWanted(token)) return;                             // wait expired: the worker no longer needs it
        Events.RequestSource found = null;
        Events.ResponseSource foundResp = null;
        long millis = 0;
        try {
            // index entries that just reached Proxy (usually a few), kept to avoid a second scan
            Map<Integer, ProxyHttpRequestResponse> fresh = new HashMap<>();
            Set<String> tested = drainDirty();
            try {
                if (indexNew(tested, LOOKUP_CAP, fresh)) scheduleCatchUp(500);
            } catch (Throwable t) {
                dirty.addAll(tested);
                throw t;
            }
            Integer id = latestFor(method, hostKey, pathKey);
            if (id != null) {
                ProxyHttpRequestResponse h = fresh.get(id);
                if (h == null) {
                    final int want = id;
                    List<ProxyHttpRequestResponse> hits = api.proxy().history(item -> {
                        try { return item.id() == want; } catch (Throwable e) { return false; }
                    });
                    h = hits.isEmpty() ? null : hits.get(0);
                }
                if (h != null) {
                    found = BurpRequest.snapshot(h.finalRequest());
                    foundResp = responseOf(h);
                    millis = h.time() == null ? System.currentTimeMillis() : h.time().toInstant().toEpochMilli();
                }
            }
        } catch (Throwable t) {
            Log.error("original request lookup in Proxy history", t);
        }
        tracker.submitInternal(new Events.LookupResult(parkedApiKey, token, found, millis, foundResp));
        scheduleApply();
    }

    private static Events.ResponseSource responseOf(ProxyHttpRequestResponse h) {
        try { return h.hasResponse() ? BurpResponse.of(h.response()) : null; } catch (Throwable t) { return null; }
    }

    /** Max recent Proxy entries of one API compared when looking for an original's response. */
    static final int RESPONSE_SCAN = 50;

    @Override
    public void lookupResponse(int originalId, String statusKey, byte[] requestRaw) {
        try {
            ex.submit(() -> doLookupResponse(originalId, statusKey, requestRaw));
        } catch (RuntimeException ignored) {
            // stopped
        }
    }

    /**
     * Response of an original that came from a Repeater tab (Burp's own Send to Repeater): among the most recent Proxy
     * entries of the same API, the one with the identical request (ignoring CR), otherwise the same request line.
     */
    private void doLookupResponse(int originalId, String statusKey, byte[] raw) {
        try {
            Set<String> tested = drainDirty();
            try {
                if (indexNew(tested, LOOKUP_CAP, null)) scheduleCatchUp(500);  // the entry may have just arrived
            } catch (Throwable t) {
                dirty.addAll(tested);
                throw t;
            }
            Integer skId = registry.find(statusKey);
            IntList ids = skId == null ? null : idsBySk.get(skId);
            if (ids == null || ids.isEmpty()) return;
            BitSet want = new BitSet();
            for (int i = ids.size() - 1, n = 0; i >= 0 && n < RESPONSE_SCAN; i--, n++) want.set(ids.get(i));
            List<ProxyHttpRequestResponse> hits = new ArrayList<>(api.proxy().history(item -> {
                try { return want.get(item.id()); } catch (Throwable e) { return false; }
            }));
            hits.sort(Comparator.comparingInt(ProxyHttpRequestResponse::id).reversed());
            byte[] norm = withoutCr(raw);
            String line = firstLine(norm);
            ProxyHttpRequestResponse exact = null, sameLine = null;
            for (ProxyHttpRequestResponse h : hits) {
                try {
                    if (!h.hasResponse()) continue;
                    byte[] hb = withoutCr(h.finalRequest().toByteArray().getBytes());
                    if (Arrays.equals(hb, norm)) { exact = h; break; }
                    if (sameLine == null && firstLine(hb).equals(line)) sameLine = h;
                } catch (Throwable ignored) {
                    // broken entry
                }
            }
            ProxyHttpRequestResponse pick = exact != null ? exact : sameLine;
            Events.ResponseSource resp = pick == null ? null : responseOf(pick);
            if (resp != null) tracker.submitInternal(new Events.OriginalResponse(originalId, resp));
        } catch (Throwable t) {
            Log.error("looking up the original's response in Proxy history", t);
        }
        scheduleApply();
    }

    static byte[] withoutCr(byte[] b) {
        if (b == null) return new byte[0];
        byte[] out = new byte[b.length];
        int n = 0;
        for (byte x : b) if (x != '\r') out[n++] = x;
        return n == b.length ? out : Arrays.copyOf(out, n);
    }

    private static String firstLine(byte[] b) {
        int e = 0;
        while (e < b.length && b[e] != '\n') e++;
        return new String(b, 0, e, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    /**
     * Exact path match (same method first, then other methods); failing that, a same-method variant differing in
     * exactly one segment. A path that really exists in Proxy history is therefore always its own API.
     */
    /** Updates a statusKey's latest id; a new statusKey is split once and added to the per-host index. */
    private void noteLatest(int skId, int id) {
        Integer prev = latestBySk.get(skId);
        if (prev != null) {
            if (id > prev) latestBySk.put(skId, id);
            return;
        }
        latestBySk.put(skId, id);
        String key = registry.keyOf(skId);
        if (key == null) return;
        int sp = key.indexOf(' ');
        if (sp < 0) return;
        String ak = key.substring(sp + 1);
        int scheme = ak.indexOf("://");
        int slash = scheme < 0 ? -1 : ak.indexOf('/', scheme + 3);
        if (slash < 0) return;
        String pk = ak.substring(slash);
        skByHost.computeIfAbsent(ak.substring(0, slash), k -> new ArrayList<>())
                .add(new SkInfo(skId, key.substring(0, sp), pk, ApiKeys.segments(pk)));
    }

    private Integer latestFor(String method, String hostKey, String pathKey) {
        String apiKey = hostKey + pathKey;
        Integer skId = registry.find(ApiKeys.statusKeyOf(method, apiKey));
        if (skId != null && latestBySk.containsKey(skId)) return latestBySk.get(skId);
        List<SkInfo> list = skByHost.get(hostKey);
        if (list == null) return null;
        String[] segs = ApiKeys.segments(pathKey);
        Integer bestSame = null, bestVariant = null;
        int bestScore = -1;
        for (SkInfo s : list) {
            Integer latest = latestBySk.get(s.skId());
            if (latest == null) continue;
            if (s.pathKey().equals(pathKey)) {
                if (bestSame == null || latest > bestSame) bestSame = latest;
            } else if (s.method().equals(method)) {
                int sc = ApiKeys.variantScore(s.segs(), segs);
                if (sc >= 0 && (sc > bestScore || (sc == bestScore && latest > bestVariant))) {
                    bestVariant = latest;
                    bestScore = sc;
                }
            }
        }
        return bestSame != null ? bestSame : bestVariant;
    }

    /**
     * APIs in Proxy history that are untested and in Burp's current scope (Target → Scope), with their request count
     * in history. Scope is re-queried on every call, so scope changes apply immediately. Runs on the history thread.
     */
    public void snapshotUntestedInScope(java.util.function.Consumer<Map<Integer, Integer>> cb) {
        try {
            ex.submit(() -> {
                Map<Integer, Integer> counts = new HashMap<>();
                Set<String> tested = drainDirty();
                try {
                    if (indexNew(tested, PASS_CAP, null)) scheduleCatchUp(500);   // includes entries that just reached history
                    tested = Set.of();
                    scheduleApply();
                    resolveUrls();
                    var scope = api.scope();
                    for (Map.Entry<Integer, IntList> e : idsBySk.entrySet()) {
                        String sk = registry.keyOf(e.getKey());
                        if (sk == null || status.isTested(sk)) continue;
                        String url = urlBySk.get(e.getKey());
                        if (url == null || url.isEmpty()) continue;
                        boolean in;
                        try { in = scope.isInScope(url); } catch (Throwable t) { in = false; }
                        if (in) counts.put(e.getKey(), e.getValue().size());
                    }
                } catch (Throwable t) {
                    dirty.addAll(tested);                                     // failed pass: don't lose the highlight clearing
                    Log.rateLimited(t);
                }
                cb.accept(counts);
            });
        } catch (RuntimeException ignored) {
            // stopped
        }
    }

    /** Latest Proxy entry (request + response) of a statusKey (null if gone from history). Callback runs on the history thread. */
    public void latestItem(String statusKey, java.util.function.Consumer<ProxyHttpRequestResponse> cb) {
        try {
            ex.submit(() -> {
                ProxyHttpRequestResponse out = null;
                try {
                    Integer skId = registry.find(statusKey);
                    Integer id = skId == null ? null : latestBySk.get(skId);
                    if (id != null) {
                        final int want = id;
                        List<ProxyHttpRequestResponse> hits = api.proxy().history(item -> {
                            try { return item.id() == want; } catch (Throwable e) { return false; }
                        });
                        if (!hits.isEmpty()) out = hits.get(0);
                    }
                } catch (Throwable t) {
                    Log.rateLimited(t);
                }
                cb.accept(out);
            });
        } catch (RuntimeException e) {
            cb.accept(null);
        }
    }

    /**
     * statusKeys loaded from the saved index have no URL yet: fetch each one's latest request in one history scan
     * (id-only filter). Requests deleted from history are marked "" so they are not rescanned.
     */
    private void resolveUrls() {
        BitSet want = new BitSet();
        Map<Integer, Integer> skOfId = new HashMap<>();
        for (Map.Entry<Integer, Integer> e : latestBySk.entrySet()) {
            if (urlBySk.containsKey(e.getKey()) || !idsBySk.containsKey(e.getKey())) continue;
            want.set(e.getValue());
            skOfId.put(e.getValue(), e.getKey());
        }
        if (skOfId.isEmpty()) return;
        List<ProxyHttpRequestResponse> hits = api.proxy().history(item -> {
            try { return want.get(item.id()); } catch (Throwable t) { return false; }
        });
        for (ProxyHttpRequestResponse h : hits) {
            Integer skId = skOfId.get(h.id());
            if (skId == null) continue;
            try {
                HttpRequest q = h.finalRequest();
                HttpService sv = q.httpService();
                urlBySk.put(skId, ApiKeys.hostKey(sv.host(), sv.port(), sv.secure()) + q.pathWithoutQuery());
            } catch (Throwable ignored) {
                // broken entry
            }
        }
        for (Integer skId : skOfId.values()) urlBySk.putIfAbsent(skId, "");
    }
}
