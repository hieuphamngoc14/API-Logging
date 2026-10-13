package apitracker.core;

import apitracker.core.Events.AttackEvent;
import apitracker.core.Events.Event;
import apitracker.core.Events.LookupResult;
import apitracker.core.Events.OriginalEvent;
import apitracker.core.Events.RequestSource;
import apitracker.core.Events.ResponseEvent;
import apitracker.core.Events.SendEvent;
import apitracker.store.Db;
import apitracker.store.DbWriter;
import apitracker.store.Rows;
import apitracker.store.Zip;
import apitracker.util.Log;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

/**
 * The single worker (tracker-core). Owns all processing state, so no internal locking is needed.
 * Pairs requests/responses by messageId (no ordering assumed), picks the original request, diffs, updates status,
 * queues DB writes and UI updates.
 */
public final class Tracker implements Runnable {

    public interface Listener {
        void apiChanged(Rows.ApiRow row);
        void sendAdded(Rows.SendRow row);
        /** Hint to rename the selected Repeater tab (tier 3). rawFirstLine is unredacted, used only for matching on the EDT. */
        default void renameHint(String rawFirstLine, String hostHeader, String tabName) {}
    }

    /**
     * Looks up a Proxy request to use as the original: exact match first, else a variant differing in exactly one segment.
     * The result comes back via {@link #submitInternal(Event)} as a {@link LookupResult} with the same token.
     */
    public interface OriginalLookup {
        void lookup(String method, String hostKey, String pathKey, String parkedApiKey, long token);

        /**
         * Finds the Proxy history response of an original that came without one (Repeater tab hook); answers with an
         * {@link Events.OriginalResponse} if found.
         */
        default void lookupResponse(int originalId, String statusKey, byte[] requestRaw) {}
    }

    public interface TestedListener { void markTested(String statusKey); }

    // ---------- internal state ----------

    static final class ApiEntry {
        int id;
        String hostKey, pathKey, apiKey, method;
        String[] segs;
        long firstSeen, lastSeen;
        int sendCount;
        /** Last log number given in this API (#1 = first original or send). */
        int seq;
        final List<OriginalEntry> originals = new ArrayList<>(2);
    }

    static final class OriginalEntry {
        int id;
        ApiEntry api;
        String method;
        long ts;
        int source;
        long[] features;
        byte[] rawZ;
        String host;
        int port;
        boolean secure;
        boolean truncated;          // rawZ keeps only the first MAX_ORIGINAL_RAW bytes
        long bodyHash;
        int bodySize;
    }

    private static final class Pending {
        SendEvent send;
        final long createdNs = System.nanoTime();
    }

    private static final class Finished {
        SendEvent send;
        ResponseEvent resp;
        boolean lookedUp;
    }

    private static final class Parked {
        final List<Finished> items = new ArrayList<>(2);
        final long sinceNs = System.nanoTime();
        long token;
    }

    private static final class HookOriginal {
        String hostHeader, pathKey;
        String[] segs;
        byte[] raw;
        long millis;
        final long nano = System.nanoTime();
    }

    private record Redirect(String url, long nano) {}

    private record ReqInfo(byte[] raw, ParsedReq pr, String host, int port, boolean secure, String hostKey, String pathKey) {
        String apiKey() { return hostKey + pathKey; }
    }

    // ---------- constants ----------
    static final long PENDING_TTL_NS = TimeUnit.SECONDS.toNanos(120);
    static final long PARK_TTL_NS = TimeUnit.SECONDS.toNanos(10);
    static final long HOOK_TTL_NS = TimeUnit.MINUTES.toNanos(30);
    static final long REDIRECT_WINDOW_NS = TimeUnit.SECONDS.toNanos(2);
    /** Proxy lookup found no original: don't look that API up again for this long (AI keeps sending APIs with none). */
    static final long NOT_FOUND_TTL_NS = TimeUnit.SECONDS.toNanos(30);
    static final int MAX_ORIGINAL_RAW = 1024 * 1024;
    static final int MAX_BLOB_RAW = 4 * 1024 * 1024;
    static final long MAX_HOOK_BYTES = 32L * 1024 * 1024;
    static final int MAX_CHANGES = 64 * 1024;
    static final int MAX_SEARCH = 4 * 1024;

    private final BlockingQueue<Event> q = new ArrayBlockingQueue<>(2_000);
    public final LongAdder dropped = new LongAdder();
    public final LongAdder processed = new LongAdder();
    public final LongAdder processNs = new LongAdder();

    private final ApiKeys keys;
    private final StatusIndex status;
    private final KeyRegistry registry;
    private final DbWriter writer;
    private final Settings settings;
    private volatile Redactor redactor;
    private volatile Listener listener = new Listener() {
        @Override public void apiChanged(Rows.ApiRow row) {}
        @Override public void sendAdded(Rows.SendRow row) {}
    };
    private volatile OriginalLookup lookup;
    private volatile TestedListener testedListener = sk -> {};

    private final Map<String, ApiEntry> apis = new HashMap<>();
    private final Map<Integer, ApiEntry> apisById = new HashMap<>();
    private final Map<String, List<ApiEntry>> byHost = new HashMap<>();
    private final Map<Long, Pending> pending = new HashMap<>();
    private final Map<String, Parked> parked = new HashMap<>();
    private final Map<String, Long> notFound = new HashMap<>();
    /** Tokens of pending lookups: the history thread skips lookups that have timed out. */
    private final java.util.Set<Long> liveTokens = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final ArrayDeque<HookOriginal> hookOriginals = new ArrayDeque<>();
    private final ArrayDeque<Redirect> redirects = new ArrayDeque<>();
    private final Map<Integer, ParsedReq> parsedCache = new LinkedHashMap<>(256, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<Integer, ParsedReq> e) { return size() > 200; }
    };
    /** Compression dictionary (first 32 KB of the original request) by original id, for recent sends. */
    private final Map<Integer, byte[]> dictCache = new LinkedHashMap<>(128, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<Integer, byte[]> e) { return size() > 64; }
    };
    /** Loads an original request from the DB on demand (originals from earlier sessions are not kept in RAM). */
    private volatile java.util.function.IntFunction<byte[]> originalLoader = id -> null;

    private static final class AttackState {
        long sendId;
        int seq;
        ApiEntry api;
        int originalId;
        ParsedReq base;
        boolean testedRaised;
    }
    private final Map<Long, AttackState> attacks = new HashMap<>();

    private long hookBytes;
    private long nextToken = 1;
    private int nextApiId = 1;
    private int nextOriginalId = 1;
    private long nextSendId = 1;
    private volatile boolean running = true;
    private Thread thread;

    public Tracker(ApiKeys keys, StatusIndex status, KeyRegistry registry, DbWriter writer, Settings settings, Redactor redactor) {
        this.keys = keys;
        this.status = status;
        this.registry = registry;
        this.writer = writer;
        this.settings = settings;
        this.redactor = redactor;
    }

    public void setListener(Listener l) { listener = l; }
    public void setLookup(OriginalLookup l) { lookup = l; }
    public void setTestedListener(TestedListener l) { testedListener = l; }
    public void setRedactor(Redactor r) { redactor = r; }
    public void setOriginalLoader(java.util.function.IntFunction<byte[]> l) { originalLoader = l; }
    public Redactor redactor() { return redactor; }

    // ---------- load state from DB (call before start) ----------

    public void load(Db.State st) {
        for (Db.ApiRec a : st.apis) {
            ApiEntry e = new ApiEntry();
            e.id = a.id(); e.hostKey = a.host(); e.pathKey = a.pathKey(); e.apiKey = a.host() + a.pathKey();
            e.segs = ApiKeys.segments(a.pathKey()); e.firstSeen = a.firstSeen(); e.lastSeen = a.lastSeen();
            e.sendCount = a.sendCount(); e.method = a.method();
            e.seq = st.maxSeq.getOrDefault(a.id(), 0);
            apis.put(e.apiKey, e);
            apisById.put(e.id, e);
            byHost.computeIfAbsent(e.hostKey, k -> new ArrayList<>()).add(e);
            nextApiId = Math.max(nextApiId, e.id + 1);
        }
        for (Db.OriginalRec o : st.originals) {
            ApiEntry api = apisById.get(o.apiId());
            if (api == null) continue;
            OriginalEntry oe = new OriginalEntry();
            oe.id = o.id(); oe.api = api; oe.method = o.method(); oe.ts = o.ts(); oe.source = o.source();
            oe.features = bytesToLongs(o.features()); oe.rawZ = o.requestZ();
            oe.host = o.host(); oe.port = o.port(); oe.secure = o.secure();
            oe.truncated = o.truncated(); oe.bodyHash = o.bodyHash(); oe.bodySize = o.bodySize();
            api.originals.add(oe);
            if (api.method == null) api.method = oe.method;
            nextOriginalId = Math.max(nextOriginalId, oe.id + 1);
        }
        for (Map.Entry<Integer, String> e : st.statusKeys.entrySet()) {
            registry.load(e.getKey(), e.getValue());
            Integer s = st.statusState.get(e.getKey());
            if (s != null) status.load(e.getValue(), (byte) (int) s);
        }
        nextSendId = st.maxSendId + 1;
    }

    // ---------- loop ----------

    public void start() {
        thread = new Thread(this, "tracker-core");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Stops without interrupt (interrupting while queuing a DB write would lose that write): wakes the loop with an
     * empty event; the loop drains the queue, then exits.
     */
    public void stop(long waitMs) {
        running = false;
        if (thread != null) {
            q.offer(new Events.Tick());
            try { thread.join(waitMs); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    /** Called from a Burp thread: never blocks. */
    public boolean submit(Event e) {
        if (q.offer(e)) return true;
        dropped.increment();
        return false;
    }

    /** Called from internal threads (history, intruder, EDT): waits up to 100 ms. Not cancelled by the interrupt flag. */
    public boolean submitInternal(Event e) {
        boolean wasInterrupted = Thread.interrupted();
        try {
            if (q.offer(e, 100, TimeUnit.MILLISECONDS)) return true;
        } catch (InterruptedException ie) {
            wasInterrupted = true;
        } finally {
            if (wasInterrupted) Thread.currentThread().interrupt();
        }
        dropped.increment();
        return false;
    }

    public int queueSize() { return q.size(); }

    /** Whether the lookup with this token is still awaited (called from the history thread to skip wasted work). */
    public boolean lookupWanted(long token) { return liveTokens.contains(token); }

    @Override
    public void run() {
        long lastSweep = System.nanoTime();
        while (running) {
            Event e;
            try { e = q.poll(500, TimeUnit.MILLISECONDS); }
            catch (InterruptedException ie) { if (!running) break; continue; }
            if (e != null) {
                long t0 = System.nanoTime();
                try { handle(e); }
                catch (Throwable t) { Log.rateLimited(t); }
                processNs.add(System.nanoTime() - t0);
            }
            long now = System.nanoTime();
            if (now - lastSweep > 5_000_000_000L) {
                try { sweep(now); } catch (Throwable t) { Log.rateLimited(t); }
                lastSweep = now;
            }
        }
        // on stop: drain the queue (e.g. the final summary line of an Intruder attack) for up to 300 ms.
        // Clear stop()'s interrupt flag first so queuing DB writes (timed offer) is not cancelled.
        Thread.interrupted();
        long end = System.nanoTime() + 300_000_000L;
        List<Event> rest = new ArrayList<>();
        q.drainTo(rest);
        // final summary lines of Intruder attacks first, then the rest (within the time limit)
        for (Event e : rest) {
            if (!(e instanceof AttackEvent)) continue;
            try { handle(e); } catch (Throwable t) { Log.rateLimited(t); }
        }
        for (Event e : rest) {
            if (e instanceof AttackEvent) continue;
            if (System.nanoTime() > end) break;
            try { handle(e); } catch (Throwable t) { Log.rateLimited(t); }
        }
    }

    /** Drains the whole queue synchronously (for tests). */
    public void drainForTest() {
        Event e;
        while ((e = q.poll()) != null) handle(e);
    }

    public void sweepForTest(long now) { sweep(now); }

    void handle(Event e) {
        if (e instanceof SendEvent s) {
            if (!settings.trackingEnabled) return;
            Pending p = new Pending();
            p.send = s;
            pending.put(pendingKey(s.kind(), s.messageId()), p);
        } else if (e instanceof ResponseEvent r) {
            Pending p = pending.remove(pendingKey(r.kind(), r.messageId()));
            if (!settings.trackingEnabled && p == null) return;
            Finished f = new Finished();
            f.send = p == null ? null : p.send;
            f.resp = r;
            recordRedirect(f);
            processFinished(f);
        } else if (e instanceof OriginalEvent o) {
            onOriginal(o);
        } else if (e instanceof AttackEvent a) {
            onAttack(a);
        } else if (e instanceof LookupResult lr) {
            resolveParked(lr.parkedApiKey(), lr.token(), lr.found(), lr.foundMillis(), lr.foundResponse());
        } else if (e instanceof Events.OriginalResponse or) {
            storeOriginalResponse(or.originalId(), or.response());
        }
    }

    private static long pendingKey(int kind, int id) { return ((long) kind << 32) | (id & 0xffffffffL); }

    private void sweep(long now) {
        Iterator<Map.Entry<Long, Pending>> it = pending.entrySet().iterator();
        List<Pending> expired = new ArrayList<>();
        while (it.hasNext()) {
            Pending p = it.next().getValue();
            if (now - p.createdNs > PENDING_TTL_NS) { expired.add(p); it.remove(); }
        }
        for (Pending p : expired) {
            Finished f = new Finished();
            f.send = p.send;
            processFinished(f);
        }
        List<Map.Entry<String, Long>> stale = new ArrayList<>();
        for (Map.Entry<String, Parked> e : parked.entrySet()) {
            if (now - e.getValue().sinceNs > PARK_TTL_NS) stale.add(Map.entry(e.getKey(), e.getValue().token));
        }
        for (Map.Entry<String, Long> k : stale) resolveParked(k.getKey(), k.getValue(), null, 0, null);
        notFound.values().removeIf(t -> now - t > NOT_FOUND_TTL_NS);
        while (!hookOriginals.isEmpty() && now - hookOriginals.peekFirst().nano > HOOK_TTL_NS) dropOldestHook();
        while (!redirects.isEmpty() && now - redirects.peekFirst().nano() > REDIRECT_WINDOW_NS * 5) redirects.pollFirst();
    }

    // ---------- user-designated original request ----------

    private void onOriginal(OriginalEvent o) {
        RequestSource src = o.req();
        byte[] raw = src.bytes();
        if (raw == null || raw.length == 0) return;
        ParsedReq pr = ParsedReq.parse(raw);
        if (src.host() == null || src.host().isEmpty()) {
            // hooked tab: service unknown yet, wait for the first send matching Host + path
            HookOriginal h = new HookOriginal();
            h.hostHeader = pr.hostHeader;
            h.pathKey = keys.pathKey(pr.path);
            h.segs = ApiKeys.segments(h.pathKey);
            h.raw = raw;
            h.millis = o.millis();
            hookOriginals.addLast(h);
            hookBytes += raw.length;
            while (hookOriginals.size() > 200 || (hookBytes > MAX_HOOK_BYTES && hookOriginals.size() > 1)) dropOldestHook();
            return;
        }
        String hostKey = ApiKeys.hostKey(src.host(), src.port(), src.secure());
        ApiEntry api = ensureApi(hostKey, keys.pathKey(pr.path), pr.method, o.millis());
        addOriginal(api, raw, pr, src.host(), src.port(), src.secure(), o.sourceKind(), o.millis(), o.response());
    }

    private void dropOldestHook() {
        HookOriginal h = hookOriginals.pollFirst();
        if (h != null) hookBytes -= h.raw.length;
    }

    // ---------- processing a send ----------

    private void processFinished(Finished f) {
        RequestSource src = (f.resp != null && f.resp.initiating() != null) ? f.resp.initiating()
                : (f.send != null ? f.send.req() : null);
        if (src == null) return;
        byte[] raw = src.bytes();
        if (raw == null || raw.length == 0) return;
        ParsedReq pr = ParsedReq.parse(raw);
        String hostKey = ApiKeys.hostKey(src.host(), src.port(), src.secure());
        ReqInfo info = new ReqInfo(raw, pr, src.host(), src.port(), src.secure(), hostKey, keys.pathKey(pr.path));
        processInfo(f, info);
    }

    /*
     * Order for choosing the API + original request for a send:
     *   1. pending original from a hooked tab (matching Host + path; a variant only if the send's API has no original)
     *   2. the send's API already has an original
     *   3. a Proxy lookup for this API is pending
     *   4. look up Proxy history (async): exact match first. A path that exists in Proxy is its own API, never
     *      merged into a sibling API (/api/v1/orders does not go into the log of /api/v1/users)
     *   5. variant of an API with an original (path with one segment edited for testing: /users/john → /users/alice)
     *   6. the send becomes its own original; AI requests are never used as the original (logged without diff)
     */
    private void processInfo(Finished f, ReqInfo info) {
        long ts = f.send != null ? f.send.millis() : System.currentTimeMillis();
        ApiEntry api = apis.get(info.apiKey());
        boolean hasOriginal = api != null && !api.originals.isEmpty();
        if (!hookOriginals.isEmpty()) {
            HookOriginal h = matchHook(info, !hasOriginal);
            if (h != null) {
                ApiEntry a = ensureApi(info.hostKey(), h.pathKey, info.pr().method, h.millis);
                addOriginal(a, h.raw, ParsedReq.parse(h.raw), info.host(), info.port(), info.secure(), Rows.SRC_TABHOOK, h.millis,
                        null);
                api = apis.get(info.apiKey());
                hasOriginal = api != null && !api.originals.isEmpty();
            }
        }
        if (hasOriginal) { record(api, f, info, false); return; }
        Parked p = parked.get(info.apiKey());
        if (p != null) { p.items.add(f); return; }
        OriginalLookup lk = lookup;
        Long nf = notFound.get(info.apiKey());
        boolean recentlyNotFound = nf != null && System.nanoTime() - nf < NOT_FOUND_TTL_NS;
        if (lk != null && !f.lookedUp && !recentlyNotFound) {
            Parked np = new Parked();
            np.items.add(f);
            np.token = nextToken++;
            parked.put(info.apiKey(), np);
            liveTokens.add(np.token);
            try {
                lk.lookup(info.pr().method, info.hostKey(), info.pathKey(), info.apiKey(), np.token);
            } catch (Throwable t) {
                Log.rateLimited(t);
                resolveParked(info.apiKey(), np.token, null, 0, null);
            }
            return;
        }
        ApiEntry v = findVariant(info.hostKey(), ApiKeys.segments(info.pathKey()));
        if (v != null) { record(v, f, info, false); return; }
        if (kindOf(f) == Events.KIND_AI) { recordNoOriginal(f, info, ts); return; }
        selfOriginal(f, info, ts);
    }

    private void resolveParked(String apiKey, long token, RequestSource found, long foundMillis, Events.ResponseSource foundResp) {
        Parked p = parked.get(apiKey);
        if (p == null || p.token != token) return;                      // late result of an old lookup
        parked.remove(apiKey);
        liveTokens.remove(token);
        if (found == null) {
            notFound.put(apiKey, System.nanoTime());
            if (notFound.size() > 5_000) notFound.clear();
        } else {
            notFound.remove(apiKey);
            byte[] raw = found.bytes();
            if (raw != null && raw.length > 0) {
                ParsedReq pr = ParsedReq.parse(raw);
                String hostKey = ApiKeys.hostKey(found.host(), found.port(), found.secure());
                ApiEntry a = ensureApi(hostKey, keys.pathKey(pr.path), pr.method, foundMillis);
                addOriginal(a, raw, pr, found.host(), found.port(), found.secure(), Rows.SRC_PROXY,
                        foundMillis > 0 ? foundMillis : System.currentTimeMillis(), foundResp);
            }
        }
        for (Finished f : p.items) {
            f.lookedUp = true;
            processFinished(f);
        }
    }

    private HookOriginal matchHook(ReqInfo info, boolean allowVariant) {
        Iterator<HookOriginal> it = hookOriginals.descendingIterator();
        String[] segs = ApiKeys.segments(info.pathKey());
        HookOriginal variant = null;
        while (it.hasNext()) {
            HookOriginal h = it.next();
            if (!h.hostHeader.equalsIgnoreCase(info.pr().hostHeader)) continue;
            if (h.pathKey.equals(info.pathKey())) { removeHook(h); return h; }
            if (allowVariant && variant == null && ApiKeys.isVariant(h.segs, segs)) variant = h;
        }
        if (variant != null) removeHook(variant);
        return variant;
    }

    private void removeHook(HookOriginal h) {
        if (hookOriginals.remove(h)) hookBytes -= h.raw.length;
    }

    private static int kindOf(Finished f) {
        return f.send != null ? f.send.kind() : (f.resp != null ? f.resp.kind() : Events.KIND_REPEATER);
    }

    private ApiEntry findVariant(String hostKey, String[] segs) {
        List<ApiEntry> list = byHost.get(hostKey);
        if (list == null) return null;
        ApiEntry best = null;
        int bestScore = -1;
        for (ApiEntry a : list) {
            if (a.originals.isEmpty()) continue;
            int sc = ApiKeys.variantScore(a.segs, segs);
            if (sc < 0) continue;
            if (sc > bestScore || (sc == bestScore && a.lastSeen > best.lastSeen)) { best = a; bestScore = sc; }
        }
        return best;
    }

    private void selfOriginal(Finished f, ReqInfo info, long ts) {
        ApiEntry api = ensureApi(info.hostKey(), info.pathKey(), info.pr().method, ts);
        addOriginal(api, info.raw(), info.pr(), info.host(), info.port(), info.secure(), Rows.SRC_SELF, ts,
                f.resp == null ? null : f.resp.response());
        record(api, f, info, true);
    }

    private ApiEntry ensureApi(String hostKey, String pathKey, String method, long ts) {
        String apiKey = hostKey + pathKey;
        ApiEntry a = apis.get(apiKey);
        if (a != null) {
            if (a.method == null) a.method = method;
            return a;
        }
        a = new ApiEntry();
        a.id = nextApiId++;
        a.hostKey = hostKey; a.pathKey = pathKey; a.apiKey = apiKey; a.segs = ApiKeys.segments(pathKey);
        a.method = method;
        a.firstSeen = ts; a.lastSeen = ts;
        apis.put(apiKey, a);
        apisById.put(a.id, a);
        byHost.computeIfAbsent(hostKey, k -> new ArrayList<>()).add(a);
        writer.submit(DbWriter.insertApi(a.id, hostKey, pathKey, method, ts));
        return a;
    }

    private OriginalEntry addOriginal(ApiEntry api, byte[] raw, ParsedReq pr, String host, int port, boolean secure,
                                      int source, long ts, Events.ResponseSource resp) {
        for (OriginalEntry o : api.originals) if (Arrays.equals(o.features, pr.features)) return o;
        OriginalEntry o = new OriginalEntry();
        o.id = nextOriginalId++;
        int seq = ++api.seq;
        o.api = api; o.method = pr.method; o.ts = ts; o.source = source; o.features = pr.features;
        o.host = host; o.port = port; o.secure = secure;
        o.truncated = raw.length > MAX_ORIGINAL_RAW;
        o.bodyHash = pr.bodyHash; o.bodySize = pr.bodySize;
        byte[] kept = o.truncated ? Arrays.copyOf(raw, MAX_ORIGINAL_RAW) : raw;
        o.rawZ = Zip.deflate(kept);
        api.originals.add(o);
        parsedCache.put(o.id, pr);
        registry.idOf(ApiKeys.statusKeyOf(pr.method, api.apiKey));
        writer.submit(DbWriter.insertOriginal(o.id, api.id, ts, source, pr.method, redactedFirstLine(pr),
                longsToBytes(pr.features), host, port, secure, o.rawZ, o.bodyHash, o.bodySize, o.truncated, seq));
        storeOriginalContext(o, api, raw, pr, resp);
        listener.apiChanged(row(api));
        return o;
    }

    /**
     * Readable request + response of an original (columns request_text / response_text), the context an AI needs to
     * read the log. Response: from the event when known, otherwise looked up in Proxy history (tab hook, tracked send
     * from an editor without a response). Follows the "store raw requests" option.
     */
    private void storeOriginalContext(OriginalEntry o, ApiEntry api, byte[] raw, ParsedReq pr, Events.ResponseSource resp) {
        if (!settings.storeRaw) return;
        try {
            String reqText = HttpText.of(raw, HttpText.MAX_CHARS);
            if (reqText != null) writer.submit(DbWriter.setOriginalText(o.id, reqText, null));
        } catch (Throwable t) {
            Log.rateLimited(t);
        }
        if (resp != null) {
            storeOriginalResponse(o.id, resp);
        } else if (o.source == Rows.SRC_TABHOOK || o.source == Rows.SRC_TRACKED) {
            OriginalLookup lk = lookup;
            if (lk != null) {
                try { lk.lookupResponse(o.id, ApiKeys.statusKeyOf(pr.method, api.apiKey), raw); }
                catch (Throwable t) { Log.rateLimited(t); }
            }
        }
    }

    private void storeOriginalResponse(int originalId, Events.ResponseSource resp) {
        if (!settings.storeRaw || resp == null) return;
        try {
            String text = HttpText.of(resp.bytes(HttpText.MAX_RAW), HttpText.MAX_CHARS);
            if (text != null) writer.submit(DbWriter.setOriginalText(originalId, null, text));
        } catch (Throwable t) {
            Log.rateLimited(t);
        }
    }

    private byte[] rawZOf(OriginalEntry o) {
        return o.rawZ != null ? o.rawZ : originalLoader.apply(o.id);
    }

    /** Compression dictionary for sends against original o (first 32 KB of the original), cached. */
    private byte[] dictOf(OriginalEntry o) {
        if (o == null) return null;
        byte[] d = dictCache.get(o.id);
        if (d != null) return d;
        d = Zip.dictOf(Zip.inflate(rawZOf(o)));
        if (d != null) dictCache.put(o.id, d);
        return d;
    }

    private ParsedReq parsedOf(OriginalEntry o) {
        ParsedReq p = parsedCache.get(o.id);
        if (p != null) return p;
        byte[] raw = Zip.inflate(rawZOf(o));
        if (raw == null) return null;                                     // DB read error: don't cache an empty result
        if (!dictCache.containsKey(o.id)) {
            byte[] d = Zip.dictOf(raw);
            if (d != null) dictCache.put(o.id, d);
        }
        p = ParsedReq.parse(raw);
        // truncated copy: keep the full body fingerprint to avoid false body diffs
        if (o.truncated) p = p.withLargeBody(o.bodyHash, o.bodySize);
        parsedCache.put(o.id, p);
        return p;
    }

    private OriginalEntry choose(ApiEntry api, long[] features) {
        OriginalEntry best = null;
        int bestD = Integer.MAX_VALUE;
        for (OriginalEntry o : api.originals) {
            int d = ParsedReq.distance(o.features, features);
            if (d < bestD || (d == bestD && best != null && o.id > best.id)) { best = o; bestD = d; }
        }
        return best;
    }

    private void record(ApiEntry api, Finished f, ReqInfo info, boolean selfOriginal) {
        OriginalEntry o = choose(api, info.pr().features);
        ParsedReq op = parsedOf(o);
        Redactor r = redactor;
        List<Diff.Change> changes = op == null ? List.of() : Diff.compute(op, info.pr(), r, settings.ignoredHeaders);

        long ts = f.send != null ? f.send.millis() : System.currentTimeMillis();
        int flags = op == null ? Rows.FLAG_ORIGINAL_UNAVAILABLE : 0;
        if (f.resp == null) flags |= Rows.FLAG_NO_RESPONSE;
        if (isRedirectFollow(info)) flags |= Rows.FLAG_REDIRECT;
        if (selfOriginal && changes.isEmpty()) flags |= Rows.FLAG_SELF_ORIGINAL;
        int ms = (f.send != null && f.resp != null) ? (int) Math.max(0, (f.resp.nano() - f.send.nano()) / 1_000_000) : -1;
        int st = f.resp != null ? f.resp.status() : 0;
        int len = f.resp != null ? f.resp.length() : -1;
        int kind = kindOf(f);
        String source = f.send != null ? f.send.source() : (kind == Events.KIND_AI ? "ai" : "repeater");
        boolean storeRaw = settings.storeRaw && info.raw().length <= MAX_BLOB_RAW;
        if (settings.storeRaw && !storeRaw) flags |= Rows.FLAG_RAW_DROPPED;

        String firstLine = redactedFirstLine(info.pr());
        String text = Diff.format(changes);
        if (text.length() > MAX_CHANGES) text = text.substring(0, MAX_CHANGES) + "\n… (truncated)";
        String search = searchText(firstLine + "\n" + (text.length() > MAX_SEARCH ? text.substring(0, MAX_SEARCH) : text));

        long id = nextSendId++;
        Rows.SendRow row = new Rows.SendRow(id, api.id, o.id, ts, st, len, ms, flags, source, Diff.locMask(changes),
                firstLine, text, ++api.seq);
        writer.submit(DbWriter.insertSend(row, search));
        // compress with the original as dictionary: a send differs from it by a few bytes, so the stored copy is tiny
        if (storeRaw) writer.submit(DbWriter.insertBlob(id, Zip.deflate(info.raw(), dictOf(o))));

        api.sendCount++;
        api.lastSeen = Math.max(api.lastSeen, ts);

        String sk = ApiKeys.statusKeyOf(o.method, api.apiKey);
        boolean meaningful = false;
        for (Diff.Change c : changes) if (!Noise.ignorableForStatus(c)) { meaningful = true; break; }
        raiseStatus(sk, (meaningful && (flags & Rows.FLAG_REDIRECT) == 0) ? StatusIndex.TESTED : StatusIndex.SENT);
        processed.increment();
        Listener l = listener;
        l.sendAdded(row);
        l.apiChanged(row(api));
        boolean tabNamedByUser = o.source == Rows.SRC_TRACKED || o.source == Rows.SRC_TABHOOK;
        if (kind == Events.KIND_REPEATER && !tabNamedByUser && api.sendCount == 1) {
            l.renameHint(info.pr().firstLine, info.pr().hostHeader, TabNames.tabName(info.pr().method, info.pr().path, java.util.Set.of()));
        }
    }

    private void raiseStatus(String sk, byte newState) {
        if (status.raise(sk, newState)) {
            int skId = registry.idOf(sk);
            writer.submit(DbWriter.raiseStatus(skId, newState));
            if (newState == StatusIndex.TESTED) {
                try { testedListener.markTested(sk); } catch (Throwable t) { Log.rateLimited(t); }
            }
        }
    }

    /** AI request for an API with no original: log the send (no diff), create no original, don't mark it "tested". */
    private void recordNoOriginal(Finished f, ReqInfo info, long ts) {
        ApiEntry api = ensureApi(info.hostKey(), info.pathKey(), info.pr().method, ts);
        int flags = Rows.FLAG_NO_ORIGINAL;
        if (f.resp == null) flags |= Rows.FLAG_NO_RESPONSE;
        if (isRedirectFollow(info)) flags |= Rows.FLAG_REDIRECT;
        int ms = (f.send != null && f.resp != null) ? (int) Math.max(0, (f.resp.nano() - f.send.nano()) / 1_000_000) : -1;
        int st = f.resp != null ? f.resp.status() : 0;
        int len = f.resp != null ? f.resp.length() : -1;
        String source = f.send != null ? f.send.source() : "ai";
        boolean storeRaw = settings.storeRaw && info.raw().length <= MAX_BLOB_RAW;
        if (settings.storeRaw && !storeRaw) flags |= Rows.FLAG_RAW_DROPPED;
        String firstLine = redactedFirstLine(info.pr());
        long id = nextSendId++;
        Rows.SendRow row = new Rows.SendRow(id, api.id, 0, ts, st, len, ms, flags, source, 0, firstLine, "", ++api.seq);
        writer.submit(DbWriter.insertSend(row, searchText(firstLine)));
        if (storeRaw) writer.submit(DbWriter.insertBlob(id, Zip.deflate(info.raw())));
        api.sendCount++;
        api.lastSeen = Math.max(api.lastSeen, ts);
        raiseStatus(ApiKeys.statusKeyOf(info.pr().method, api.apiKey), StatusIndex.SENT);
        processed.increment();
        Listener l = listener;
        l.sendAdded(row);
        l.apiChanged(row(api));
    }

    // ---------- Intruder ----------

    /** One Intruder attack snapshot: the first one inserts a row, later ones update the same row. */
    private void onAttack(AttackEvent e) {
        AttackState st = attacks.get(e.attackId());
        boolean insert = st == null;
        if (insert) {
            if (e.base() == null || e.base().length == 0) return;
            st = new AttackState();
            st.base = ParsedReq.parse(e.base());
            String hostKey = ApiKeys.hostKey(e.host(), e.port(), e.secure());
            String pathKey = keys.pathKey(st.base.path);
            java.util.Set<Integer> fuzzed = pathPositions(e.positions());
            ApiEntry api = fuzzed.isEmpty() ? null : templateMatch(hostKey, ApiKeys.segments(pathKey), fuzzed);
            if (api == null) {
                api = ensureApi(hostKey, fuzzed.isEmpty() ? pathKey : templatePath(pathKey, fuzzed), st.base.method,
                        e.startMillis());
            }
            st.api = api;
            OriginalEntry o = api.originals.isEmpty() ? null : choose(api, st.base.features);
            st.originalId = o == null ? 0 : o.id;
            st.sendId = nextSendId++;
            st.seq = ++api.seq;
            if (!e.finished()) attacks.put(e.attackId(), st);
            if (settings.storeRaw && e.base().length <= MAX_BLOB_RAW) {
                writer.submit(DbWriter.insertBlob(st.sendId, Zip.deflate(e.base(), dictOf(o))));
            }
            st.api.sendCount++;
        } else if (e.finished()) {
            attacks.remove(e.attackId());
        }
        ApiEntry api = st.api;
        api.lastSeen = Math.max(api.lastSeen, e.endMillis());

        Redactor r = redactor;
        String firstLine = templateFirstLine(st.base, e.positions(), r);
        StringBuilder ch = new StringBuilder();
        int loc = 0;
        for (FieldLocator.Field f : e.positions()) {
            loc |= f.loc();
            if (ch.length() > 0) ch.append('\n');
            String l = Diff.locName(f.loc());
            ch.append("§ ").append(l);
            if (!f.name().isEmpty()) {
                for (int i = l.length(); i < 7; i++) ch.append(' ');
                ch.append(' ').append(safeName(f.name(), r));
            }
        }
        if (e.moreParams() > 0) ch.append("\n§ … +").append(e.moreParams()).append(e.moreParams() == 1 ? " more position" : " more positions");
        if (e.positions().isEmpty()) {
            ch.append(e.requests() <= 1 ? "(only 1 request so far: payload positions not yet known)"
                    : "(identical requests: no payload position changed)");
        }
        ch.append('\n').append(attackSummary(e));
        String changes = ch.toString();
        int topStatus = 0, topCount = -1;
        for (Map.Entry<Integer, Integer> s : e.statuses().entrySet()) {
            if (s.getValue() > topCount) { topStatus = s.getKey(); topCount = s.getValue(); }
        }
        int flags = Rows.FLAG_INTRUDER | (e.finished() ? 0 : Rows.FLAG_RUNNING);
        int ms = (int) Math.min(Integer.MAX_VALUE, Math.max(0, e.endMillis() - e.startMillis()));
        Rows.SendRow row = new Rows.SendRow(st.sendId, api.id, st.originalId, e.startMillis(), topStatus, e.maxLen(), ms,
                flags, "intruder", loc, firstLine, changes, st.seq);
        String search = searchText("intruder " + firstLine + "\n" + (changes.length() > MAX_SEARCH ? changes.substring(0, MAX_SEARCH) : changes));
        int statusMask = 0;
        for (Integer s : e.statuses().keySet()) statusMask |= Rows.statusClassBit(s);
        // upsert: if the initial insert was dropped (queue full), a later update still creates the row
        writer.submit(insert ? DbWriter.insertSend(row, search, statusMask) : DbWriter.updateSend(row, search, statusMask));
        if (!e.positions().isEmpty() && !st.testedRaised) {
            st.testedRaised = true;
            raiseStatus(ApiKeys.statusKeyOf(st.base.method, api.apiKey), StatusIndex.TESTED);
        }
        processed.increment();
        Listener l = listener;
        l.sendAdded(row);
        l.apiChanged(row(api));
    }

    private static java.util.Set<Integer> pathPositions(List<FieldLocator.Field> positions) {
        java.util.Set<Integer> out = new java.util.TreeSet<>();
        for (FieldLocator.Field f : positions) {
            if (f.loc() != Diff.LOC_PATH || !f.name().startsWith("[")) continue;
            try { out.add(Integer.parseInt(f.name().substring(1, f.name().length() - 1))); }
            catch (NumberFormatException ignored) { /* ignore */ }
        }
        return out;
    }

    /**
     * API matching the attack template: same segments outside fuzzed positions, and a placeholder at fuzzed positions
     * ({id}, {uuid}, {hex}, {token}, §). Never attaches to a concrete sibling API (/api/orders when fuzzing /api/§):
     * the template API /api/§ is used instead so the sibling is not wrongly marked tested.
     */
    private ApiEntry templateMatch(String hostKey, String[] segs, java.util.Set<Integer> fuzzed) {
        List<ApiEntry> list = byHost.get(hostKey);
        if (list == null) return null;
        ApiEntry best = null;
        outer:
        for (ApiEntry a : list) {
            if (a.segs.length != segs.length) continue;
            for (int i = 0; i < segs.length; i++) {
                if (fuzzed.contains(i)) { if (!isPlaceholder(a.segs[i])) continue outer; }
                else if (!a.segs[i].equals(segs[i])) continue outer;
            }
            if (best == null) { best = a; continue; }
            boolean ao = !a.originals.isEmpty(), bo = !best.originals.isEmpty();
            if ((ao && !bo) || (ao == bo && a.lastSeen > best.lastSeen)) best = a;
        }
        return best;
    }

    private static boolean isPlaceholder(String seg) {
        return seg.equals("§") || seg.equals("{id}") || seg.equals("{uuid}") || seg.equals("{hex}") || seg.equals("{token}");
    }

    private static String templatePath(String pathKey, java.util.Set<Integer> fuzzed) {
        String[] segs = ApiKeys.segments(pathKey);
        StringBuilder b = new StringBuilder();
        // keep segments that are already placeholders ({id}…): /api/orders/{id} rather than /api/orders/§
        for (int i = 0; i < segs.length; i++) b.append('/').append(fuzzed.contains(i) && !isPlaceholder(segs[i]) ? "§" : segs[i]);
        return b.length() == 0 ? "/" : b.toString();
    }

    /** First line as an attack template: path segments / query params that are payload positions show as §. */
    private static String templateFirstLine(ParsedReq base, List<FieldLocator.Field> positions, Redactor r) {
        java.util.Set<Integer> segs = pathPositions(positions);
        java.util.Set<String> qn = new java.util.HashSet<>();
        boolean method = false, queryNames = false;
        for (FieldLocator.Field f : positions) {
            if (f.loc() == Diff.LOC_QUERY) {
                if (f.name().equals(FieldLocator.nameFuzz(Diff.LOC_QUERY))) queryNames = true;
                else qn.add(f.name());
            } else if (f.loc() == Diff.LOC_METHOD) method = true;
        }
        String target = base.target;
        int q = target.indexOf('?');
        String path = q >= 0 ? target.substring(0, q) : target;
        StringBuilder t = new StringBuilder();
        if (!segs.isEmpty() && path.startsWith("/")) {
            int idx = 0;
            String[] parts = path.split("/", -1);
            for (int i = 1; i < parts.length; i++) {
                t.append('/');
                if (parts[i].isEmpty()) continue;
                t.append(segs.contains(idx) ? "§" : parts[i]);
                idx++;
            }
        } else {
            t.append(path);
        }
        if (q >= 0 && queryNames) {
            t.append("?§");                                               // param name fuzzing: don't reveal the first payload name
        } else if (q >= 0) {
            t.append('?');
            String[] pairs = target.substring(q + 1).split("&", -1);
            for (int i = 0; i < pairs.length; i++) {
                if (i > 0) t.append('&');
                int eq = pairs[i].indexOf('=');
                String name = eq < 0 ? pairs[i] : pairs[i].substring(0, eq);
                t.append(qn.contains(name) ? name + "=§" : pairs[i]);
            }
        }
        return (method ? "§" : base.method) + " " + r.redactTarget(t.toString())
                + (base.version.isEmpty() ? "" : " " + base.version);
    }

    /**
     * Text for the search index: Unicode lowercase, so LIKE (small APIs) and FTS (large APIs) give the same results
     * for accented text (SQLite LIKE is case-insensitive only for ASCII).
     */
    static String searchText(String s) {
        return s.toLowerCase(Locale.ROOT);
    }

    private static String safeName(String name, Redactor r) {
        return Redactor.clip(name);
    }

    static String attackSummary(AttackEvent e) {
        StringBuilder b = new StringBuilder("→ ").append(String.format("%,d", e.requests())).append(e.requests() == 1 ? " request" : " requests");
        List<Map.Entry<Integer, Integer>> st = new ArrayList<>(e.statuses().entrySet());
        st.sort((x, y) -> y.getValue() - x.getValue());
        for (int i = 0; i < st.size() && i < 5; i++) {
            Map.Entry<Integer, Integer> s = st.get(i);
            b.append(i == 0 ? " · " : "  ").append(s.getKey()).append('×').append(String.format("%,d", s.getValue()));
        }
        if (st.size() > 5) b.append("  …");
        if (e.maxLen() >= 0) {
            b.append(" · ").append(String.format("%,d", Math.max(0, e.minLen())));
            if (e.maxLen() != e.minLen()) b.append('–').append(String.format("%,d", e.maxLen()));
            b.append(" B");
        }
        b.append(" · ").append(duration(e.endMillis() - e.startMillis()));
        if (!e.finished()) b.append(" · running");
        if (e.approximate()) b.append(" · ≈ (some requests skipped due to overload)");
        return b.toString();
    }

    static String duration(long ms) {
        long s = Math.max(0, ms) / 1000;
        if (s < 1) return "< 1 s";
        if (s < 60) return s + " s";
        if (s < 3600) return (s / 60) + " min" + (s % 60 > 0 ? " " + (s % 60) + " s" : "");
        return (s / 3600) + " h" + ((s % 3600) / 60 > 0 ? " " + ((s % 3600) / 60) + " min" : "");
    }

    // ---------- redirect ----------

    private void recordRedirect(Finished f) {
        ResponseEvent r = f.resp;
        if (r == null || r.location() == null || r.status() < 300 || r.status() >= 400) return;
        RequestSource src = r.initiating() != null ? r.initiating() : (f.send != null ? f.send.req() : null);
        if (src == null) return;
        try {
            byte[] raw = src.bytes();
            ParsedReq pr = ParsedReq.parse(raw);
            String base = url(src.secure(), src.host(), src.port(), pr.target);
            URI resolved = URI.create(base).resolve(r.location().trim());
            redirects.addLast(new Redirect(normUrl(resolved), r.nano()));
            while (redirects.size() > 50) redirects.pollFirst();
        } catch (RuntimeException ignored) {
            // invalid Location
        }
    }

    private boolean isRedirectFollow(ReqInfo info) {
        if (redirects.isEmpty()) return false;
        String u;
        try { u = normUrl(URI.create(url(info.secure(), info.host(), info.port(), info.pr().target))); }
        catch (RuntimeException e) { return false; }
        long now = System.nanoTime();
        for (Iterator<Redirect> it = redirects.descendingIterator(); it.hasNext(); ) {
            Redirect rd = it.next();
            if (now - rd.nano() > REDIRECT_WINDOW_NS * 5) break;
            if (rd.url().equals(u)) { it.remove(); return true; }
        }
        return false;
    }

    static String url(boolean secure, String host, int port, String target) {
        String h = host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
        String t = target.startsWith("/") ? target : (target.contains("://") ? URI.create(target).getRawPath() : "/" + target);
        return (secure ? "https://" : "http://") + h + ":" + port + t;
    }

    static String normUrl(URI u) {
        String scheme = u.getScheme() == null ? "http" : u.getScheme().toLowerCase(Locale.ROOT);
        int port = u.getPort() >= 0 ? u.getPort() : (scheme.equals("https") ? 443 : 80);
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
        String path = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
        return scheme + "://" + host + ":" + port + path + (u.getRawQuery() == null ? "" : "?" + u.getRawQuery());
    }

    // ---------- utilities ----------

    private String redactedFirstLine(ParsedReq pr) {
        return pr.method + " " + redactor.redactTarget(pr.target) + (pr.version.isEmpty() ? "" : " " + pr.version);
    }

    private Rows.ApiRow row(ApiEntry a) {
        String method = !a.originals.isEmpty() ? a.originals.get(0).method : (a.method != null ? a.method : "?");
        boolean tested = a.method != null && status.isTested(ApiKeys.statusKeyOf(a.method, a.apiKey));
        for (OriginalEntry o : a.originals) {
            if (tested) break;
            if (status.isTested(ApiKeys.statusKeyOf(o.method, a.apiKey))) tested = true;
        }
        return new Rows.ApiRow(a.id, a.hostKey, a.pathKey, method, a.sendCount, a.lastSeen, tested, a.originals.size());
    }

    /** Snapshot of the API list for the UI (call before start or from the worker itself). */
    public List<Rows.ApiRow> snapshotRows() {
        List<Rows.ApiRow> out = new ArrayList<>(apis.size());
        for (ApiEntry a : apis.values()) out.add(row(a));
        return out;
    }

    static byte[] longsToBytes(long[] a) {
        ByteBuffer b = ByteBuffer.allocate(a.length * 8);
        for (long x : a) b.putLong(x);
        return b.array();
    }

    static long[] bytesToLongs(byte[] b) {
        if (b == null) return new long[0];
        ByteBuffer bb = ByteBuffer.wrap(b);
        long[] a = new long[b.length / 8];
        for (int i = 0; i < a.length; i++) a[i] = bb.getLong();
        return a;
    }
}
