package apitracker.core;

import apitracker.core.Events.AttackEvent;
import apitracker.core.Events.RequestSource;
import apitracker.core.FieldLocator.Field;
import apitracker.util.Log;

import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Predicate;

/**
 * Groups Intruder requests into attacks and infers payload positions, on a dedicated thread (tracker-intruder) so
 * Intruder traffic does not get in the way of Repeater / AI logging.
 *
 * <p>For each request (once its response arrives):
 * <ol>
 *   <li>Compare with the previous request of each open attack on the same host, chunk by chunk ([request line + headers
 *       before Content-Length], [headers after], [body]; Content-Length is skipped since Intruder updates it): the
 *       common prefix / suffix (vectorized byte compare) gives the differing range.</li>
 *   <li>Fast path: {@link FieldLocator} tells which field each range is in (sniper, cluster bomb: almost every
 *       request). Slow path when a range spans several fields (pitchfork, battering ram): full parse, compare field names.</li>
 *   <li>Pick the attack by structure, not byte count: a request joins an attack if at most {@value #MAX_NOVEL} changed
 *       fields are new to it (payload length never splits an attack). No match: open a new attack.</li>
 *   <li>An attack ends after no request for max(8 s, 5 × the average gap between requests), so slow attacks
 *       (throttled, time-based SQLi) are not split into several attacks.</li>
 * </ol>
 * Union of fields changed between consecutive requests = every field seen with two or more values = payload positions,
 * even when responses arrive out of order. The log holds only field names and stats; payloads never reach it (param
 * name fuzzing is recorded as "(param name)"). The first request's raw bytes are stored like any other send when
 * raw request storage is on.
 */
public final class IntruderTracker implements Runnable {
    /** An Intruder request with its response. Created on a Burp thread; nothing is read there. */
    public record Hit(long nano, long millis, int status, int length, String location, int estBytes, RequestSource req) {
        public Hit(long nano, long millis, int status, int length, RequestSource req) {
            this(nano, millis, status, length, null, 0, req);
        }
    }

    static final long IDLE_NS = TimeUnit.SECONDS.toNanos(8);
    static final long MAX_IDLE_NS = TimeUnit.SECONDS.toNanos(120);
    static final long SINGLE_IDLE_NS = TimeUnit.SECONDS.toNanos(60);
    /** An attack with over 10 requests waits at least 30 s (one long sleep payload mid-attack does not split it). */
    static final long LONG_IDLE_NS = TimeUnit.SECONDS.toNanos(30);
    /** Attack ran long enough that a path segment changing for the first time means a new attack on a sibling endpoint. */
    static final int ESTABLISHED = 20;
    static final long SNAPSHOT_NS = TimeUnit.SECONDS.toNanos(5);
    static final long REDIRECT_TTL_NS = TimeUnit.SECONDS.toNanos(10);
    static final int MAX_OPEN = 32;
    static final int MAX_POSITIONS = 32;
    static final int MAX_NOVEL = 12;
    static final int MAX_RAW = 2 * 1024 * 1024;
    static final long MAX_QUEUED_BYTES = 64L * 1024 * 1024;

    private final BlockingQueue<Hit> q = new ArrayBlockingQueue<>(4_096);
    private final AtomicLong queuedBytes = new AtomicLong();
    public final LongAdder dropped = new LongAdder();
    public final LongAdder processed = new LongAdder();
    public final LongAdder fastPath = new LongAdder();
    public final LongAdder slowPath = new LongAdder();
    public final LongAdder followUps = new LongAdder();
    private final Settings settings;
    private final Predicate<AttackEvent> sink;
    private final List<Attack> open = new ArrayList<>();
    private final List<AttackEvent> unsentFinal = new ArrayList<>();
    /** Pending redirect target URL → {redirect count, deadline}: counts every in-flight redirect to the same target. */
    private final Map<String, long[]> redirects = new LinkedHashMap<>();
    private long nextId = 1;
    private java.util.function.LongSupplier clock = System::nanoTime;
    private volatile boolean running = true;
    private Thread thread;

    private static final class Attack {
        long id;
        String host;
        int port;
        boolean secure;
        byte[] base, prev;
        FieldLocator.Parts prevParts;
        ParsedReq prevParsed;
        final Map<String, Field> positions = new LinkedHashMap<>();
        int morePositions;
        int requests;
        final Map<Integer, Integer> statuses = new TreeMap<>();
        int minLen = Integer.MAX_VALUE, maxLen = -1;
        long startMillis, endMillis, lastHitNs, lastEmitNs, gapNs;
        long droppedAtStart;
        boolean emitted, dirty;
    }

    /** sink returns false when the worker is busy (interim snapshots are resent later; final ones are kept for retry). */
    public IntruderTracker(Settings settings, Predicate<AttackEvent> sink) {
        this.settings = settings;
        this.sink = sink;
    }

    public void start() {
        thread = new Thread(this, "tracker-intruder");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Stops, drains the queue (up to 300 ms) and finishes all open attacks. Does not interrupt the thread (interrupting
     * while sending the final summary line to the worker would lose it): wakes it with an empty element instead.
     */
    public void stop(long waitMs) {
        running = false;
        if (thread == null) return;
        q.offer(WAKE);
        try { thread.join(waitMs); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static final Hit WAKE = new Hit(0, 0, 0, 0, null);

    /** Called from a Burp thread: never blocks. Caps both the element count and the estimated queued bytes. */
    public boolean submit(Hit h) {
        int est = Math.max(1024, h.estBytes());
        if (queuedBytes.get() + est <= MAX_QUEUED_BYTES && q.offer(h)) {
            queuedBytes.addAndGet(est);
            return true;
        }
        dropped.increment();
        return false;
    }

    public int queueSize() { return q.size(); }

    /** Fake clock for tests (slow attacks, idle timeout). */
    public void setClockForTest(java.util.function.LongSupplier c) { clock = c; }

    private Hit take(Hit h) {
        if (h != null && h.req() != null) queuedBytes.addAndGet(-Math.max(1024, h.estBytes()));
        return h;
    }

    @Override
    public void run() {
        long lastSweep = System.nanoTime();
        try {
            while (running) {
                Hit h;
                try { h = take(q.poll(500, TimeUnit.MILLISECONDS)); }
                catch (InterruptedException ie) { if (!running) break; continue; }
                if (h != null) {
                    try { handle(h); } catch (Throwable t) { Log.rateLimited(t); }
                }
                long now = System.nanoTime();
                if (now - lastSweep > 1_000_000_000L) {
                    try { sweep(clock.getAsLong()); } catch (Throwable t) { Log.rateLimited(t); }
                    lastSweep = now;
                }
            }
            Thread.interrupted();
            long end = System.nanoTime() + 300_000_000L;
            Hit h;
            while (System.nanoTime() < end && (h = take(q.poll())) != null) {
                try { handle(h); } catch (Throwable t) { Log.rateLimited(t); }
            }
        } finally {
            Thread.interrupted();
            finishAllForTest();
        }
    }

    /** Drains the queue synchronously (for tests). */
    public void drainForTest() {
        Hit h;
        while ((h = take(q.poll())) != null) handle(h);
    }

    public void sweepForTest(long now) { sweep(now); }

    /** Finishes all open attacks and sends any pending final snapshots. */
    public void finishAllForTest() {
        for (Attack a : new ArrayList<>(open)) finish(a);
        open.clear();
        retryUnsent();
    }

    // ---------- processing ----------

    void handle(Hit h) {
        if (h.req() == null || !settings.intruderEnabled) return;
        RequestSource src = h.req();
        byte[] raw = src.bytes();
        if (raw == null || raw.length == 0) return;
        if (raw.length > MAX_RAW) { dropped.increment(); return; }
        String host = src.host() == null ? "" : src.host();
        int port = src.port();
        boolean secure = src.secure();
        FieldLocator.Parts parts = FieldLocator.parts(raw);
        long now = clock.getAsLong();

        // Intruder auto-following a redirect ("Follow redirections" option): not a request of the attack
        // only a bodiless GET can be a redirect follow (so an attack POST to the same URL as Location is not
        // swallowed by mistake)
        if (!redirects.isEmpty() && parts.bodyStart >= parts.len && startsWithGet(raw)) {
            String url = urlOf(raw, parts, host, port, secure);
            long[] r = url == null ? null : redirects.get(url);
            if (r != null && r[1] > now && r[0] > 0) {
                if (--r[0] == 0) redirects.remove(url);
                followUps.increment();
                return;
            }
        }
        if (h.status() >= 300 && h.status() < 400 && h.location() != null) noteRedirect(raw, parts, host, port, secure, h.location(), now);

        // rank candidates by differing byte count (cheap), then check the top 2 by field (costlier)
        List<Object[]> cands = new ArrayList<>(2);
        for (Attack a : open) {
            if (a.port != port || a.secure != secure || !a.host.equalsIgnoreCase(host)) continue;
            long[] d = chunkDiffs(a.prev, a.prevParts, raw, parts);
            long size = 0;
            for (int k = 0; k < d.length; k += 4) size += Math.max(d[k + 1] - d[k], d[k + 3] - d[k + 2]);
            cands.add(new Object[]{a, d, size});
        }
        cands.sort((x, y) -> Long.compare((Long) x[2], (Long) y[2]));
        Attack best = null;
        Detection bestDet = null;
        long bestScore = Long.MAX_VALUE;
        for (int i = 0; i < cands.size() && i < 2; i++) {
            Attack a = (Attack) cands.get(i)[0];
            Detection det = detect(a, raw, parts, (long[]) cands.get(i)[1]);
            int novel = 0;
            for (Field f : det.fields()) if (!a.positions.containsKey(f.key())) novel++;
            // same attack when: only values changed (any payload length), or very little structure changed (param
            // name fuzzing, payload containing '/'), or the two requests are still over half identical by bytes
            long total = Math.max(1, Math.max(raw.length, a.prev.length));
            boolean similar = (Long) cands.get(i)[2] * 2 <= total;
            // established attack where a path segment now changes for the first time: next attack on a sibling endpoint
            // (/api/users/§id§ then /api/orders/§id§); don't merge, and don't record that segment as a payload position
            boolean newPathPosition = false;
            if (a.requests >= ESTABLISHED) {
                for (Field f : det.fields()) {
                    if (f.loc() == Diff.LOC_PATH && !a.positions.containsKey(f.key())) { newPathPosition = true; break; }
                }
            }
            boolean same = !newPathPosition && novel <= MAX_NOVEL && (det.structural() <= 2 || similar);
            long score = novel * 1_000L + det.structural() * 100L + Math.min(99, (Long) cands.get(i)[2] * 99 / total);
            if (same && score < bestScore) { best = a; bestDet = det; bestScore = score; }
        }
        processed.increment();
        if (best != null) {
            for (Field f : bestDet.fields()) addPosition(best, f);
            best.prev = raw;
            best.prevParts = parts;
            best.prevParsed = bestDet.parsed();               // null after fast path: re-parse next time if needed
            long gap = now - best.lastHitNs;
            best.gapNs = best.gapNs == 0 ? gap : (best.gapNs * 7 + gap) / 8;
        } else {
            best = newAttack(host, port, secure, raw, parts, h, now);
        }
        Attack a = best;
        a.requests++;
        a.statuses.merge(h.status(), 1, Integer::sum);
        if (h.length() >= 0) { a.minLen = Math.min(a.minLen, h.length()); a.maxLen = Math.max(a.maxLen, h.length()); }
        a.endMillis = Math.max(a.endMillis, h.millis());
        a.lastHitNs = now;
        a.dirty = true;
        if (!a.emitted && !a.positions.isEmpty()) emit(a, false);
        else if (a.emitted && now - a.lastEmitNs > SNAPSHOT_NS) emit(a, false);
    }

    /** Adds a position, skipping ignored headers (Content-Length, Connection) and "(body)" once a body field is known. */
    private void addPosition(Attack a, Field f) {
        if (f.loc() == Diff.LOC_HEADER && settings.ignoredHeaders.contains(f.name().toLowerCase(Locale.ROOT))) return;
        if (a.positions.containsKey(f.key())) return;
        String whole = new Field(Diff.LOC_BODY, FieldLocator.WHOLE_BODY).key();
        if (f.loc() == Diff.LOC_BODY) {
            if (f.name().equals(FieldLocator.WHOLE_BODY)) {
                for (Field p : a.positions.values()) if (p.loc() == Diff.LOC_BODY) return;
            } else {
                a.positions.remove(whole);
            }
        }
        if (a.positions.size() >= MAX_POSITIONS) { a.morePositions++; return; }
        a.positions.put(f.key(), f);
    }

    private Attack newAttack(String host, int port, boolean secure, byte[] raw, FieldLocator.Parts parts, Hit h, long now) {
        if (open.size() >= MAX_OPEN) {
            Attack oldest = open.get(0);
            for (Attack x : open) if (x.lastHitNs < oldest.lastHitNs) oldest = x;
            finish(oldest);
            open.remove(oldest);
        }
        Attack a = new Attack();
        a.id = nextId++;
        a.host = host;
        a.port = port;
        a.secure = secure;
        a.base = raw;
        a.prev = raw;
        a.prevParts = parts;
        a.startMillis = h.millis();
        a.endMillis = h.millis();
        a.droppedAtStart = dropped.sum();
        a.lastEmitNs = now;
        a.lastHitNs = now;
        open.add(a);
        return a;
    }

    /**
     * Differing range of each chunk: flat array [aFrom, aTo, bFrom, bTo] per chunk (aFrom == aTo == bFrom == bTo
     * when the chunk is identical). If chunk counts differ (only one has Content-Length), whole header blocks are compared.
     */
    public static long[] chunkDiffs(byte[] a, FieldLocator.Parts pa, byte[] b, FieldLocator.Parts pb) {
        int[][] ca = pa.chunks(), cb = pb.chunks();
        if (ca.length != cb.length) {
            ca = new int[][]{{0, pa.headEnd}, {pa.bodyStart, pa.len}};
            cb = new int[][]{{0, pb.headEnd}, {pb.bodyStart, pb.len}};
        }
        long[] out = new long[ca.length * 4];
        for (int k = 0; k < ca.length; k++) {
            int as = ca[k][0], ae = ca[k][1], bs = cb[k][0], be = cb[k][1];
            int p = FieldLocator.commonPrefix(a, as, ae, b, bs, be);
            if (p == ae - as && p == be - bs) {
                out[k * 4] = out[k * 4 + 1] = as + p;
                out[k * 4 + 2] = out[k * 4 + 3] = bs + p;
                continue;
            }
            int max = Math.min(ae - as, be - bs) - p;
            int s = FieldLocator.commonSuffix(a, as, ae, b, bs, be, max);
            out[k * 4] = as + p;
            out[k * 4 + 1] = ae - s;
            out[k * 4 + 2] = bs + p;
            out[k * 4 + 3] = be - s;
        }
        return out;
    }

    /** Result of comparing a request with the attack's previous one. parsed: the new request parsed (null after fast path). */
    private record Detection(List<Field> fields, int structural, ParsedReq parsed) {}

    /** Fields that differ between the attack's previous request and this one (fast path, or full parse). */
    private Detection detect(Attack a, byte[] raw, FieldLocator.Parts parts, long[] d) {
        List<Field> found = new ArrayList<>(2);
        boolean fast = true;
        boolean any = false;
        for (int k = 0; k < d.length; k += 4) {
            int af = (int) d[k], at = (int) d[k + 1], bf = (int) d[k + 2], bt = (int) d[k + 3];
            if (af == at && bf == bt) continue;
            any = true;
            Field f = FieldLocator.locate(a.prev, a.prevParts, af, at);
            // cannot locate on the previous request (inserted payload, or the previous payload broke the JSON):
            // try the current request
            if (f == null) f = FieldLocator.locate(raw, parts, bf, bt);
            if (f == null) { fast = false; break; }
            found.add(f);
        }
        if (!any) return new Detection(List.of(), 0, a.prevParsed);   // identical to the previous request: keep its parse
        if (fast) {
            fastPath.increment();
            int structural = 0;
            for (Field f : found) {
                if (f.loc() == Diff.LOC_METHOD || f.name().equals(FieldLocator.nameFuzz(f.loc()))) structural++;
            }
            return new Detection(found, structural, null);
        }
        slowPath.increment();
        ParsedReq prev = a.prevParsed != null ? a.prevParsed : ParsedReq.parse(a.prev);
        ParsedReq cur = ParsedReq.parse(raw);
        return new Detection(Diff.changedFields(prev, cur, settings.ignoredHeaders),
                Diff.structuralChanges(prev, cur, settings.ignoredHeaders), cur);
    }

    /**
     * Idle timeout of an attack: max(8 s, 5 × the average gap between responses), at most 2 min. A new attack with one
     * request (rate unknown) waits 60 s: single-request attacks are never logged, so keeping them costs only a little RAM.
     */
    private static long idleNs(Attack a) {
        if (a.requests < 2) return SINGLE_IDLE_NS;
        long floor = a.requests > 10 ? LONG_IDLE_NS : IDLE_NS;
        return Math.min(MAX_IDLE_NS, Math.max(floor, a.gapNs * 5));
    }

    private void sweep(long now) {
        for (int i = open.size() - 1; i >= 0; i--) {
            Attack a = open.get(i);
            if (now - a.lastHitNs > idleNs(a)) {
                finish(a);
                open.remove(i);
            } else if (a.dirty && a.emitted && now - a.lastEmitNs > SNAPSHOT_NS) {
                emit(a, false);
            } else if (a.dirty && !a.emitted && !a.positions.isEmpty()) {
                emit(a, false);                                   // first send was rejected because the worker was busy
            }
        }
        redirects.values().removeIf(r -> r[1] <= now);
        retryUnsent();
    }

    private void finish(Attack a) {
        // a lone request with no positions: no line (avoids log junk from requests that fit no attack)
        if (!a.emitted && a.positions.isEmpty() && a.requests < 2) return;
        emit(a, true);
    }

    private void emit(Attack a, boolean finished) {
        AttackEvent e = new AttackEvent(a.id, finished, a.host, a.port, a.secure, a.base,
                List.copyOf(a.positions.values()), a.morePositions, a.requests, Map.copyOf(a.statuses),
                a.minLen == Integer.MAX_VALUE ? -1 : a.minLen, a.maxLen, a.startMillis, a.endMillis,
                dropped.sum() > a.droppedAtStart);
        boolean ok;
        try { ok = sink.test(e); } catch (Throwable t) { Log.rateLimited(t); ok = false; }
        if (ok) {
            a.emitted = true;
            a.dirty = false;
            a.lastEmitNs = clock.getAsLong();
        } else if (finished) {
            if (unsentFinal.size() < 256) unsentFinal.add(e);
        }
    }

    private void retryUnsent() {
        for (Iterator<AttackEvent> it = unsentFinal.iterator(); it.hasNext(); ) {
            AttackEvent e = it.next();
            boolean ok;
            try { ok = sink.test(e); } catch (Throwable t) { ok = false; }
            if (!ok) return;
            it.remove();
        }
    }

    // ---------- redirect ----------

    private void noteRedirect(byte[] raw, FieldLocator.Parts parts, String host, int port, boolean secure, String location, long now) {
        String base = urlOf(raw, parts, host, port, secure);
        if (base == null) return;
        try {
            URI resolved = URI.create(base).resolve(location.trim());
            long[] r = redirects.computeIfAbsent(Tracker.normUrl(resolved), k -> new long[2]);
            r[0]++;
            r[1] = now + REDIRECT_TTL_NS;
            if (redirects.size() > 256) {
                Iterator<String> it = redirects.keySet().iterator();
                it.next();
                it.remove();
            }
        } catch (RuntimeException ignored) {
            // invalid Location
        }
    }

    private static boolean startsWithGet(byte[] raw) {
        return raw.length > 4 && raw[0] == 'G' && raw[1] == 'E' && raw[2] == 'T' && raw[3] == ' ';
    }

    private static String urlOf(byte[] raw, FieldLocator.Parts parts, String host, int port, boolean secure) {
        int end = parts.lineEnd;
        int sp1 = FieldLocator.indexOf(raw, (byte) ' ', 0, end);
        if (sp1 < 0) return null;
        int sp2 = FieldLocator.lastIndexOf(raw, (byte) ' ', sp1 + 1, end);
        String target = FieldLocator.latin1(raw, sp1 + 1, sp2 > sp1 ? sp2 : end);
        try {
            return Tracker.normUrl(URI.create(Tracker.url(secure, host, port, target)));
        } catch (RuntimeException e) {
            return null;
        }
    }
}
