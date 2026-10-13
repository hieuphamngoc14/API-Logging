package apitracker.store;

import apitracker.util.Log;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * The single SQLite writer thread (tracker-db), and the only thread using the write connection after startup.
 * Batches up to 500 commands per transaction. Never blocks callers for long: droppable commands (raw requests,
 * FTS merge) are dropped at once when the queue is full or pending data exceeds 64 MB; others wait up to 200 ms, then are dropped and counted.
 */
public final class DbWriter implements Runnable {
    public interface Cmd {
        void apply(Ctx c) throws SQLException;
        default boolean droppable() { return false; }
        /** Size of the data the command carries (to bound queue memory in bytes). */
        default int bytes() { return 0; }
    }

    /** Droppable commands are dropped when pending data exceeds this (large raw requests piling up on a slow disk). */
    static final long MAX_QUEUED_BYTES = 64L * 1024 * 1024;

    public static final class Ctx {
        final Connection conn;
        private final Map<String, PreparedStatement> cache = new HashMap<>();
        /** Per-API send count / last seen, aggregated over a batch, then written as one UPDATE per API. */
        final Map<Integer, long[]> apiDelta = new HashMap<>();
        Ctx(Connection c) { conn = c; }

        void countSend(int apiId, long ts) {
            long[] d = apiDelta.computeIfAbsent(apiId, k -> new long[]{0, Long.MIN_VALUE});
            d[0]++;
            d[1] = Math.max(d[1], ts);
        }

        void flushCounts() throws SQLException {
            if (apiDelta.isEmpty()) return;
            try {
                PreparedStatement u = ps("UPDATE apis SET send_count = send_count + ?, last_seen = max(coalesce(last_seen, 0), ?) WHERE id = ?");
                for (Map.Entry<Integer, long[]> e : apiDelta.entrySet()) {
                    u.setLong(1, e.getValue()[0]);
                    u.setLong(2, e.getValue()[1]);
                    u.setInt(3, e.getKey());
                    u.addBatch();
                }
                u.executeBatch();
            } finally {
                apiDelta.clear();
            }
        }
        public PreparedStatement ps(String sql) throws SQLException {
            PreparedStatement p = cache.get(sql);
            if (p == null) { p = conn.prepareStatement(sql); cache.put(sql, p); }
            return p;
        }
        void close() {
            for (PreparedStatement p : cache.values()) { try { p.close(); } catch (SQLException ignored) { } }
            cache.clear();
        }
    }

    private final BlockingQueue<Cmd> q = new ArrayBlockingQueue<>(10_000);
    private final Connection conn;
    private final boolean disabled;
    public final LongAdder dropped = new LongAdder();
    public final LongAdder written = new LongAdder();
    private final AtomicLong queuedBytes = new AtomicLong();
    private volatile boolean running = true;
    private volatile long lastCommitNs;
    private Thread thread;
    // hands off closing the connection when stop() times out while the thread is still writing
    private final Object exitLock = new Object();
    private boolean exited;
    private Runnable onExit;

    public DbWriter(Connection conn, boolean readOnly) {
        this.conn = conn;
        this.disabled = readOnly;
    }

    public void start() {
        thread = new Thread(this, "tracker-db");
        thread.setDaemon(true);
        thread.start();
    }

    /** Non-droppable commands wait up to 200 ms when the queue is full; droppable ones are dropped at once. False if dropped. */
    public boolean submit(Cmd c) {
        return submit(c, 200);
    }

    public boolean submit(Cmd c, long waitMs) {
        if (disabled || !running) return false;
        int size = c.bytes();
        boolean ok;
        if (c.droppable()) {
            ok = queuedBytes.get() + size <= MAX_QUEUED_BYTES && q.offer(c);
        } else {
            // the caller's interrupt flag (stopping) must not lose a write: clear it temporarily, then restore it
            boolean wasInterrupted = Thread.interrupted();
            try { ok = q.offer(c, waitMs, TimeUnit.MILLISECONDS); }
            catch (InterruptedException e) { wasInterrupted = true; ok = false; }
            finally { if (wasInterrupted) Thread.currentThread().interrupt(); }
        }
        if (ok) queuedBytes.addAndGet(size);
        else dropped.increment();
        return ok;
    }

    public int queueSize() { return q.size(); }
    public double lastCommitMs() { return lastCommitNs / 1e6; }

    @Override
    public void run() {
        Ctx ctx = new Ctx(conn);
        List<Cmd> batch = new ArrayList<>(512);
        try {
            while (running || !q.isEmpty()) {
                Cmd first;
                try { first = q.poll(1, TimeUnit.SECONDS); }
                catch (InterruptedException e) { if (!running) break; continue; }
                if (first == null) continue;
                batch.clear();
                batch.add(first);
                q.drainTo(batch, 499);
                commit(ctx, batch);
            }
            // flush the rest on stop
            batch.clear();
            q.drainTo(batch);
            if (!batch.isEmpty()) commit(ctx, batch);
        } finally {
            ctx.close();
            Runnable r;
            synchronized (exitLock) { exited = true; r = onExit; }
            if (r != null) {
                try { r.run(); } catch (Throwable t) { Log.error("closing DB after writes finished", t); }
            }
        }
    }

    private void commit(Ctx ctx, List<Cmd> batch) {
        long t0 = System.nanoTime();
        long bytes = 0;
        try {
            conn.setAutoCommit(false);
            for (Cmd c : batch) bytes += c.bytes();
            for (Cmd c : batch) {
                try { c.apply(ctx); }
                catch (SQLException e) {
                    // errors that make SQLite roll back the whole transaction (disk full, I/O, locking...): drop the batch,
                    // do not run the remaining commands in autocommit mode and do not count the rolled-back part
                    if (fatal(e)) throw e;
                    Log.error("DB write: " + e.getMessage(), null);
                }
            }
            ctx.flushCounts();
            conn.commit();
            written.add(batch.size());
        } catch (SQLException e) {
            Log.error("DB commit failed, dropping batch of " + batch.size() + " commands", e);
            ctx.apiDelta.clear();
            try { conn.rollback(); } catch (SQLException ignored) { }
        } finally {
            try { conn.setAutoCommit(true); } catch (SQLException ignored) { }
            queuedBytes.addAndGet(-bytes);
            lastCommitNs = System.nanoTime() - t0;
        }
    }

    /** SQLite error codes that roll the transaction back automatically. */
    static boolean fatal(SQLException e) {
        int code = e.getErrorCode() & 0xFF;
        return code == 5 /*BUSY*/ || code == 6 /*LOCKED*/ || code == 7 /*NOMEM*/ || code == 9 /*INTERRUPT*/
                || code == 10 /*IOERR*/ || code == 11 /*CORRUPT*/ || code == 13 /*FULL*/;
    }

    /**
     * Stops accepting new commands, flushes the queue, waits at most {@code waitMs}.
     * @return true if the writer thread has finished (the connection can be closed right away)
     */
    public boolean stop(long waitMs) {
        running = false;
        if (thread == null) return true;
        thread.interrupt();
        try { thread.join(waitMs); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        return !thread.isAlive();
    }

    /**
     * Hands closing the DB to the writer thread once it is done (never closes the connection under a running thread).
     * @return false if the thread has already finished: the caller closes it
     */
    public boolean closeWhenDone(Runnable closer) {
        synchronized (exitLock) {
            if (exited || thread == null) return false;
            onExit = closer;
            return true;
        }
    }

    /** Waits for the queue to empty (used in tests). */
    public void awaitIdle(long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (!q.isEmpty() && System.currentTimeMillis() < end) {
            try { Thread.sleep(10); } catch (InterruptedException e) { return; }
        }
        try { Thread.sleep(50); } catch (InterruptedException ignored) { }
    }

    // ---------- commands ----------

    public static Cmd insertApi(int id, String host, String pathKey, String method, long ts) {
        return c -> {
            PreparedStatement p = c.ps("INSERT OR IGNORE INTO apis(id, host, path_key, first_seen, last_seen, send_count, method)"
                    + " VALUES (?, ?, ?, ?, ?, 0, ?)");
            p.setInt(1, id); p.setString(2, host); p.setString(3, pathKey); p.setLong(4, ts); p.setLong(5, ts);
            p.setString(6, method);
            p.executeUpdate();
        };
    }

    public static Cmd insertStatusKey(int id, String key) {
        return c -> {
            PreparedStatement p = c.ps("INSERT OR IGNORE INTO status_keys(id, key, state) VALUES (?, ?, 0)");
            p.setInt(1, id); p.setString(2, key);
            p.executeUpdate();
        };
    }

    public static Cmd raiseStatus(int skId, int state) {
        return c -> {
            PreparedStatement p = c.ps("UPDATE status_keys SET state = max(state, ?) WHERE id = ?");
            p.setInt(1, state); p.setInt(2, skId);
            p.executeUpdate();
        };
    }

    public static Cmd insertOriginal(int id, int apiId, long ts, int source, String method, String firstLine,
                                     byte[] features, String host, int port, boolean secure, byte[] requestZ,
                                     long bodyHash, int bodySize, boolean truncated) {
        return insertOriginal(id, apiId, ts, source, method, firstLine, features, host, port, secure, requestZ,
                bodyHash, bodySize, truncated, 0);
    }

    /** seq = number of the original in its API's log (0 = unknown, stored as NULL). */
    public static Cmd insertOriginal(int id, int apiId, long ts, int source, String method, String firstLine,
                                     byte[] features, String host, int port, boolean secure, byte[] requestZ,
                                     long bodyHash, int bodySize, boolean truncated, int seq) {
        return new Cmd() {
            @Override public void apply(Ctx c) throws SQLException {
                PreparedStatement p = c.ps("INSERT OR IGNORE INTO originals(id, api_id, ts, source, method, first_line,"
                        + " features, host, port, secure, request_z, body_hash, body_size, truncated, seq)"
                        + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                p.setInt(1, id); p.setInt(2, apiId); p.setLong(3, ts); p.setInt(4, source); p.setString(5, method);
                p.setString(6, firstLine); p.setBytes(7, features); p.setString(8, host); p.setInt(9, port);
                p.setInt(10, secure ? 1 : 0); p.setBytes(11, requestZ); p.setLong(12, bodyHash); p.setInt(13, bodySize);
                p.setInt(14, truncated ? 1 : 0);
                if (seq > 0) p.setInt(15, seq); else p.setNull(15, java.sql.Types.INTEGER);
                p.executeUpdate();
            }
            @Override public int bytes() { return requestZ == null ? 0 : requestZ.length; }
        };
    }

    /**
     * Readable request / response text of an original (AI context). null = leave that column unchanged, so the request
     * (stored right away) and a response found later can be written separately.
     */
    public static Cmd setOriginalText(int id, String requestText, String responseText) {
        return new Cmd() {
            @Override public void apply(Ctx c) throws SQLException {
                PreparedStatement p = c.ps("UPDATE originals SET request_text = COALESCE(?, request_text),"
                        + " response_text = COALESCE(?, response_text) WHERE id = ?");
                p.setString(1, requestText); p.setString(2, responseText); p.setInt(3, id);
                p.executeUpdate();
            }
            @Override public boolean droppable() { return true; }
            @Override public int bytes() {
                return 2 * ((requestText == null ? 0 : requestText.length()) + (responseText == null ? 0 : responseText.length()));
            }
        };
    }

    public static Cmd insertSend(Rows.SendRow s, String searchText) {
        return insertSend(s, searchText, 0);
    }

    private static final String INSERT_SEND = "INSERT OR IGNORE INTO sends(id, api_id, original_id, ts, status, length, ms,"
            + " flags, source, loc_mask, first_line, search_text, changes, status_mask, seq)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static boolean doInsertSend(Ctx c, Rows.SendRow s, String searchText, int statusMask) throws SQLException {
        PreparedStatement p = c.ps(INSERT_SEND);
        p.setLong(1, s.id()); p.setInt(2, s.apiId()); p.setInt(3, s.originalId()); p.setLong(4, s.ts());
        p.setInt(5, s.status()); p.setInt(6, s.length()); p.setInt(7, s.ms()); p.setInt(8, s.flags());
        p.setString(9, s.source()); p.setInt(10, s.locMask()); p.setString(11, s.firstLine());
        p.setString(12, searchText); p.setString(13, s.changes()); p.setInt(14, statusMask);
        if (s.seq() > 0) p.setInt(15, s.seq()); else p.setNull(15, java.sql.Types.INTEGER);
        if (p.executeUpdate() == 0) return false;
        c.countSend(s.apiId(), s.ts());
        return true;
    }

    /** statusMask: status classes (bits of {@link Rows#statusClassBit}) of an Intruder row; 0 for normal sends. */
    public static Cmd insertSend(Rows.SendRow s, String searchText, int statusMask) {
        return new Cmd() {
            @Override public void apply(Ctx c) throws SQLException { doInsertSend(c, s, searchText, statusMask); }
            @Override public int bytes() {
                return 2 * (s.changes().length() + searchText.length() + s.firstLine().length());
            }
        };
    }

    /**
     * Updates the summary row of a running Intruder attack (FTS updated via trigger). Upsert: if the first insert was
     * dropped on a full queue, this update creates the row (the send count only grows on an actual insert).
     */
    public static Cmd updateSend(Rows.SendRow s, String searchText, int statusMask) {
        return new Cmd() {
            @Override public void apply(Ctx c) throws SQLException {
                PreparedStatement p = c.ps("UPDATE sends SET ts = ?, status = ?, length = ?, ms = ?, flags = ?, loc_mask = ?,"
                        + " first_line = ?, search_text = ?, changes = ?, status_mask = ? WHERE id = ?");
                p.setLong(1, s.ts()); p.setInt(2, s.status()); p.setInt(3, s.length()); p.setInt(4, s.ms());
                p.setInt(5, s.flags()); p.setInt(6, s.locMask()); p.setString(7, s.firstLine()); p.setString(8, searchText);
                p.setString(9, s.changes()); p.setInt(10, statusMask); p.setLong(11, s.id());
                if (p.executeUpdate() == 0) doInsertSend(c, s, searchText, statusMask);
            }
            @Override public int bytes() {
                return 2 * (s.changes().length() + searchText.length() + s.firstLine().length());
            }
        };
    }

    public static Cmd insertBlob(long owner, byte[] requestZ) {
        return new Cmd() {
            @Override public void apply(Ctx c) throws SQLException {
                PreparedStatement p = c.ps("INSERT OR REPLACE INTO blobs(owner, request_z) VALUES (?, ?)");
                p.setLong(1, owner); p.setBytes(2, requestZ);
                p.executeUpdate();
            }
            @Override public boolean droppable() { return true; }
            @Override public int bytes() { return requestZ == null ? 0 : requestZ.length; }
        };
    }

    public static Cmd insertProxyIndex(int[] ids, int[] sks, int n) {
        return new Cmd() {
            @Override public void apply(Ctx c) throws SQLException {
                PreparedStatement p = c.ps("INSERT OR REPLACE INTO proxy_index(id, sk) VALUES (?, ?)");
                for (int i = 0; i < n; i++) { p.setInt(1, ids[i]); p.setInt(2, sks[i]); p.addBatch(); }
                p.executeBatch();
            }
        };
    }

    public static Cmd setMeta(String k, String v) {
        return c -> {
            PreparedStatement p = c.ps("INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v");
            p.setString(1, k); p.setString(2, v);
            p.executeUpdate();
        };
    }

    public static Cmd putLabel(String hmac, String label) {
        return c -> {
            PreparedStatement p = c.ps("INSERT INTO labels(hmac, label) VALUES (?, ?) ON CONFLICT(hmac) DO UPDATE SET label=excluded.label");
            p.setString(1, hmac); p.setString(2, label);
            p.executeUpdate();
        };
    }

    public static Cmd deleteLabel(String hmac) {
        return c -> {
            PreparedStatement p = c.ps("DELETE FROM labels WHERE hmac = ?");
            p.setString(1, hmac);
            p.executeUpdate();
        };
    }

    /**
     * Merges FTS segments incrementally (up to ~100 pages per call) instead of a full 'optimize': bounded run time,
     * does not block the writer thread for long.
     */
    public static Cmd mergeFts() {
        return new Cmd() {
            @Override public void apply(Ctx c) throws SQLException {
                try (Statement s = c.conn.createStatement()) {
                    s.execute("INSERT INTO sends_fts(sends_fts, rank) VALUES ('merge', 100)");
                }
            }
            @Override public boolean droppable() { return true; }
        };
    }
}
