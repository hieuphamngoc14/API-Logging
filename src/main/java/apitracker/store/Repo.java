package apitracker.store;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read queries on a dedicated connection (used only from the tracker-search thread). Never runs on the EDT.
 *
 * <p>Searching one API's log picks a plan by size: APIs with few sends (most) scan that API's rows directly via the
 * {@code (api_id, id)} index with LIKE, without touching FTS; APIs with very many sends use FTS5 trigram, then filter by API.
 * Prepared statements are kept (cached) instead of being re-prepared on every keystroke.
 */
public final class Repo implements AutoCloseable {
    public static final int ST_2XX = 1, ST_3XX = 2, ST_4XX = 4, ST_5XX = 8, ST_NONE = 16;
    public static final int SRC_REPEATER = 1, SRC_AI = 2, SRC_INTRUDER = 4;
    /** Below this, a LIKE scan over the API's rows beats going through FTS (FTS returns matches of every API). */
    static final int LIKE_SCAN_MAX = 5_000;
    private static final int STMT_CACHE = 48;

    /** locMask = 0: all positions. statusMask = 0: all statuses. sourceMask = 0: all sources (SRC_*). */
    public record Filter(int locMask, int statusMask, int sourceMask) {
        public static final Filter ALL = new Filter(0, 0, 0);
    }

    private static final String COLS_BASE = "s.id, s.api_id, s.original_id, s.ts, s.status, s.length, s.ms, s.flags, s.source,"
            + " s.loc_mask, s.first_line, s.changes";
    /** Send columns; the log number (seq) is 0 on an old schema opened read-only. */
    private final String COLS;
    private final String origSeq;

    private final Connection c;
    private volatile PreparedStatement current;
    private final Map<String, PreparedStatement> stmts = new LinkedHashMap<>(64, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, PreparedStatement> e) {
            if (size() <= STMT_CACHE) return false;
            try { e.getValue().close(); } catch (SQLException ignored) { }
            return true;
        }
    };

    public Repo(Connection c) {
        this.c = c;
        boolean sendSeq = hasColumn(c, "sends", "seq"), origSeqCol = hasColumn(c, "originals", "seq");
        COLS = COLS_BASE + (sendSeq ? ", coalesce(s.seq, 0)" : ", 0");
        origSeq = origSeqCol ? "coalesce(o.seq, 0)" : "0";
    }

    private static boolean hasColumn(Connection c, String table, String column) {
        try (java.sql.Statement s = c.createStatement(); ResultSet r = s.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (r.next()) if (column.equalsIgnoreCase(r.getString("name"))) return true;
        } catch (SQLException ignored) {
            // treat as missing
        }
        return false;
    }

    /** Statement from the cache (not closed after use). */
    private PreparedStatement prep(String sql) throws SQLException {
        PreparedStatement p = stmts.get(sql);
        if (p == null) {
            p = c.prepareStatement(sql);
            stmts.put(sql, p);
        } else {
            p.clearParameters();
        }
        current = p;
        return p;
    }

    public synchronized List<Rows.SendRow> page(int apiId, long beforeId, int limit, Filter f) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT ").append(COLS).append(" FROM sends s WHERE s.api_id = ? AND s.id < ?");
        List<Object> args = new ArrayList<>(List.of(apiId, beforeId));
        appendFilter(sql, args, f);
        sql.append(" ORDER BY s.id DESC LIMIT ?");
        args.add(limit);
        return query(sql.toString(), args);
    }

    /** Searches one API's log (send count unknown: treated as a large API). */
    public synchronized List<Rows.SendRow> search(int apiId, String text, Collection<String> alternatives, Filter f,
                                                  long beforeId, int limit) throws SQLException {
        return search(apiId, text, alternatives, f, beforeId, limit, Integer.MAX_VALUE);
    }

    /**
     * Searches one API's log. apiSendCount picks the plan: small → LIKE over the API's rows; large → FTS.
     * Terms shorter than 3 characters always use LIKE (trigram needs at least 3 characters).
     */
    public synchronized List<Rows.SendRow> search(int apiId, String text, Collection<String> alternatives, Filter f,
                                                  long beforeId, int limit, int apiSendCount) throws SQLException {
        String q = text.trim();
        if (q.isEmpty()) return page(apiId, beforeId, limit, f);
        StringBuilder sql = new StringBuilder("SELECT ").append(COLS);
        List<Object> args = new ArrayList<>();
        boolean shortTerm = q.codePointCount(0, q.length()) < 3;
        if (shortTerm || apiSendCount <= LIKE_SCAN_MAX) {
            // search_text is stored lowercase (Unicode): lowercase the term the same way so LIKE matches accented letters too
            sql.append(" FROM sends s WHERE s.api_id = ? AND s.id < ? AND (s.search_text LIKE ? ESCAPE '\\'");
            args.add(apiId); args.add(beforeId); args.add("%" + likeEscape(q.toLowerCase(java.util.Locale.ROOT)) + "%");
            if (alternatives != null) for (String alt : alternatives) {
                if (alt == null || alt.isEmpty()) continue;
                sql.append(" OR s.search_text LIKE ? ESCAPE '\\'");
                args.add("%" + likeEscape(alt.toLowerCase(java.util.Locale.ROOT)) + "%");
            }
            sql.append(')');
        } else {
            sql.append(" FROM sends_fts JOIN sends s ON s.id = sends_fts.rowid WHERE sends_fts MATCH ?"
                    + " AND s.api_id = ? AND s.id < ?");
            args.add(ftsExpr(q, alternatives)); args.add(apiId); args.add(beforeId);
        }
        appendFilter(sql, args, f);
        sql.append(" ORDER BY s.id DESC LIMIT ?");
        args.add(limit);
        return query(sql.toString(), args);
    }

    /** Searches the log of all APIs: apiId → matching send count. Terms under 3 characters return empty. */
    public synchronized Map<Integer, Integer> searchAll(String text, Collection<String> alternatives) throws SQLException {
        Map<Integer, Integer> out = new HashMap<>();
        String q = text.trim();
        if (q.codePointCount(0, q.length()) < 3) return out;
        PreparedStatement p = prep("SELECT s.api_id, count(*) FROM sends_fts JOIN sends s"
                + " ON s.id = sends_fts.rowid WHERE sends_fts MATCH ? GROUP BY s.api_id LIMIT 5000");
        p.setString(1, ftsExpr(q, alternatives));
        try (ResultSet r = p.executeQuery()) {
            while (r.next()) out.put(r.getInt(1), r.getInt(2));
        }
        return out;
    }

    public synchronized List<Rows.OriginalRow> originals(int apiId) throws SQLException {
        List<Rows.OriginalRow> out = new ArrayList<>();
        PreparedStatement p = prep("SELECT o.id, o.api_id, o.ts, o.source, o.method, o.first_line, " + origSeq
                + " FROM originals o WHERE o.api_id = ? ORDER BY o.id");
        p.setInt(1, apiId);
        try (ResultSet r = p.executeQuery()) {
            while (r.next()) out.add(new Rows.OriginalRow(r.getInt(1), r.getInt(2), r.getLong(3), r.getInt(4),
                    r.getString(5), r.getString(6), 0, 0, r.getInt(7)));
        }
        return out;
    }

    public record RawReq(byte[] requestZ, String host, int port, boolean secure) {}

    public synchronized RawReq originalRaw(int originalId) throws SQLException {
        PreparedStatement p = prep("SELECT request_z, host, port, secure FROM originals WHERE id = ?");
        p.setInt(1, originalId);
        try (ResultSet r = p.executeQuery()) {
            return r.next() ? new RawReq(r.getBytes(1), r.getString(2), r.getInt(3), r.getInt(4) != 0) : null;
        }
    }

    /** Raw request (compressed) of a send, exactly as stored in the DB. */
    public synchronized byte[] blob(long owner) throws SQLException {
        PreparedStatement p = prep("SELECT request_z FROM blobs WHERE owner = ?");
        p.setLong(1, owner);
        try (ResultSet r = p.executeQuery()) { return r.next() ? r.getBytes(1) : null; }
    }

    /** Decompressed raw request of a send (inflated with its original request as dictionary). null if absent. */
    public synchronized byte[] sendRaw(long sendId) throws SQLException {
        PreparedStatement p = prep("SELECT b.request_z, o.request_z FROM blobs b JOIN sends s ON s.id = b.owner"
                + " LEFT JOIN originals o ON o.id = s.original_id WHERE b.owner = ?");
        p.setLong(1, sendId);
        byte[] blob, orig;
        try (ResultSet r = p.executeQuery()) {
            if (!r.next()) return null;
            blob = r.getBytes(1);
            orig = r.getBytes(2);
        }
        byte[] dict = orig == null ? null : Zip.dictOf(Zip.inflate(orig));
        return Zip.inflate(blob, dict);
    }

    /**
     * Readable {request, response} text of an original (AI context); an element is null when not stored. null if the
     * original does not exist or the DB predates these columns.
     */
    public synchronized String[] originalText(int originalId) throws SQLException {
        PreparedStatement p;
        try {
            p = prep("SELECT request_text, response_text FROM originals WHERE id = ?");
        } catch (SQLException e) {
            return null;                                                      // old schema opened read-only
        }
        p.setInt(1, originalId);
        try (ResultSet r = p.executeQuery()) {
            return r.next() ? new String[]{r.getString(1), r.getString(2)} : null;
        }
    }

    // ---------- helpers ----------

    static String ftsPhrase(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }

    static String ftsExpr(String q, Collection<String> alternatives) {
        StringBuilder b = new StringBuilder(ftsPhrase(q));
        if (alternatives != null) for (String alt : alternatives) {
            if (alt != null && alt.length() >= 3) b.append(" OR ").append(ftsPhrase(alt));
        }
        return b.toString();
    }

    static String likeEscape(String s) {
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private static void appendFilter(StringBuilder sql, List<Object> args, Filter f) {
        if (f == null) return;
        if (f.locMask() != 0) { sql.append(" AND (s.loc_mask & ?) != 0"); args.add(f.locMask()); }
        if (f.statusMask() != 0) {
            // Intruder rows have many statuses: status_mask holds every status class seen (bits match ST_*)
            List<String> ors = new ArrayList<>();
            if ((f.statusMask() & ST_2XX) != 0) ors.add("s.status BETWEEN 200 AND 299");
            if ((f.statusMask() & ST_3XX) != 0) ors.add("s.status BETWEEN 300 AND 399");
            if ((f.statusMask() & ST_4XX) != 0) ors.add("s.status BETWEEN 400 AND 499");
            if ((f.statusMask() & ST_5XX) != 0) ors.add("s.status BETWEEN 500 AND 599");
            if ((f.statusMask() & ST_NONE) != 0) ors.add("(s.status IS NULL OR s.status <= 0)");
            ors.add("(s.status_mask & " + (f.statusMask() & 31) + ") != 0");
            sql.append(" AND (").append(String.join(" OR ", ors)).append(')');
        }
        int sm = f.sourceMask();
        if (sm != 0 && sm != (SRC_REPEATER | SRC_AI | SRC_INTRUDER)) {
            List<String> ors = new ArrayList<>();
            if ((sm & SRC_REPEATER) != 0) ors.add("s.source = 'repeater'");
            if ((sm & SRC_AI) != 0) ors.add("s.source LIKE 'ai%'");
            if ((sm & SRC_INTRUDER) != 0) ors.add("s.source = 'intruder'");
            sql.append(" AND (").append(String.join(" OR ", ors)).append(')');
        }
    }

    private List<Rows.SendRow> query(String sql, List<Object> args) throws SQLException {
        List<Rows.SendRow> out = new ArrayList<>();
        PreparedStatement p = prep(sql);
        for (int i = 0; i < args.size(); i++) p.setObject(i + 1, args.get(i));
        try (ResultSet r = p.executeQuery()) {
            while (r.next()) {
                out.add(new Rows.SendRow(r.getLong(1), r.getInt(2), r.getInt(3), r.getLong(4), r.getInt(5),
                        r.getInt(6), r.getInt(7), r.getInt(8), r.getString(9), r.getInt(10), r.getString(11),
                        r.getString(12), r.getInt(13)));
            }
        }
        return out;
    }

    /** Cancels the running query (sqlite3_interrupt), then closes, so unload does not wait for a long query. */
    @Override
    public void close() {
        PreparedStatement p = current;
        if (p != null) {
            try { p.cancel(); } catch (SQLException | RuntimeException ignored) { }
        }
        synchronized (this) {
            for (PreparedStatement s : stmts.values()) { try { s.close(); } catch (SQLException ignored) { } }
            stmts.clear();
            try { c.close(); } catch (SQLException ignored) { }
        }
    }
}
