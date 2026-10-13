package apitracker.store;

import apitracker.util.Log;
import org.sqlite.SQLiteDataSource;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Opens / creates the SQLite DB of a Burp project: picks the file by project name, matches by project id, owner-only
 * permissions, FileLock against two Burps writing at once, schema, PRAGMAs and state loading at startup.
 */
public final class Db implements AutoCloseable {
    public static final int SCHEMA_VERSION = 2;
    private static final Set<String> WINDOWS_RESERVED = Set.of("con", "prn", "aux", "nul",
            "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
            "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9");

    public final Path file;
    public final boolean temp;
    public final boolean readOnly;
    private final SQLiteDataSource ds;
    private final Connection writeConn;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private byte[] hmacKey;          // read once at open; writeConn is never touched from another thread afterwards

    private Db(Path file, boolean temp, SQLiteDataSource ds, Connection writeConn, FileChannel ch, FileLock lock) {
        this.file = file;
        this.temp = temp;
        this.ds = ds;
        this.writeConn = writeConn;
        this.lockChannel = ch;
        this.lock = lock;
        this.readOnly = lock == null;
    }

    // ---------- file selection ----------

    public static String sanitize(String name) {
        String s = name == null ? "" : name.trim();
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length() && b.length() < 80; i++) {
            char c = s.charAt(i);
            b.append((c < 128 && (Character.isLetterOrDigit(c) || c == '.' || c == '_' || c == '-')) ? c : '_');
        }
        String r = b.toString();
        while (r.startsWith(".")) r = "_" + r.substring(1);
        if (r.isEmpty()) r = "project";
        String base = r.contains(".") ? r.substring(0, r.indexOf('.')) : r;
        if (WINDOWS_RESERVED.contains(base.toLowerCase(Locale.ROOT))) r = "_" + r;
        return r;
    }

    /** Creates the storage directory if missing, with owner-only permissions (only when the extension creates it). */
    public static void ensureDir(Path dir) throws IOException {
        if (Files.isDirectory(dir)) return;
        Files.createDirectories(dir);
        restrictToOwner(dir, true);
    }

    public static Path chooseFile(Path dir, String projectName, String projectId, String rememberedFile) throws IOException {
        ensureDir(dir);
        if (rememberedFile != null && !rememberedFile.isBlank()) {
            Path fn = Path.of(rememberedFile).getFileName();
            if (fn != null) {
                Path p = dir.resolve(fn.toString());
                if (Files.isRegularFile(p) && projectId.equals(readProjectId(p))) return p;
            }
        }
        String base = sanitize(projectName);
        for (int n = 1; n < 1000; n++) {
            Path p = dir.resolve(n == 1 ? base + ".db" : base + "_" + n + ".db");
            if (!Files.exists(p)) return p;
            if (Files.size(p) == 0) return p;
            String pid = readProjectId(p);
            if (projectId.equals(pid)) return p;
        }
        throw new IOException("Could not choose a DB file name for project " + projectName);
    }

    public static Path tempFile(Path dir) throws IOException {
        ensureDir(dir);
        return dir.resolve("_temp-" + System.currentTimeMillis() + ".db");
    }

    static String readProjectId(Path p) {
        SQLiteDataSource d = new SQLiteDataSource();
        d.setUrl("jdbc:sqlite:" + p.toAbsolutePath());
        d.setReadOnly(true);
        try (Connection c = d.getConnection(); Statement s = c.createStatement();
             ResultSet r = s.executeQuery("SELECT v FROM meta WHERE k='project_id'")) {
            return r.next() ? r.getString(1) : null;
        } catch (SQLException e) {
            return null;
        }
    }

    // ---------- open ----------

    public static Db open(Path file, String projectId, boolean temp) throws IOException, SQLException {
        boolean created = !Files.exists(file) || Files.size(file) == 0;
        if (!Files.exists(file)) createOwnerOnly(file);

        Path lockFile = file.resolveSibling(file.getFileName() + ".lock");
        FileChannel ch = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock lock = null;
        for (int attempt = 0; attempt < 5 && lock == null; attempt++) {
            try {
                lock = ch.tryLock();
                if (lock == null) break;                       // another process holds the lock
            } catch (OverlappingFileLockException e) {
                // extension reloaded in the same JVM before the old lock was released: wait and retry
                try { Thread.sleep(200); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
            }
        }
        if (lock == null) {
            Log.warn("DB is open in another Burp, running read-only: " + file);
            try { ch.close(); } catch (IOException ignored) { }
            ch = null;
        }

        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + file.toAbsolutePath());
        if (lock == null) ds.setReadOnly(true);
        Connection w = ds.getConnection();
        try (Statement s = w.createStatement()) {
            s.execute("PRAGMA busy_timeout=2000");
            if (lock != null) {
                s.execute("PRAGMA journal_mode=WAL");
                s.execute("PRAGMA synchronous=NORMAL");
                s.execute("PRAGMA journal_size_limit=67108864");
                s.execute("PRAGMA temp_store=MEMORY");
                s.execute("PRAGMA cache_size=-16000");
            }
        }
        Db db = new Db(file, temp, ds, w, ch, lock);
        if (lock != null) {
            db.createSchema();
            if (created || db.meta("project_id") == null) {
                db.putMeta("project_id", projectId);
                db.putMeta("schema_version", Integer.toString(SCHEMA_VERSION));
            }
            if (db.meta("hmac_key") == null) {
                byte[] k = new byte[32];
                new SecureRandom().nextBytes(k);
                db.putMeta("hmac_key", HexFormat.of().formatHex(k));
            }
            db.putMeta("schema_version", Integer.toString(SCHEMA_VERSION));
        }
        String hex = db.meta("hmac_key");
        if (hex == null) {                       // read-only mode on a DB without a key: temporary key
            byte[] k = new byte[32];
            new SecureRandom().nextBytes(k);
            db.hmacKey = k;
        } else {
            db.hmacKey = HexFormat.of().parseHex(hex);
        }
        warnIfNetworkDrive(file);
        return db;
    }

    private boolean hasColumn(String table, String column) throws SQLException {
        try (Statement s = writeConn.createStatement(); ResultSet r = s.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (r.next()) if (column.equalsIgnoreCase(r.getString("name"))) return true;
        }
        return false;
    }

    /**
     * Numbers the log of every API (#1, #2…: originals and sends together, by time) for rows written before the seq
     * column existed. Runs only when some row has no number; then renumbers everything so numbers never collide.
     */
    public void backfillSeq() throws SQLException {
        try (Statement s = writeConn.createStatement()) {
            try (ResultSet r = s.executeQuery("SELECT EXISTS(SELECT 1 FROM sends WHERE seq IS NULL)"
                    + " OR EXISTS(SELECT 1 FROM originals WHERE seq IS NULL)")) {
                if (!r.next() || r.getInt(1) == 0) return;
            }
            boolean auto = writeConn.getAutoCommit();
            writeConn.setAutoCommit(false);
            try {
                s.execute("DROP TABLE IF EXISTS temp.seq_fill");
                s.execute("CREATE TEMP TABLE seq_fill AS SELECT k, id, ROW_NUMBER() OVER (PARTITION BY api_id ORDER BY ts, k, id) AS n"
                        + " FROM (SELECT 0 AS k, id, api_id, ts FROM originals UNION ALL SELECT 1 AS k, id, api_id, ts FROM sends)");
                s.execute("CREATE INDEX temp.seq_fill_k ON seq_fill(k, id)");
                s.execute("UPDATE originals SET seq = (SELECT n FROM seq_fill f WHERE f.k = 0 AND f.id = originals.id)");
                s.execute("UPDATE sends SET seq = (SELECT n FROM seq_fill f WHERE f.k = 1 AND f.id = sends.id)");
                s.execute("DROP TABLE temp.seq_fill");
                writeConn.commit();
            } catch (SQLException e) {
                writeConn.rollback();
                throw e;
            } finally {
                writeConn.setAutoCommit(auto);
            }
        }
    }

    /** Adds columns for DBs created by older versions (add only, data unchanged). */
    private void addColumnIfMissing(String table, String column, String type) throws SQLException {
        if (hasColumn(table, column)) return;
        try (Statement s = writeConn.createStatement()) {
            s.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + type);
        }
    }

    private void createSchema() throws SQLException {
        String[] ddl = {
                "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID",
                "CREATE TABLE IF NOT EXISTS apis(id INTEGER PRIMARY KEY, host TEXT NOT NULL, path_key TEXT NOT NULL,"
                        + " first_seen INTEGER, last_seen INTEGER, send_count INTEGER NOT NULL DEFAULT 0, method TEXT,"
                        + " UNIQUE(host, path_key))",
                "CREATE TABLE IF NOT EXISTS status_keys(id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE,"
                        + " state INTEGER NOT NULL DEFAULT 0)",
                "CREATE TABLE IF NOT EXISTS originals(id INTEGER PRIMARY KEY, api_id INTEGER NOT NULL, ts INTEGER NOT NULL,"
                        + " source INTEGER NOT NULL, method TEXT NOT NULL, first_line TEXT NOT NULL, features BLOB NOT NULL,"
                        + " host TEXT, port INTEGER, secure INTEGER, request_z BLOB, body_hash INTEGER, body_size INTEGER,"
                        + " truncated INTEGER NOT NULL DEFAULT 0)",
                "CREATE INDEX IF NOT EXISTS originals_by_api ON originals(api_id)",
                "CREATE TABLE IF NOT EXISTS sends(id INTEGER PRIMARY KEY, api_id INTEGER NOT NULL, original_id INTEGER,"
                        + " ts INTEGER NOT NULL, status INTEGER, length INTEGER, ms INTEGER, flags INTEGER NOT NULL DEFAULT 0,"
                        + " source TEXT NOT NULL DEFAULT 'repeater', loc_mask INTEGER NOT NULL DEFAULT 0,"
                        + " first_line TEXT NOT NULL, search_text TEXT NOT NULL, changes TEXT NOT NULL,"
                        + " status_mask INTEGER NOT NULL DEFAULT 0)",
                "CREATE INDEX IF NOT EXISTS sends_by_api ON sends(api_id, id DESC)",
                "CREATE TABLE IF NOT EXISTS blobs(owner INTEGER PRIMARY KEY, request_z BLOB)",
                "CREATE TABLE IF NOT EXISTS labels(hmac TEXT PRIMARY KEY, label TEXT NOT NULL) WITHOUT ROWID",
                "CREATE TABLE IF NOT EXISTS proxy_index(id INTEGER PRIMARY KEY, sk INTEGER NOT NULL)",
                "CREATE VIRTUAL TABLE IF NOT EXISTS sends_fts USING fts5(search_text, content='sends',"
                        + " content_rowid='id', tokenize='trigram')",
                "CREATE TRIGGER IF NOT EXISTS sends_ai AFTER INSERT ON sends BEGIN"
                        + " INSERT INTO sends_fts(rowid, search_text) VALUES (new.id, new.search_text); END",
                "CREATE TRIGGER IF NOT EXISTS sends_ad AFTER DELETE ON sends BEGIN"
                        + " INSERT INTO sends_fts(sends_fts, rowid, search_text) VALUES ('delete', old.id, old.search_text); END",
                "CREATE TRIGGER IF NOT EXISTS sends_au AFTER UPDATE OF search_text ON sends BEGIN"
                        + " INSERT INTO sends_fts(sends_fts, rowid, search_text) VALUES ('delete', old.id, old.search_text);"
                        + " INSERT INTO sends_fts(rowid, search_text) VALUES (new.id, new.search_text); END",
        };
        try (Statement s = writeConn.createStatement()) {
            for (String d : ddl) s.execute(d);
        }
        addColumnIfMissing("apis", "method", "TEXT");
        addColumnIfMissing("originals", "body_hash", "INTEGER");
        addColumnIfMissing("originals", "body_size", "INTEGER");
        addColumnIfMissing("originals", "truncated", "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing("sends", "status_mask", "INTEGER NOT NULL DEFAULT 0");
        addColumnIfMissing("originals", "seq", "INTEGER");           // number within the API's log (#1, #2…)
        addColumnIfMissing("sends", "seq", "INTEGER");
        backfillSeq();
        addColumnIfMissing("originals", "request_text", "TEXT");     // readable request + response for AI context
        addColumnIfMissing("originals", "response_text", "TEXT");
        // Intruder attacks still "running" from the previous session (Burp killed abruptly): no longer running
        try (Statement s = writeConn.createStatement()) {
            s.execute("UPDATE sends SET flags = flags & ~" + Rows.FLAG_RUNNING + " WHERE (flags & " + Rows.FLAG_RUNNING + ") != 0");
        }
    }

    public String meta(String k) throws SQLException {
        try (PreparedStatement p = writeConn.prepareStatement("SELECT v FROM meta WHERE k=?")) {
            p.setString(1, k);
            try (ResultSet r = p.executeQuery()) { return r.next() ? r.getString(1) : null; }
        }
    }

    private void putMeta(String k, String v) throws SQLException {
        try (PreparedStatement p = writeConn.prepareStatement(
                "INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v")) {
            p.setString(1, k);
            p.setString(2, v);
            p.executeUpdate();
        }
    }

    /** The DB's HMAC key (read at open, not queried again). */
    public byte[] hmacKey() {
        return hmacKey.clone();
    }

    public Connection writeConnection() { return writeConn; }

    /**
     * Read-only connection (WAL allows reads in parallel with the writer thread). mmap cuts syscalls when reading pages,
     * 8 MB cache for hot index pages.
     */
    public Connection newReadConnection() throws SQLException {
        Connection c = ds.getConnection();
        try (Statement s = c.createStatement()) {
            s.execute("PRAGMA busy_timeout=2000");
            s.execute("PRAGMA query_only=1");
            s.execute("PRAGMA cache_size=-8000");
            s.execute("PRAGMA temp_store=MEMORY");
            s.execute("PRAGMA mmap_size=134217728");
        }
        return c;
    }

    /** Loads an original request (compressed) by id on demand instead of loading all at project open. One thread only. */
    public static final class OriginalLoader implements AutoCloseable {
        private final Connection c;
        private PreparedStatement ps;

        OriginalLoader(Connection c) { this.c = c; }

        public synchronized byte[] load(int originalId) {
            try {
                if (ps == null) ps = c.prepareStatement("SELECT request_z FROM originals WHERE id = ?");
                ps.setInt(1, originalId);
                try (ResultSet r = ps.executeQuery()) { return r.next() ? r.getBytes(1) : null; }
            } catch (SQLException e) {
                Log.rateLimited(e);
                return null;
            }
        }

        @Override public synchronized void close() {
            try { if (ps != null) ps.close(); } catch (SQLException ignored) { }
            try { c.close(); } catch (SQLException ignored) { }
        }
    }

    public OriginalLoader newOriginalLoader() throws SQLException {
        return new OriginalLoader(newReadConnection());
    }

    // ---------- state loading ----------

    public record ApiRec(int id, String host, String pathKey, long firstSeen, long lastSeen, int sendCount, String method) {}

    public record OriginalRec(int id, int apiId, long ts, int source, String method, String firstLine, byte[] features,
                              String host, int port, boolean secure, byte[] requestZ, long bodyHash, int bodySize,
                              boolean truncated) {}

    public static final class State {
        public final List<ApiRec> apis = new ArrayList<>();
        public final List<OriginalRec> originals = new ArrayList<>();
        public final Map<Integer, String> statusKeys = new HashMap<>();
        public final Map<Integer, Integer> statusState = new HashMap<>();
        public final Map<String, String> labels = new HashMap<>();
        public int[] proxyIds = new int[0];
        public int[] proxySk = new int[0];
        public long maxSendId;
        public long proxyLastId;
        /** Highest log number (#) per API id. */
        public final Map<Integer, Integer> maxSeq = new HashMap<>();
    }

    public State load() throws SQLException {
        State st = new State();
        // read-only mode does not upgrade the schema: DBs from older versions may lack new columns
        String method = hasColumn("apis", "method") ? "method" : "NULL";
        boolean v2 = hasColumn("originals", "truncated");
        String origExtra = v2 ? "coalesce(body_hash, 0), coalesce(body_size, 0), coalesce(truncated, 0)" : "0, 0, 0";
        try (Statement s = writeConn.createStatement()) {
            try (ResultSet r = s.executeQuery("SELECT id, host, path_key, first_seen, last_seen, send_count, " + method + " FROM apis")) {
                while (r.next()) st.apis.add(new ApiRec(r.getInt(1), r.getString(2), r.getString(3), r.getLong(4), r.getLong(5),
                        r.getInt(6), r.getString(7)));
            }
            // request_z not loaded: original requests are read on demand (OriginalLoader), fast project open, low RAM
            try (ResultSet r = s.executeQuery("SELECT id, api_id, ts, source, method, first_line, features, host, port,"
                    + " secure, " + origExtra + " FROM originals ORDER BY id")) {
                while (r.next()) st.originals.add(new OriginalRec(r.getInt(1), r.getInt(2), r.getLong(3), r.getInt(4),
                        r.getString(5), r.getString(6), r.getBytes(7), r.getString(8), r.getInt(9), r.getInt(10) != 0,
                        null, r.getLong(11), r.getInt(12), r.getInt(13) != 0));
            }
            try (ResultSet r = s.executeQuery("SELECT id, key, state FROM status_keys")) {
                while (r.next()) {
                    st.statusKeys.put(r.getInt(1), r.getString(2));
                    if (r.getInt(3) > 0) st.statusState.put(r.getInt(1), r.getInt(3));
                }
            }
            try (ResultSet r = s.executeQuery("SELECT hmac, label FROM labels")) {
                while (r.next()) st.labels.put(r.getString(1), r.getString(2));
            }
            try (ResultSet r = s.executeQuery("SELECT count(*) FROM proxy_index")) {
                int n = r.next() ? r.getInt(1) : 0;
                st.proxyIds = new int[n];
                st.proxySk = new int[n];
            }
            try (ResultSet r = s.executeQuery("SELECT id, sk FROM proxy_index ORDER BY id")) {
                int i = 0;
                while (r.next() && i < st.proxyIds.length) { st.proxyIds[i] = r.getInt(1); st.proxySk[i] = r.getInt(2); i++; }
            }
            try (ResultSet r = s.executeQuery("SELECT coalesce(max(id), 0) FROM sends")) {
                st.maxSendId = r.next() ? r.getLong(1) : 0;
            }
            // old schema opened read-only: no seq column, the entry count stands in for the highest number
            String seqAgg = hasColumn("sends", "seq") && hasColumn("originals", "seq") ? "max(seq)" : "count(*)";
            String seqCol = seqAgg.equals("max(seq)") ? "seq" : "1";
            try (ResultSet r = s.executeQuery("SELECT api_id, " + seqAgg + " FROM (SELECT api_id, " + seqCol + " AS seq FROM originals"
                    + " UNION ALL SELECT api_id, " + seqCol + " AS seq FROM sends) GROUP BY api_id")) {
                while (r.next()) st.maxSeq.put(r.getInt(1), r.getInt(2));
            }
        }
        String last = meta("proxy_last_id");
        st.proxyLastId = last == null ? 0 : Long.parseLong(last);
        return st;
    }

    // ---------- file permissions ----------

    static void createOwnerOnly(Path file) throws IOException {
        try {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            Files.createFile(file);
            restrictToOwner(file, false);
        }
    }

    /** POSIX: 0700/0600. Windows: ACL with only the owner and SYSTEM (inherited by children). Errors are ignored. */
    static void restrictToOwner(Path p, boolean dir) {
        try {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(dir ? "rwx------" : "rw-------"));
            return;
        } catch (UnsupportedOperationException | IOException ignored) {
            // not POSIX
        }
        try {
            AclFileAttributeView view = Files.getFileAttributeView(p, AclFileAttributeView.class);
            if (view == null) return;
            UserPrincipal owner = Files.getOwner(p);
            List<AclEntry> acl = new ArrayList<>();
            Set<AclEntryFlag> flags = dir ? EnumSet.of(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT)
                    : EnumSet.noneOf(AclEntryFlag.class);
            acl.add(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
                    .setPermissions(EnumSet.allOf(AclEntryPermission.class)).setFlags(flags).build());
            try {
                UserPrincipal system = p.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName("SYSTEM");
                acl.add(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(system)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class)).setFlags(flags).build());
            } catch (IOException | UnsupportedOperationException ignored) {
                // SYSTEM lookup failed: owner only
            }
            view.setAcl(acl);
        } catch (Exception e) {
            Log.warn("Could not set owner-only permissions on " + p + ": " + e.getMessage());
        }
    }

    private static void warnIfNetworkDrive(Path file) {
        try {
            FileStore fs = Files.getFileStore(file);
            String type = fs.type().toLowerCase(Locale.ROOT);
            if (type.contains("nfs") || type.contains("smb") || type.contains("cifs") || file.toString().startsWith("\\\\")) {
                Log.warn("DB is on a network drive (" + fs.type() + "): SQLite WAL is not supported there, choose a folder on a local drive.");
            }
        } catch (IOException ignored) {
            // ignore
        }
    }

    @Override
    public void close() {
        try { writeConn.close(); } catch (SQLException e) { Log.error("closing DB", e); }
        try { if (lock != null) lock.release(); } catch (IOException ignored) { }
        try { if (lockChannel != null) lockChannel.close(); } catch (IOException ignored) { }
    }

    public void deleteFiles() {
        for (String suffix : new String[]{"", "-wal", "-shm", ".lock"}) {
            try { Files.deleteIfExists(file.resolveSibling(file.getFileName() + suffix)); } catch (IOException ignored) { }
        }
    }
}
