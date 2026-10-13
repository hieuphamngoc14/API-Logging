package apitracker.store;

/** Immutable records shared by the worker, DB and UI. */
public final class Rows {
    private Rows() {}

    public static final int FLAG_REDIRECT = 1;
    public static final int FLAG_NO_RESPONSE = 2;
    public static final int FLAG_SELF_ORIGINAL = 4;
    public static final int FLAG_RAW_DROPPED = 8;
    /** AI send for an API with no original request: recorded but not diffed (AI is never the original). */
    public static final int FLAG_NO_ORIGINAL = 16;
    /** Summary row of an Intruder attack: changes is the payload position list + a stats line "→ …". */
    public static final int FLAG_INTRUDER = 32;
    /** Intruder attack still running (the row will be updated). */
    public static final int FLAG_RUNNING = 64;
    /** Original request unreadable (DB error): the send is recorded without diff and the test state is unchanged. */
    public static final int FLAG_ORIGINAL_UNAVAILABLE = 128;

    /** Status class bit (2xx..5xx) for the status_mask column of Intruder rows (an attack has many statuses). */
    public static int statusClassBit(int status) {
        if (status >= 200 && status < 300) return 1;
        if (status >= 300 && status < 400) return 2;
        if (status >= 400 && status < 500) return 4;
        if (status >= 500 && status < 600) return 8;
        return 16;
    }

    public static final int SRC_TRACKED = 1, SRC_TABHOOK = 2, SRC_PROXY = 3, SRC_SELF = 4;

    public static String originalSourceName(int s) {
        switch (s) {
            case SRC_TRACKED: return "Send to Repeater, tracked";
            case SRC_TABHOOK: return "Repeater tab";
            case SRC_PROXY: return "Proxy history";
            case SRC_SELF: return "first send";
            default: return "?";
        }
    }

    /** method = method of the first original request (shown in the list). */
    public record ApiRow(int id, String hostKey, String pathKey, String method, int sendCount, long lastSeen,
                         boolean tested, int originals) {}

    /** seq = number of this entry in its API's log (#1 = first entry, originals and sends share the sequence); 0 = unknown. */
    public record SendRow(long id, int apiId, int originalId, long ts, int status, int length, int ms, int flags,
                          String source, int locMask, String firstLine, String changes, int seq) {
        public SendRow(long id, int apiId, int originalId, long ts, int status, int length, int ms, int flags,
                       String source, int locMask, String firstLine, String changes) {
            this(id, apiId, originalId, ts, status, length, ms, flags, source, locMask, firstLine, changes, 0);
        }
    }

    public record OriginalRow(int id, int apiId, long ts, int source, String method, String firstLine, int status,
                              int length, int seq) {
        public OriginalRow(int id, int apiId, long ts, int source, String method, String firstLine, int status, int length) {
            this(id, apiId, ts, source, method, firstLine, status, length, 0);
        }
    }
}
