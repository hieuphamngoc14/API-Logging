package apitracker.util;

import burp.api.montoya.logging.Logging;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Compact logging, rate-limited so repeated errors do not flood Burp's Output tab.
 * When running the self-test (no Burp), prints to stderr.
 */
public final class Log {
    private static final long REPEAT_WINDOW_MS = 10_000;
    private static volatile Logging out;
    private static final ConcurrentHashMap<String, Long> lastByKey = new ConcurrentHashMap<>();

    private Log() {}

    public static void init(Logging logging) { out = logging; }

    public static void info(String msg) {
        Logging l = out;
        if (l != null) l.logToOutput("[API Logging] " + msg);
        else System.err.println("[info] " + msg);
    }

    public static void warn(String msg) {
        Logging l = out;
        if (l != null) l.logToError("[API Logging] " + msg);
        else System.err.println("[warn] " + msg);
    }

    public static void error(String msg, Throwable t) {
        if (!allow(msg + '|' + (t == null ? "" : t.getClass().getName()))) return;
        Logging l = out;
        if (l != null) {
            if (t != null) l.logToError("[API Logging] " + msg, t);
            else l.logToError("[API Logging] " + msg);
        } else {
            System.err.println("[error] " + msg);
            if (t != null) t.printStackTrace();
        }
    }

    /** Error on a hot path: logged at most once every 10 seconds per throw site. */
    public static void rateLimited(Throwable t) {
        StackTraceElement[] st = t.getStackTrace();
        String where = st.length > 0 ? st[0].toString() : "?";
        error("error at " + where, t);
    }

    private static boolean allow(String key) {
        long now = System.currentTimeMillis();
        Long prev = lastByKey.get(key);
        if (prev != null && now - prev < REPEAT_WINDOW_MS) return false;
        lastByKey.put(key, now);
        if (lastByKey.size() > 2_000) lastByKey.clear();
        return true;
    }
}
