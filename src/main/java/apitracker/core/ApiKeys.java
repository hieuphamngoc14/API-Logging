package apitracker.core;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * API key normalization.
 * <ul>
 *   <li>apiKey = hostKey + pathKey (no method, no query) — used to group the log.</li>
 *   <li>statusKey = METHOD + ' ' + apiKey — used to highlight yellow / clear the yellow highlight.</li>
 * </ul>
 * Single pass, O(path length), no regex, with a cache shared across proxy threads.
 */
public final class ApiKeys {
    private static final int CACHE_MAX = 8192;
    private static final int CACHE_MAX_LEN = 512;
    private final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>(4096);

    public static String hostKey(String host, int port, boolean secure) {
        String h = host == null ? "" : host.toLowerCase(Locale.ROOT);
        if (h.indexOf(':') >= 0 && !h.startsWith("[")) h = '[' + h + ']';   // IPv6
        return (secure ? "https://" : "http://") + h + ':' + port;
    }

    /** rawPath must be the path without the query (pathWithoutQuery). */
    public String pathKey(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) return "/";
        if (rawPath.length() > CACHE_MAX_LEN) return normalize(rawPath);
        String k = cache.get(rawPath);
        if (k != null) return k;
        k = normalize(rawPath);
        if (cache.size() >= CACHE_MAX) cache.clear();   // cheaper than a locked LRU
        cache.put(rawPath, k);
        return k;
    }

    public String statusKey(String method, String hostKey, String rawPath) {
        return statusKeyOf(method, hostKey + pathKey(rawPath));
    }

    public static String statusKeyOf(String method, String apiKey) {
        return (method == null ? "GET" : method.toUpperCase(Locale.ROOT)) + ' ' + apiKey;
    }

    public static String normalize(String p) {
        int q = p.indexOf('?');
        int n = q >= 0 ? q : p.length();
        int hashIdx = p.indexOf('#');
        if (hashIdx >= 0 && hashIdx < n) n = hashIdx;
        // absolute URL in the request line (proxy style): drop scheme://host
        int start = 0;
        int schemeEnd = p.indexOf("://");
        if (schemeEnd > 0 && schemeEnd < n && p.charAt(0) != '/') {
            int slash = p.indexOf('/', schemeEnd + 3);
            start = (slash < 0 || slash > n) ? n : slash;
        }
        StringBuilder out = new StringBuilder(n - start + 1);
        for (int i = start; i < n; ) {
            while (i < n && p.charAt(i) == '/') i++;
            int a = i;
            while (i < n && p.charAt(i) != '/') i++;
            int b = cutJsessionid(p, a, i);
            if (b > a) out.append('/').append(classify(p, a, b));
        }
        return out.length() == 0 ? "/" : out.toString();
    }

    static int cutJsessionid(String p, int a, int b) {
        int j = p.indexOf(';', a);
        return (j >= 0 && j < b && p.regionMatches(true, j, ";jsessionid=", 0, 12)) ? j : b;
    }

    static CharSequence classify(String p, int a, int b) {
        int len = b - a, dig = 0, hex = 0, alpha = 0, sep = 0, dash = 0, flips = 0, prev = 0;
        for (int i = a; i < b; i++) {
            char c = p.charAt(i);
            int kind = 0;
            if (c >= '0' && c <= '9') { dig++; hex++; kind = 2; }
            else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') { hex++; alpha++; kind = 1; }
            else if (Character.isLetter(c)) { alpha++; kind = 1; }
            else if (c == '-') { dash++; sep++; }
            else if (c == '_') sep++;
            if (kind != 0) {
                if (prev != 0 && kind != prev) flips++;
                prev = kind;
            }
        }
        if (dig == len) return "{id}";
        if (len == 36 && dash == 4 && hex == 32) return "{uuid}";
        if (len >= 16 && hex == len) return "{hex}";
        if (len >= 20 && dig >= 3 && flips >= 3 && dig + alpha + sep == len) return "{token}";
        return p.subSequence(a, b);
    }

    /** Splits pathKey into segments (leading '/' dropped). "/" → empty array. */
    public static String[] segments(String pathKey) {
        if (pathKey == null || pathKey.length() <= 1) return new String[0];
        return pathKey.substring(1).split("/", -1);
    }

    /**
     * Two segment lists of equal length (≥ 2) that differ in at most one position. Single-segment paths
     * (/login and /logout) are never variants of each other.
     */
    public static boolean isVariant(String[] a, String[] b) {
        if (a.length != b.length || a.length < 2) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            if (!a[i].equals(b[i]) && ++diff > 1) return false;
        }
        return true;
    }

    /**
     * Similarity of two variant paths: -1 if not variants; otherwise the common prefix + suffix length of the
     * differing segment (users' is closer to users than orders is). Used to pick the right API among candidates.
     */
    public static int variantScore(String[] a, String[] b) {
        if (!isVariant(a, b)) return -1;
        for (int i = 0; i < a.length; i++) {
            if (a[i].equals(b[i])) continue;
            String x = a[i], y = b[i];
            int p = 0, max = Math.min(x.length(), y.length());
            while (p < max && x.charAt(p) == y.charAt(p)) p++;
            int s = 0;
            while (s < max - p && x.charAt(x.length() - 1 - s) == y.charAt(y.length() - 1 - s)) s++;
            return p + s;
        }
        return Integer.MAX_VALUE;
    }

    public void clearCache() { cache.clear(); }
}
