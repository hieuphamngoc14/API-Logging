package apitracker.core;

import java.util.Locale;
import java.util.Set;

/**
 * Repeater tab name: method + full path, without the query (after ?), e.g.
 * {@code GET /iis-server/watchlist?customerId=0009003785} → {@code GET /iis-server/watchlist}. Duplicate names get
 * {@code (2)}, {@code (3)}…
 */
public final class TabNames {
    private TabNames() {}

    /** Overly long paths (rare) are shortened in the middle so the tab stays readable. */
    public static final int MAX_PATH = 150;

    /**
     * @param path request path (may still have query / fragment / absolute URL form / {@code ;jsessionid=}: all stripped)
     */
    public static String tabName(String method, String path, Set<String> taken) {
        String base = (method == null || method.isBlank() ? "?" : method.trim().toUpperCase(Locale.ROOT)) + " " + cleanPath(path);
        String name = base;
        for (int n = 2; taken != null && taken.contains(name); n++) name = base + " (" + n + ")";
        return name;
    }

    /** Tab name from the request's first line ({@code GET /a/b?x=1 HTTP/1.1} → {@code GET /a/b}). */
    public static String fromRequestLine(String firstLine, Set<String> taken) {
        String l = firstLine == null ? "" : firstLine.trim();
        int sp1 = l.indexOf(' ');
        if (sp1 < 0) return tabName(l, "/", taken);
        int sp2 = l.indexOf(' ', sp1 + 1);
        return tabName(l.substring(0, sp1), sp2 < 0 ? l.substring(sp1 + 1) : l.substring(sp1 + 1, sp2), taken);
    }

    /** Full path without query, fragment, scheme://host or ;jsessionid= (keeps the session out of the tab name). */
    static String cleanPath(String path) {
        if (path == null || path.isEmpty()) return "/";
        String p = path.trim();
        int cut = p.length();
        int q = p.indexOf('?');
        if (q >= 0) cut = q;
        int h = p.indexOf('#');
        if (h >= 0 && h < cut) cut = h;
        p = p.substring(0, cut);
        int scheme = p.indexOf("://");
        if (scheme > 0 && !p.startsWith("/")) {
            int slash = p.indexOf('/', scheme + 3);
            p = slash < 0 ? "/" : p.substring(slash);
        }
        int js = p.toLowerCase(Locale.ROOT).indexOf(";jsessionid=");
        if (js >= 0) {
            int next = p.indexOf('/', js);
            p = p.substring(0, js) + (next >= 0 ? p.substring(next) : "");
        }
        if (p.isEmpty()) p = "/";
        if (!p.startsWith("/")) p = "/" + p;
        if (p.length() > MAX_PATH) p = p.substring(0, MAX_PATH / 2 - 1) + "…" + p.substring(p.length() - MAX_PATH / 2);
        return p;
    }

    /** Tabs Burp names itself are plain numbers (1, 2, 3…). Tabs the user renamed are left alone. */
    public static boolean isDefaultName(String title) {
        if (title == null) return false;
        String t = title.trim();
        if (t.isEmpty()) return false;
        for (int i = 0; i < t.length(); i++) if (!Character.isDigit(t.charAt(i))) return false;
        return true;
    }
}
