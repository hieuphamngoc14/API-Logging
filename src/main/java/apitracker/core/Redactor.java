package apitracker.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Masks the values the user chose to hide before they go into the log / FTS. Everything is cleartext by default:
 * only fields named in the "Masked fields" setting, and values the user labeled (userA's token…), are replaced by a
 * fingerprint {@code <#a1b2c3d4>} (first 8 hex of HMAC-SHA256 with a random per-DB key; not reversible).
 * <p>A listed name matches a header / cookie / query / form / JSON field when the field name, or one of its words
 * (split on non-alphanumerics and camelCase), equals it ignoring case, plural included: "token" masks {@code token},
 * {@code accessToken}, {@code x-csrf-token}, {@code tokens}, but not {@code tokenizer}.
 */
public final class Redactor {
    public static final int MAX_DISPLAY = 120;

    private final byte[] key;
    private final ThreadLocal<Mac> mac;
    private final Set<String> tokens;
    /** Full HMACs of labeled values (live view of the labels): shown as their label even when not masked. */
    private volatile Set<String> labeled = Set.of();
    private final Map<String, String> cache = new LinkedHashMap<>(256, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, String> e) { return size() > 1000; }
    };

    /** maskedFields: names from the "Masked fields" setting (empty = mask nothing). */
    public Redactor(byte[] hmacKey, Collection<String> maskedFields) {
        this.key = hmacKey.clone();
        this.mac = ThreadLocal.withInitial(this::newMac);
        Set<String> t = new HashSet<>();
        if (maskedFields != null) for (String s : maskedFields) {
            String v = s.trim().toLowerCase(Locale.ROOT);
            if (!v.isEmpty()) t.add(v);
        }
        this.tokens = Set.copyOf(t);
    }

    /** Live set of labeled values' full HMACs (from the labels store). */
    public void setLabeled(Set<String> fullHmacs) { labeled = fullHmacs == null ? Set.of() : fullHmacs; }

    private Mac newMac() {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Nothing to mask: no masked field configured and no label. Callers skip all work. */
    private boolean idle() { return tokens.isEmpty() && labeled.isEmpty(); }

    // ---------- names ----------

    /** True if the field name is in the "Masked fields" setting (see class doc for the matching rule). */
    public boolean masked(String name) {
        if (tokens.isEmpty() || name == null || name.isEmpty()) return false;
        int hash = name.indexOf('#');                       // drop the occurrence suffix "id#2"
        String n = hash > 0 ? name.substring(0, hash) : name;
        int dot = n.lastIndexOf('.');                       // JSON path: only the last key counts
        int br = n.lastIndexOf('[');
        if (n.startsWith("$")) {
            if (br > dot && n.endsWith("]")) {
                // $.a["x y"] or $.a[0]
                String inner = n.substring(br + 1, n.length() - 1);
                if (inner.startsWith("\"")) n = inner.replace("\"", "");
                else return masked(n.substring(0, br));      // array element: use the array name
            } else if (dot >= 0) n = n.substring(dot + 1);
        }
        if (isToken(n.toLowerCase(Locale.ROOT))) return true;
        // words split on non-alphanumeric chars and on camelCase
        int start = 0;
        for (int i = 1; i <= n.length(); i++) {
            boolean boundary = i == n.length();
            if (!boundary) {
                char c = n.charAt(i), p = n.charAt(i - 1);
                boundary = !Character.isLetterOrDigit(c) || (Character.isUpperCase(c) && Character.isLowerCase(p));
            }
            if (boundary) {
                if (i > start && isToken(n.substring(start, i).toLowerCase(Locale.ROOT))) return true;
                start = (i < n.length() && !Character.isLetterOrDigit(n.charAt(i))) ? i + 1 : i;
            }
        }
        return false;
    }

    /** Word is in the list, including plural forms (tokens, passwords). */
    private boolean isToken(String t) {
        if (tokens.contains(t)) return true;
        return t.length() > 3 && t.endsWith("s") && tokens.contains(t.substring(0, t.length() - 1));
    }

    // ---------- values ----------

    /** Value without surrounding double quotes (JSON strings are stored quoted). */
    private static String unquote(String v) {
        return v.length() >= 2 && v.charAt(0) == '"' && v.charAt(v.length() - 1) == '"' ? v.substring(1, v.length() - 1) : v;
    }

    /** True if the user labeled this value (quoted or not). */
    public boolean isLabeled(String value) {
        Set<String> l = labeled;
        if (l.isEmpty() || value == null || value.isEmpty()) return false;
        return l.contains(hmac(value)) || (value.charAt(0) == '"' && l.contains(hmac(unquote(value))));
    }

    /** Fingerprint of the value's content (quotes dropped), so a token has the same fingerprint everywhere. */
    private String mask(String value) {
        String v = unquote(value);
        Set<String> l = labeled;
        // a value that was labeled together with its quotes keeps them, so its label still applies
        if (!v.equals(value) && !l.isEmpty() && l.contains(hmac(value)) && !l.contains(hmac(v))) return fp(value);
        return fp(v);
    }

    // ---------- fingerprint ----------

    public String fullHmac(String value) {
        byte[] d = mac.get().doFinal(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder b = new StringBuilder(64);
        for (byte x : d) {
            b.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        }
        return b.toString();
    }

    private String hmac(String value) {
        synchronized (cache) {
            String c = cache.get(value);
            if (c != null) return c;
        }
        String h = fullHmac(value);
        synchronized (cache) { cache.put(value, h); }
        return h;
    }

    public String fp(String value) {
        return "<#" + hmac(value == null ? "" : value).substring(0, 8) + ">";
    }

    /** Value for the log: masked if the field is in the setting (or forced) or the value is labeled, else clipped cleartext. */
    public String display(String name, String value, boolean forceMasked) {
        if (value == null) return "";
        if (forceMasked || masked(name) || isLabeled(value)) return mask(value);
        return clip(value);
    }

    public static String clip(String v) {
        if (v == null) return "";
        String s = v;
        if (s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0 || s.indexOf('\t') >= 0) {
            s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
        }
        if (s.length() > MAX_DISPLAY) s = s.substring(0, 60) + "…(+" + (s.length() - 60) + ")";
        return s;
    }

    /** Request-line target: masks values of listed query / ;matrix parameters and labeled values; the rest as is. */
    public String redactTarget(String target) {
        if (target == null) return "";
        if (idle()) return target;
        int q = target.indexOf('?');
        String path = q >= 0 ? target.substring(0, q) : target;
        StringBuilder b = new StringBuilder(target.length());
        int i = 0;
        while (i < path.length()) {
            int slash = path.indexOf('/', i);
            if (slash < 0) slash = path.length();
            b.append(redactSegment(path.substring(i, slash)));
            if (slash < path.length()) b.append('/');
            i = slash + 1;
        }
        if (q >= 0) {
            b.append('?');
            String query = target.substring(q + 1);
            String[] parts = query.split("&", -1);
            for (int k = 0; k < parts.length; k++) {
                if (k > 0) b.append('&');
                String p = parts[k];
                int eq = p.indexOf('=');
                if (eq < 0) { b.append(isLabeled(p) ? fp(p) : p); continue; }
                String name = p.substring(0, eq), val = p.substring(eq + 1);
                b.append(name).append('=').append(masked(name) || isLabeled(val) ? fp(val) : val);
            }
        }
        return b.toString();
    }

    /** One path segment: masks it if labeled, and values of listed ;matrix parameters (;jsessionid=…). */
    public String redactSegment(String seg) {
        if (seg == null) return "";
        if (idle()) return seg;
        int semi = seg.indexOf(';');
        if (semi < 0) return isLabeled(seg) ? fp(seg) : seg;
        StringBuilder b = new StringBuilder(seg.length());
        String head = seg.substring(0, semi);
        b.append(isLabeled(head) ? fp(head) : head);
        for (String param : seg.substring(semi + 1).split(";", -1)) {
            b.append(';');
            int eq = param.indexOf('=');
            if (eq < 0) { b.append(isLabeled(param) ? fp(param) : param); continue; }
            String k = param.substring(0, eq), v = param.substring(eq + 1);
            b.append(k).append('=').append(masked(k) || isLabeled(v) ? fp(v) : v);
        }
        return b.toString();
    }

    // ---------- raw HTTP message (AI export) ----------

    /**
     * Readable HTTP message (request or response, "\n" line breaks): masks the request-line query, headers, cookies and
     * body fields named in the setting, and labeled values. Unchanged when nothing is configured.
     */
    public String maskHttp(String text) {
        if (text == null || text.isEmpty() || idle()) return text;
        int split = text.indexOf("\n\n");
        String head = split < 0 ? text : text.substring(0, split);
        String[] lines = head.split("\n", -1);
        StringBuilder b = new StringBuilder(text.length() + 32);
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i];
            if (i > 0) b.append('\n');
            if (i == 0) {                                                   // request line: METHOD target VERSION
                int s1 = l.indexOf(' '), s2 = l.lastIndexOf(' ');
                if (!l.startsWith("HTTP/") && s1 > 0 && s2 > s1) b.append(l, 0, s1 + 1).append(redactTarget(l.substring(s1 + 1, s2))).append(l.substring(s2));
                else b.append(l);
                continue;
            }
            int c = l.indexOf(':');
            if (c <= 0) { b.append(l); continue; }
            String name = l.substring(0, c).trim(), value = l.substring(c + 1).trim();
            String lname = name.toLowerCase(Locale.ROOT);
            b.append(name).append(": ");
            if (masked(name) || isLabeled(value)) b.append(mask(value));
            else if (lname.equals("cookie")) b.append(maskPairs(value, false));
            else if (lname.equals("set-cookie")) b.append(maskPairs(value, true));
            else if (value.regionMatches(true, 0, "bearer ", 0, 7) && isLabeled(value.substring(7).trim())) {
                b.append(value, 0, 7).append(fp(value.substring(7).trim()));
            } else b.append(value);
        }
        if (split >= 0) b.append("\n\n").append(redactText(text.substring(split + 2)));
        return b.toString();
    }

    /** "a=1; b=2" (Cookie) or "SID=x; Path=/" (Set-Cookie: only the first pair is a cookie). */
    private String maskPairs(String value, boolean firstOnly) {
        String[] parts = value.split(";", -1);
        StringBuilder b = new StringBuilder(value.length());
        for (int k = 0; k < parts.length; k++) {
            if (k > 0) b.append(';');
            String p = parts[k];
            int eq = p.indexOf('=');
            if ((firstOnly && k > 0) || eq < 0) { b.append(p); continue; }
            String n = p.substring(0, eq), v = p.substring(eq + 1);
            b.append(n).append('=').append(masked(n.trim()) || isLabeled(v.trim()) ? fp(v.trim()) : v);
        }
        return b.toString();
    }

    // ---------- free text (XML / text body) ----------

    /** Char that belongs to a value (not a structural separator). */
    public static boolean valueChar(char c) {
        return c > ' ' && "&\"'<>=:,;{}[]()".indexOf(c) < 0;
    }

    private static boolean nameChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '-' || c == '.';
    }

    private static boolean sepChar(char c) {
        return c == '"' || c == '\'' || c == ' ' || c == '\t' || c == ':' || c == '=' || c == '>';
    }

    /**
     * Name right before position {@code at}, in the forms {@code name=}, {@code "name": "}, {@code <name>},
     * {@code name="}. Returns null if none.
     */
    public static String nameBefore(String s, int at) {
        int i = at, seps = 0, spaces = 0;
        boolean assign = false;
        while (i > 0 && seps < 4 && spaces < 32 && sepChar(s.charAt(i - 1))) {
            char c = s.charAt(i - 1);
            if (c == '=' || c == ':' || c == '>') assign = true;
            if (c == ' ' || c == '\t') spaces++; else seps++;
            i--;
        }
        if (!assign) return null;
        int end = i;
        while (i > 0 && end - i < 64 && nameChar(s.charAt(i - 1))) i--;
        return end > i ? s.substring(i, end) : null;
    }

    /**
     * Free text (XML / text body): masks values following a listed name ({@code password=x}, {@code "token":"x"},
     * {@code <secret>x}) and labeled values; everything else stays cleartext.
     */
    public String redactText(String s) {
        if (s == null || s.isEmpty()) return "";
        if (idle()) return s;
        String r = s;
        if (!tokens.isEmpty()) {
            int n = s.length();
            StringBuilder out = new StringBuilder(n + 16);
            int i = 0;
            while (i < n) {
                char c = s.charAt(i);
                if (!nameChar(c)) { out.append(c); i++; continue; }
                int a = i;
                while (i < n && nameChar(s.charAt(i))) i++;
                String name = s.substring(a, i);
                int j = i, seps = 0, spaces = 0;
                boolean assign = false;
                while (j < n && seps < 4 && spaces < 32 && sepChar(s.charAt(j))) {
                    char sc = s.charAt(j);
                    if (sc == '=' || sc == ':' || sc == '>') assign = true;
                    if (sc == ' ' || sc == '\t') spaces++; else seps++;
                    j++;
                }
                int v = j;
                while (v < n && valueChar(s.charAt(v))) v++;
                if (assign && v > j && masked(name)) {
                    out.append(name).append(s, i, j).append(fp(s.substring(j, v)));
                    i = v;
                } else {
                    out.append(name);
                }
            }
            r = out.toString();
        }
        if (labeled.isEmpty()) return r;
        StringBuilder b = new StringBuilder(r.length());
        int k = 0;
        while (k < r.length()) {
            if (!valueChar(r.charAt(k))) { b.append(r.charAt(k)); k++; continue; }
            int a = k;
            while (k < r.length() && valueChar(r.charAt(k))) k++;
            String tok = r.substring(a, k);
            b.append(isLabeled(tok) ? fp(tok) : tok);
        }
        return b.toString();
    }
}
