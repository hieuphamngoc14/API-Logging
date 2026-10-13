package apitracker.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.CRC32C;

/**
 * Request parsed once, used for original request selection and diff. No Burp dependency.
 * Repeated fields are all kept, keyed by occurrence order: {@code id}, {@code id#2}, {@code id#3}.
 */
public final class ParsedReq {
    public enum BodyKind { NONE, JSON, FORM, MULTIPART, TEXT, BINARY, LARGE }

    public static final int DEFAULT_MAX_BODY = 256 * 1024;
    public static final int JSON_MAX_DEPTH = 8;
    public static final int JSON_MAX_FIELDS = 1000;

    public final String method;
    public final String target;
    public final String path;
    public final String version;
    public final String firstLine;
    public final String hostHeader;
    public final String[] segments;
    public final Map<String, String> query;
    public final Map<String, String> headers;          // lowercase name (#n) → value, excluding Cookie
    public final Map<String, String> headerDisplay;    // lowercase name → original name
    public final Map<String, String> cookies;
    public final BodyKind bodyKind;
    public final Map<String, String> bodyFields;       // JSON / FORM / MULTIPART
    public final int bodySize;
    public final long bodyHash;
    public final String bodyText;                      // TEXT (≤ maxBody)
    public final String contentType;
    public final long[] features;

    private ParsedReq(Builder b) {
        method = b.method; target = b.target; path = b.path; version = b.version;
        firstLine = b.method + " " + b.target + (b.version.isEmpty() ? "" : " " + b.version);
        hostHeader = b.host; segments = b.segments;
        query = b.query; headers = b.headers; headerDisplay = b.headerDisplay; cookies = b.cookies;
        bodyKind = b.bodyKind; bodyFields = b.bodyFields; bodySize = b.bodySize; bodyHash = b.bodyHash;
        bodyText = b.bodyText; contentType = b.contentType;
        features = computeFeatures(this);
    }

    private ParsedReq(ParsedReq o, BodyKind kind, long hash, int size) {
        method = o.method; target = o.target; path = o.path; version = o.version; firstLine = o.firstLine;
        hostHeader = o.hostHeader; segments = o.segments; query = o.query; headers = o.headers;
        headerDisplay = o.headerDisplay; cookies = o.cookies; contentType = o.contentType;
        bodyKind = kind; bodyFields = Collections.emptyMap(); bodySize = size; bodyHash = hash; bodyText = null;
        features = o.features;
    }

    /**
     * Copy with a "large" body carrying the full body's fingerprint. Used for original requests truncated on save
     * (so re-parsing the truncated copy does not produce a bogus body diff).
     */
    public ParsedReq withLargeBody(long hash, int size) {
        return new ParsedReq(this, BodyKind.LARGE, hash, size);
    }

    /** Swing editors use \n; real requests use \r\n. Converts only the header part, body unchanged. */
    public static String normalizeHeaderNewlines(String text) {
        int end = text.indexOf("\n\n");
        int crlfEnd = text.indexOf("\r\n\r\n");
        if (crlfEnd >= 0 && (end < 0 || crlfEnd < end)) return text;
        if (end < 0) return text.replace("\r\n", "\n").replace("\n", "\r\n");
        String head = text.substring(0, end).replace("\r\n", "\n").replace("\n", "\r\n");
        return head + "\r\n\r\n" + text.substring(end + 2);
    }

    private static final class Builder {
        String method = "?", target = "/", path = "/", version = "", host = "", contentType = "";
        String[] segments = new String[0];
        Map<String, String> query = new LinkedHashMap<>();
        Map<String, String> headers = new LinkedHashMap<>();
        Map<String, String> headerDisplay = new HashMap<>();
        Map<String, String> cookies = new LinkedHashMap<>();
        BodyKind bodyKind = BodyKind.NONE;
        Map<String, String> bodyFields = Collections.emptyMap();
        int bodySize;
        long bodyHash;
        String bodyText;
    }

    public static ParsedReq parse(byte[] raw) { return parse(raw, DEFAULT_MAX_BODY); }

    public static ParsedReq parse(byte[] raw, int maxBody) {
        Builder b = new Builder();
        try {
            parseInto(b, raw == null ? new byte[0] : raw, maxBody);
        } catch (RuntimeException e) {
            // malformed request: keep whatever was parsed
        }
        return new ParsedReq(b);
    }

    private static void parseInto(Builder b, byte[] raw, int maxBody) {
        int headerEnd = -1, bodyStart = raw.length;
        for (int i = 0; i + 1 < raw.length; i++) {
            if (raw[i] == '\n' && raw[i + 1] == '\n') { headerEnd = i; bodyStart = i + 2; break; }
            if (raw[i] == '\r' && i + 3 < raw.length && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
                headerEnd = i; bodyStart = i + 4; break;
            }
        }
        if (headerEnd < 0) headerEnd = raw.length;
        String head = new String(raw, 0, headerEnd, StandardCharsets.ISO_8859_1);
        String[] lines = head.split("\r?\n", -1);
        if (lines.length == 0) return;

        String rl = lines[0].trim();
        int sp1 = rl.indexOf(' ');
        int sp2 = sp1 < 0 ? -1 : rl.lastIndexOf(' ');
        if (sp1 < 0) { b.method = rl.isEmpty() ? "?" : rl; }
        else if (sp2 == sp1) { b.method = rl.substring(0, sp1); b.target = rl.substring(sp1 + 1); }
        else {
            b.method = rl.substring(0, sp1);
            b.target = rl.substring(sp1 + 1, sp2).trim();
            b.version = rl.substring(sp2 + 1);
            if (!b.version.startsWith("HTTP/")) { b.target = rl.substring(sp1 + 1); b.version = ""; }
        }
        b.method = b.method.toUpperCase(Locale.ROOT);

        String t = b.target;
        int frag = t.indexOf('#');
        if (frag >= 0) t = t.substring(0, frag);
        int q = t.indexOf('?');
        String p = q >= 0 ? t.substring(0, q) : t;
        int scheme = p.indexOf("://");
        if (scheme > 0 && !p.startsWith("/")) {
            int slash = p.indexOf('/', scheme + 3);
            p = slash < 0 ? "/" : p.substring(slash);
        }
        b.path = p.isEmpty() ? "/" : p;
        b.segments = rawSegments(b.path);
        if (q >= 0) parsePairs(t.substring(q + 1), '&', b.query);

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int c = line.indexOf(':', line.startsWith(":") ? 1 : 0);
            if (c <= 0) continue;
            String name = line.substring(0, c).trim();
            String value = line.substring(c + 1).trim();
            if (name.startsWith(":")) continue;           // pseudo-header HTTP/2
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.equals("cookie")) {
                for (String part : value.split(";")) {
                    String kv = part.trim();
                    if (kv.isEmpty()) continue;
                    int eq = kv.indexOf('=');
                    if (eq < 0) putOcc(b.cookies, kv, "");
                    else putOcc(b.cookies, kv.substring(0, eq).trim(), kv.substring(eq + 1).trim());
                }
                continue;
            }
            if (lower.equals("host") && b.host.isEmpty()) b.host = value;
            if (lower.equals("content-type") && b.contentType.isEmpty()) b.contentType = value;
            b.headerDisplay.putIfAbsent(lower, name);
            putOcc(b.headers, lower, value);
        }

        int bodyLen = Math.max(0, raw.length - bodyStart);
        b.bodySize = bodyLen;
        if (bodyLen == 0) { b.bodyKind = BodyKind.NONE; return; }
        CRC32C crc = new CRC32C();
        crc.update(raw, bodyStart, bodyLen);
        b.bodyHash = (crc.getValue() << 32) ^ bodyLen;
        if (bodyLen > maxBody) { b.bodyKind = BodyKind.LARGE; return; }

        String ct = b.contentType.toLowerCase(Locale.ROOT);
        String text = new String(raw, bodyStart, bodyLen, StandardCharsets.UTF_8);
        if (ct.contains("multipart/form-data")) {
            String boundary = param(b.contentType, "boundary");
            if (boundary != null && !boundary.isEmpty()) {
                Map<String, String> m = new LinkedHashMap<>();
                if (parseMultipart(text, boundary, m)) { b.bodyKind = BodyKind.MULTIPART; b.bodyFields = m; return; }
            }
        }
        if (ct.contains("x-www-form-urlencoded")) {
            Map<String, String> m = new LinkedHashMap<>();
            parsePairs(text.trim(), '&', m);
            b.bodyKind = BodyKind.FORM; b.bodyFields = m; return;
        }
        String trimmed = text.trim();
        boolean looksJson = !trimmed.isEmpty() && (trimmed.charAt(0) == '{' || trimmed.charAt(0) == '[');
        if (ct.contains("json") || (looksJson && !ct.contains("xml") && !ct.contains("html"))) {
            try {
                b.bodyFields = JsonFlattener.flatten(text, JSON_MAX_DEPTH, JSON_MAX_FIELDS);
                b.bodyKind = BodyKind.JSON;
                return;
            } catch (IllegalArgumentException ignored) {
                // not valid JSON: treat as text
            }
        }
        if (isText(raw, bodyStart, bodyLen)) { b.bodyKind = BodyKind.TEXT; b.bodyText = text; }
        else b.bodyKind = BodyKind.BINARY;
    }

    static String[] rawSegments(String path) {
        String p = path;
        int semi = p.toLowerCase(Locale.ROOT).indexOf(";jsessionid=");
        if (semi >= 0) {
            int next = p.indexOf('/', semi);
            p = p.substring(0, semi) + (next >= 0 ? p.substring(next) : "");
        }
        String[] parts = p.split("/");
        int n = 0;
        for (String s : parts) if (!s.isEmpty()) n++;
        String[] out = new String[n];
        int k = 0;
        for (String s : parts) if (!s.isEmpty()) out[k++] = s;
        return out;
    }

    static void parsePairs(String s, char sep, Map<String, String> into) {
        if (s == null || s.isEmpty()) return;
        int i = 0, n = s.length();
        while (i <= n) {
            int j = s.indexOf(sep, i);
            if (j < 0) j = n;
            if (j > i) {
                String part = s.substring(i, j);
                int eq = part.indexOf('=');
                if (eq < 0) putOcc(into, part, "");
                else putOcc(into, part.substring(0, eq), part.substring(eq + 1));
            }
            i = j + 1;
        }
    }

    static void putOcc(Map<String, String> m, String name, String value) {
        if (!m.containsKey(name)) { m.put(name, value); return; }
        for (int n = 2; ; n++) {
            String k = name + "#" + n;
            if (!m.containsKey(k)) { m.put(k, value); return; }
        }
    }

    static String param(String headerValue, String name) {
        for (String part : headerValue.split(";")) {
            String kv = part.trim();
            int eq = kv.indexOf('=');
            if (eq > 0 && kv.substring(0, eq).trim().equalsIgnoreCase(name)) {
                String v = kv.substring(eq + 1).trim();
                if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length() - 1);
                return v;
            }
        }
        return null;
    }

    static boolean parseMultipart(String body, String boundary, Map<String, String> into) {
        String delim = "--" + boundary;
        int pos = body.indexOf(delim);
        if (pos < 0) return false;
        int parts = 0;
        while (pos >= 0) {
            int start = pos + delim.length();
            if (body.startsWith("--", start)) break;                   // closing delimiter
            int next = body.indexOf(delim, start);
            if (next < 0) next = body.length();
            String part = body.substring(start, next);
            if (part.startsWith("\r\n")) part = part.substring(2); else if (part.startsWith("\n")) part = part.substring(1);
            int sep = part.indexOf("\r\n\r\n");
            int sepLen = 4;
            if (sep < 0) { sep = part.indexOf("\n\n"); sepLen = 2; }
            if (sep >= 0) {
                String headers = part.substring(0, sep);
                String content = part.substring(sep + sepLen);
                if (content.endsWith("\r\n")) content = content.substring(0, content.length() - 2);
                else if (content.endsWith("\n")) content = content.substring(0, content.length() - 1);
                String disp = null;
                for (String h : headers.split("\r?\n")) {
                    if (h.toLowerCase(Locale.ROOT).startsWith("content-disposition:")) disp = h.substring(20);
                }
                String name = disp == null ? null : param(disp, "name");
                String filename = disp == null ? null : param(disp, "filename");
                if (name == null) name = "part" + (parts + 1);
                String value = filename != null
                        ? "<file \"" + filename + "\" " + content.length() + " B #" + Integer.toHexString(content.hashCode()) + ">"
                        : content;
                putOcc(into, name, value);
                parts++;
            }
            pos = next < body.length() ? next : -1;
        }
        return parts > 0;
    }

    static boolean isText(byte[] raw, int off, int len) {
        int check = Math.min(len, 2048), bad = 0;
        for (int i = off; i < off + check; i++) {
            int c = raw[i] & 0xFF;
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') bad++;
        }
        return bad * 20 <= check;   // ≤ 5% control bytes
    }

    // ---------- features for original request selection ----------

    private static final String[] FEATURE_IGNORED_HEADERS = {"content-length", "connection"};

    private static long[] computeFeatures(ParsedReq r) {
        long[] f = new long[1 + r.segments.length + r.query.size() + r.headers.size() + r.cookies.size()
                + Math.max(1, r.bodyFields.size())];
        int n = 0;
        f[n++] = h("m", "", r.method);
        for (int i = 0; i < r.segments.length; i++) f[n++] = h("p", Integer.toString(i), r.segments[i]);
        for (Map.Entry<String, String> e : r.query.entrySet()) f[n++] = h("q", e.getKey(), e.getValue());
        outer:
        for (Map.Entry<String, String> e : r.headers.entrySet()) {
            for (String ig : FEATURE_IGNORED_HEADERS) if (e.getKey().equals(ig)) continue outer;
            f[n++] = h("h", e.getKey(), e.getValue());
        }
        for (Map.Entry<String, String> e : r.cookies.entrySet()) f[n++] = h("c", e.getKey(), e.getValue());
        if (!r.bodyFields.isEmpty()) {
            for (Map.Entry<String, String> e : r.bodyFields.entrySet()) f[n++] = h("b", e.getKey(), e.getValue());
        } else if (r.bodyKind != BodyKind.NONE) {
            f[n++] = h("b", "#", Long.toHexString(r.bodyHash));
        }
        long[] out = Arrays.copyOf(f, n);
        Arrays.sort(out);
        int m = 0;
        for (int i = 0; i < out.length; i++) if (i == 0 || out[i] != out[i - 1]) out[m++] = out[i];
        return Arrays.copyOf(out, m);
    }

    static long h(String section, String name, String value) {
        long x = 0xcbf29ce484222325L;
        x = fnv(x, section); x = (x ^ 0) * 0x100000001b3L;
        x = fnv(x, name); x = (x ^ 1) * 0x100000001b3L;
        x = fnv(x, value);
        return x;
    }

    private static long fnv(long x, String s) {
        for (int i = 0; i < s.length(); i++) {
            x ^= s.charAt(i);
            x *= 0x100000001b3L;
        }
        return x;
    }

    /** Number of differing elements between two sorted, deduplicated arrays (symmetric). O(n+m). */
    public static int distance(long[] a, long[] b) {
        int i = 0, j = 0, d = 0;
        while (i < a.length && j < b.length) {
            if (a[i] == b[j]) { i++; j++; }
            else if (a[i] < b[j]) { d++; i++; }
            else { d++; j++; }
        }
        return d + (a.length - i) + (b.length - j);
    }
}
