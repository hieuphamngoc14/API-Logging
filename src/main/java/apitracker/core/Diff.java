package apitracker.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Diff between the original request and a send, in order method → path → query → header → cookie → body.
 * Every value in the result has gone through {@link Redactor}.
 */
public final class Diff {
    /** Change name when the body differs only in formatting (whitespace, key order): not counted as a test. */
    public static final String FORMAT_ONLY = "(formatting)";
    static final int MAX_VALUE_SCAN = 2048;
    public static final int LOC_METHOD = 1, LOC_PATH = 2, LOC_QUERY = 4, LOC_HEADER = 8, LOC_COOKIE = 16, LOC_BODY = 32;

    public record Change(char op, int loc, String name, String oldV, String newV) {
        public String format() {
            String l = locName(loc);
            StringBuilder b = new StringBuilder(64).append(op).append(' ').append(l);
            for (int i = l.length(); i < 7; i++) b.append(' ');
            b.append(' ');
            if (op == '~' && name.isEmpty()) {
                b.append(' ').append(oldV).append(" → ").append(newV);
                return b.toString();
            }
            b.append(name);
            if (op == '~') b.append("   ").append(oldV).append(" → ").append(newV);
            else if (op == '+' && newV != null && !newV.isEmpty()) b.append(" = ").append(newV);
            return b.toString();
        }
    }

    public static String locName(int loc) {
        switch (loc) {
            case LOC_METHOD: return "method";
            case LOC_PATH: return "path";
            case LOC_QUERY: return "query";
            case LOC_HEADER: return "header";
            case LOC_COOKIE: return "cookie";
            case LOC_BODY: return "body";
            default: return "?";
        }
    }

    private Diff() {}

    public static List<Change> compute(ParsedReq a, ParsedReq b, Redactor r, Set<String> ignoredHeaders) {
        List<Change> out = new ArrayList<>();
        if (!a.method.equals(b.method)) out.add(new Change('~', LOC_METHOD, "", a.method, b.method));

        if (a.segments.length == b.segments.length) {
            for (int i = 0; i < a.segments.length; i++) {
                if (!a.segments[i].equals(b.segments[i])) {
                    out.add(new Change('~', LOC_PATH, "[" + i + "]",
                            Redactor.clip(r.redactSegment(a.segments[i])), Redactor.clip(r.redactSegment(b.segments[i]))));
                }
            }
        } else {
            out.add(new Change('~', LOC_PATH, "", Redactor.clip(r.redactTarget(a.path)), Redactor.clip(r.redactTarget(b.path))));
        }

        diffMap(LOC_QUERY, a.query, b.query, r, false, out, null, null);
        diffMap(LOC_HEADER, a.headers, b.headers, r, false, out, ignoredHeaders, headerNames(a, b));
        diffMap(LOC_COOKIE, a.cookies, b.cookies, r, false, out, null, null);
        diffBody(a, b, r, out);
        return out;
    }

    /** Original spelling of header names: the new request's, or the original's for removed headers. */
    private static Map<String, String> headerNames(ParsedReq a, ParsedReq b) {
        if (a.headerDisplay.isEmpty()) return b.headerDisplay;
        Map<String, String> m = new java.util.HashMap<>(a.headerDisplay);
        m.putAll(b.headerDisplay);
        return m;
    }

    static void diffMap(int loc, Map<String, String> a, Map<String, String> b, Redactor r, boolean alwaysSensitive,
                        List<Change> out, Set<String> ignored, Map<String, String> display) {
        for (Map.Entry<String, String> e : a.entrySet()) {
            String k = e.getKey();
            if (ignored != null && ignored.contains(baseName(k))) continue;
            String nv = b.get(k);
            String name = safeName(displayName(k, display), r);
            if (nv == null) out.add(new Change('-', loc, name, null, null));
            else if (!nv.equals(e.getValue())) {
                boolean sens = alwaysSensitive || r.masked(k);
                out.add(new Change('~', loc, name, r.display(k, e.getValue(), sens), r.display(k, nv, sens)));
            }
        }
        for (Map.Entry<String, String> e : b.entrySet()) {
            String k = e.getKey();
            if (ignored != null && ignored.contains(baseName(k))) continue;
            if (!a.containsKey(k)) {
                out.add(new Change('+', loc, safeName(displayName(k, display), r), null, r.display(k, e.getValue(), alwaysSensitive)));
            }
        }
    }

    /** Field name for the log (one line, clipped). */
    private static String safeName(String name, Redactor r) {
        return Redactor.clip(name);
    }

    private static String baseName(String k) {
        int h = k.indexOf('#');
        return h > 0 ? k.substring(0, h) : k;
    }

    private static String displayName(String k, Map<String, String> display) {
        if (display == null) return k;
        String base = baseName(k);
        String d = display.get(base);
        if (d == null) return k;
        return k.length() == base.length() ? d : d + k.substring(base.length());
    }

    /**
     * Names of differing fields only (no values, no redaction, no formatting): used by Intruder when the differing span
     * spans several fields (pitchfork, battering ram). Names match {@link FieldLocator}.
     */
    public static List<FieldLocator.Field> changedFields(ParsedReq a, ParsedReq b, Set<String> ignoredHeaders) {
        List<FieldLocator.Field> out = new ArrayList<>();
        if (!a.method.equals(b.method)) out.add(new FieldLocator.Field(LOC_METHOD, ""));
        if (a.segments.length == b.segments.length) {
            for (int i = 0; i < a.segments.length; i++) {
                if (!a.segments[i].equals(b.segments[i])) out.add(new FieldLocator.Field(LOC_PATH, "[" + i + "]"));
            }
        } else {
            // payload contains '/': segment count changes; the payload position is the first differing segment
            int i = 0, n = Math.min(a.segments.length, b.segments.length);
            while (i < n && a.segments[i].equals(b.segments[i])) i++;
            out.add(new FieldLocator.Field(LOC_PATH, "[" + i + "]"));
        }
        changedKeys(LOC_QUERY, a.query, b.query, null, null, out, false);
        changedKeys(LOC_HEADER, a.headers, b.headers, ignoredHeaders, a.headerDisplay, out, false);
        changedKeys(LOC_COOKIE, a.cookies, b.cookies, null, null, out, false);
        if (a.bodyKind == b.bodyKind && a.bodyHash == b.bodyHash && a.bodySize == b.bodySize) return out;
        boolean structured = a.bodyKind == ParsedReq.BodyKind.JSON || a.bodyKind == ParsedReq.BodyKind.FORM
                || a.bodyKind == ParsedReq.BodyKind.MULTIPART;
        if (a.bodyKind == b.bodyKind && structured) {
            changedKeys(LOC_BODY, a.bodyFields, b.bodyFields, null, null, out, false);
        } else if (a.bodyKind == ParsedReq.BodyKind.TEXT && b.bodyKind == ParsedReq.BodyKind.TEXT) {
            // XML / text: extract name → value pairs (password=x, <pin>x, "k": "x") and compare like a structured body,
            // so battering ram across several XML fields sees every position
            int before = out.size();
            // only names present in both requests: a name on one side only is usually payload content (e.g. "1=1")
            changedKeys(LOC_BODY, textFields(a.bodyText), textFields(b.bodyText), null, null, out, true);
            if (out.size() == before) out.add(new FieldLocator.Field(LOC_BODY, FieldLocator.WHOLE_BODY));
        } else {
            out.add(new FieldLocator.Field(LOC_BODY, FieldLocator.WHOLE_BODY));
        }
        return out;
    }

    /**
     * Names of keys whose value changed. A key removed and a new key added together means the payload is in the key
     * name itself (param name fuzzing): record one generic name instead of each payload.
     */
    private static void changedKeys(int loc, Map<String, String> a, Map<String, String> b, Set<String> ignored,
                                    Map<String, String> display, List<FieldLocator.Field> out, boolean bothSidesOnly) {
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<String> removed = new ArrayList<>(), added = new ArrayList<>();
        for (Map.Entry<String, String> e : a.entrySet()) {
            String base = baseName(e.getKey());
            if (ignored != null && ignored.contains(base)) continue;
            String nv = b.get(e.getKey());
            if (nv == null) removed.add(base);
            else if (!e.getValue().equals(nv) && seen.add(base)) out.add(new FieldLocator.Field(loc, shown(base, display)));
        }
        for (String k : b.keySet()) {
            String base = baseName(k);
            if (ignored != null && ignored.contains(base)) continue;
            if (!a.containsKey(k)) added.add(base);
        }
        if (bothSidesOnly) return;
        if (!removed.isEmpty() && !added.isEmpty()) {
            out.add(new FieldLocator.Field(loc, FieldLocator.nameFuzz(loc)));
            return;
        }
        for (String k : removed) if (seen.add(k)) out.add(new FieldLocator.Field(loc, shown(k, display)));
        for (String k : added) if (seen.add(k)) out.add(new FieldLocator.Field(loc, shown(k, display)));
    }

    /**
     * Number of structural changes between two requests (method, path segment count, keys added / removed in query /
     * header / cookie / body, body kind). Intruder only changes values at payload positions, so two requests of one
     * attack have almost no structural changes; two different endpoints have many.
     */
    public static int structuralChanges(ParsedReq a, ParsedReq b, Set<String> ignoredHeaders) {
        int n = 0;
        if (!a.method.equals(b.method)) n++;
        if (a.segments.length != b.segments.length) n++;
        n += keyDelta(a.query, b.query, null);
        n += keyDelta(a.headers, b.headers, ignoredHeaders);
        n += keyDelta(a.cookies, b.cookies, null);
        if (a.bodyKind != b.bodyKind) n++;
        else n += keyDelta(a.bodyFields, b.bodyFields, null);
        return n;
    }

    private static int keyDelta(Map<String, String> a, Map<String, String> b, Set<String> ignored) {
        int n = 0;
        for (String k : a.keySet()) if (!b.containsKey(k) && (ignored == null || !ignored.contains(baseName(k)))) n++;
        for (String k : b.keySet()) if (!a.containsKey(k) && (ignored == null || !ignored.contains(baseName(k)))) n++;
        return n;
    }

    /** Name → value pairs in free text: each value token that follows a name ({@link Redactor#nameBefore}). */
    static Map<String, String> textFields(String s) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        if (s == null) return out;
        int i = 0, n = s.length();
        while (i < n && out.size() < ParsedReq.JSON_MAX_FIELDS) {
            if (!Redactor.valueChar(s.charAt(i))) { i++; continue; }
            int a = i;
            while (i < n && Redactor.valueChar(s.charAt(i))) i++;
            String name = Redactor.nameBefore(s, a);
            if (name != null) ParsedReq.putOcc(out, name, s.substring(a, i));
        }
        return out;
    }

    private static String shown(String base, Map<String, String> display) {
        if (display == null) return base;
        String d = display.get(base);
        return d == null ? base : d;
    }

    static void diffBody(ParsedReq a, ParsedReq b, Redactor r, List<Change> out) {
        if (a.bodyKind == b.bodyKind && a.bodyHash == b.bodyHash && a.bodySize == b.bodySize) return;
        boolean structuredA = a.bodyKind == ParsedReq.BodyKind.JSON || a.bodyKind == ParsedReq.BodyKind.FORM
                || a.bodyKind == ParsedReq.BodyKind.MULTIPART;
        if (a.bodyKind == b.bodyKind && structuredA) {
            int before = out.size();
            diffMap(LOC_BODY, a.bodyFields, b.bodyFields, r, false, out, null, null);
            if (out.size() == before) {
                // same logical content, only formatting differs (whitespace, key order)
                out.add(new Change('~', LOC_BODY, FORMAT_ONLY, size(a.bodySize), size(b.bodySize)));
            }
            return;
        }
        if (a.bodyKind == ParsedReq.BodyKind.TEXT && b.bodyKind == ParsedReq.BodyKind.TEXT) {
            out.add(textChange(a.bodyText, b.bodyText, r));
            return;
        }
        if (b.bodyKind == ParsedReq.BodyKind.NONE) {
            out.add(new Change('-', LOC_BODY, "(" + kind(a) + ", " + size(a.bodySize) + ")", null, null));
            return;
        }
        if (a.bodyKind == ParsedReq.BodyKind.NONE) {
            out.add(new Change('+', LOC_BODY, "(" + kind(b) + ", " + size(b.bodySize) + ")", null, null));
            return;
        }
        out.add(new Change('~', LOC_BODY, "", kind(a) + " " + size(a.bodySize), kind(b) + " " + size(b.bodySize)));
    }

    /**
     * Text diff via common prefix/suffix. The differing span is widened to the value boundaries (to show the whole token)
     * and the name before it ({@code password=}, {@code <token>}, {@code "secret": "}) masks the span if that name is listed.
     */
    static Change textChange(String x, String y, Redactor r) {
        int p = 0, max = Math.min(x.length(), y.length());
        while (p < max && x.charAt(p) == y.charAt(p)) p++;
        int s = 0;
        while (s < max - p && x.charAt(x.length() - 1 - s) == y.charAt(y.length() - 1 - s)) s++;
        int start = p;
        while (start > 0 && p - start < MAX_VALUE_SCAN && Redactor.valueChar(x.charAt(start - 1))) start--;
        int endX = x.length() - s, endY = y.length() - s, ext = 0;
        while (ext < s && ext < MAX_VALUE_SCAN && Redactor.valueChar(x.charAt(endX + ext))) ext++;
        String mx = x.substring(start, endX + ext), my = y.substring(start, endY + ext);
        String name = Redactor.nameBefore(x, start);
        boolean sens = name != null && r.masked(name);
        String label = "@" + start + (name != null ? " " + Redactor.clip(name) : "");
        return new Change('~', LOC_BODY, label, sens ? r.fp(mx) : quoteSnippet(mx, r), sens ? r.fp(my) : quoteSnippet(my, r));
    }

    private static String quoteSnippet(String s, Redactor r) {
        String red = r.redactText(s);
        String c = red.length() > 60 ? red.substring(0, 60) + "…(+" + (red.length() - 60) + ")" : red;
        return "\"" + Redactor.clip(c) + "\"";
    }

    private static String kind(ParsedReq q) {
        switch (q.bodyKind) {
            case JSON: return "json";
            case FORM: return "form";
            case MULTIPART: return "multipart";
            case TEXT: return "text";
            case BINARY: return "binary";
            case LARGE: return "large";
            default: return "none";
        }
    }

    static String size(int n) {
        if (n < 1024) return n + " B";
        if (n < 1024 * 1024) return String.format("%.1f KB", n / 1024.0);
        return String.format("%.1f MB", n / (1024.0 * 1024));
    }

    public static int locMask(List<Change> changes) {
        int m = 0;
        for (Change c : changes) m |= c.loc();
        return m;
    }

    public static String format(List<Change> changes) {
        StringBuilder b = new StringBuilder();
        for (Change c : changes) {
            if (b.length() > 0) b.append('\n');
            b.append(c.format());
        }
        return b.toString();
    }
}
