package apitracker.core;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Locates the request field at a byte range without parsing the whole request. Used for Intruder: two consecutive
 * requests of an attack differ only at payload positions, so the common prefix / suffix (vectorized byte compare)
 * gives the differing range; this tells which field it is in (method, path segment, query, header, cookie, body field).
 * Field names match the ones {@link Diff} uses ({@code [3]}, {@code id}, {@code $.a.b[0]}, original header name), so
 * the fast path and slow path (full parse) give the same result.
 */
public final class FieldLocator {
    private FieldLocator() {}

    /** A payload position. loc is {@code Diff.LOC_*}; name is empty for the method. */
    public record Field(int loc, String name) {
        public String key() { return loc + ":" + name; }
    }

    /** Name for an unstructured body (binary, too large, text with no preceding name). */
    public static final String WHOLE_BODY = "(body)";

    /**
     * Payload is in the param / header / cookie / JSON key name itself (name fuzzing): record one generic name instead
     * of each payload, so payloads never reach the log.
     */
    public static String nameFuzz(int loc) {
        switch (loc) {
            case Diff.LOC_QUERY: return "(param name)";
            case Diff.LOC_HEADER: return "(header name)";
            case Diff.LOC_COOKIE: return "(cookie name)";
            default: return "(field name)";
        }
    }

    public static final int BODY_NONE = 0, BODY_JSON = 1, BODY_FORM = 2, BODY_MULTIPART = 3, BODY_TEXT = 4;

    /** Raw layout of a request: byte offsets, computed once per request (scans only the header). */
    public static final class Parts {
        public final int len;
        public final int lineEnd;      // end of request line (position of '\r' or '\n')
        public final int headEnd;      // start of the blank line ending the header
        public final int bodyStart;
        final int clS, clE;            // Content-Length line (incl. newline) or -1
        public final int bodyKind;

        Parts(int len, int lineEnd, int headEnd, int bodyStart, int clS, int clE, int bodyKind) {
            this.len = len; this.lineEnd = lineEnd; this.headEnd = headEnd; this.bodyStart = bodyStart;
            this.clS = clS; this.clE = clE; this.bodyKind = bodyKind;
        }

        /**
         * Chunks compared separately: [request line + headers before Content-Length], [headers after Content-Length],
         * [body]. The Content-Length line is skipped because Intruder updates it to match the payload length.
         */
        public int[][] chunks() {
            if (clS < 0) return new int[][]{{0, headEnd}, {bodyStart, len}};
            return new int[][]{{0, clS}, {clE, headEnd}, {bodyStart, len}};
        }
    }

    public static Parts parts(byte[] r) {
        int n = r.length;
        int lineEnd = indexOf(r, (byte) '\n', 0, n);
        if (lineEnd < 0) lineEnd = n;
        int le = lineEnd > 0 && r[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;
        int headEnd = n, bodyStart = n;
        for (int i = lineEnd; i < n; i++) {
            if (r[i] != '\n') continue;
            // blank line: "\n\n" or "\n\r\n"
            if (i + 1 < n && r[i + 1] == '\n') { headEnd = i + 1; bodyStart = i + 2; break; }
            if (i + 2 < n && r[i + 1] == '\r' && r[i + 2] == '\n') { headEnd = i + 1; bodyStart = i + 3; break; }
        }
        int clS = -1, clE = -1;
        String ct = "";
        int ls = lineEnd + 1;
        while (ls < headEnd) {
            int nl = indexOf(r, (byte) '\n', ls, headEnd);
            int next = nl < 0 ? headEnd : nl + 1;
            int colon = indexOf(r, (byte) ':', ls, next);
            if (colon > ls) {
                if (nameIs(r, ls, colon, "content-length")) { clS = ls; clE = next; }
                else if (nameIs(r, ls, colon, "content-type") && ct.isEmpty()) {
                    int e = nl < 0 ? headEnd : (nl > 0 && r[nl - 1] == '\r' ? nl - 1 : nl);
                    ct = latin1(r, colon + 1, e).trim().toLowerCase(Locale.ROOT);
                }
            }
            ls = next;
        }
        int kind = BODY_NONE;
        if (bodyStart < n) {
            if (ct.contains("multipart/form-data")) kind = BODY_MULTIPART;
            else if (ct.contains("x-www-form-urlencoded")) kind = BODY_FORM;
            else {
                int f = bodyStart;
                while (f < n && (r[f] == ' ' || r[f] == '\t' || r[f] == '\r' || r[f] == '\n')) f++;
                boolean looksJson = f < n && (r[f] == '{' || r[f] == '[');
                kind = (ct.contains("json") || (looksJson && !ct.contains("xml") && !ct.contains("html"))) ? BODY_JSON : BODY_TEXT;
            }
        }
        return new Parts(n, le, headEnd, bodyStart, clS, clE, kind);
    }

    /**
     * Field that fully contains range [from, to) of r (from == to: payload inserted at a point). null if the range spans
     * several fields or is uncertain: the caller then does a full parse.
     */
    public static Field locate(byte[] r, Parts p, int from, int to) {
        try {
            if (from < 0 || to < from || to > p.len) return null;
            if (from < p.lineEnd) return requestLine(r, p, from, to);
            if (from < p.headEnd) return header(r, p, from, to);
            if (from >= p.bodyStart) return body(r, p, from, to);
            return null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Field requestLine(byte[] r, Parts p, int from, int to) {
        int end = p.lineEnd;
        if (to > end) return null;
        int sp1 = indexOf(r, (byte) ' ', 0, end);
        if (sp1 < 0) return null;
        if (from < sp1) return to <= sp1 ? new Field(Diff.LOC_METHOD, "") : null;
        int sp2 = lastIndexOf(r, (byte) ' ', sp1 + 1, end);
        int tEnd = (sp2 > sp1 && startsWith(r, sp2 + 1, "HTTP/")) ? sp2 : end;
        int tStart = sp1 + 1;
        if (from < tStart || to > tEnd || tStart >= tEnd || r[tStart] != '/') return null;
        int q = indexOf(r, (byte) '?', tStart, tEnd);
        int frag = indexOf(r, (byte) '#', tStart, tEnd);
        if (frag >= 0 && (q < 0 || frag < q)) return null;
        int pathEnd = q < 0 ? tEnd : q;
        if (from < pathEnd || (from == pathEnd && q < 0)) {
            if (to > pathEnd) return null;
            if (from < pathEnd && r[from] == '/') return null;              // path structure changed
            int s0 = lastIndexOf(r, (byte) '/', tStart, from);
            int segStart = s0 < 0 ? tStart : s0 + 1;
            int segEnd = indexOf(r, (byte) '/', from, pathEnd);
            if (segEnd < 0) segEnd = pathEnd;
            if (to > segEnd || segStart == segEnd) return null;
            if (regionContainsIgnoreCase(r, segStart, segEnd, ";jsessionid=")) return null;
            int idx = 0;
            for (int k = tStart; k < segStart; k++) if (r[k] != '/' && (k == tStart || r[k - 1] == '/')) idx++;
            return new Field(Diff.LOC_PATH, "[" + idx + "]");
        }
        int fEnd = frag >= 0 ? frag : tEnd;
        if (to > fEnd) return null;
        return pairField(Diff.LOC_QUERY, r, q + 1, fEnd, from, to, (byte) '&', false);
    }

    private static Field header(byte[] r, Parts p, int from, int to) {
        if (r[from] == '\r' || r[from] == '\n') return null;
        int nl = lastIndexOf(r, (byte) '\n', 0, from);
        int ls = nl + 1;
        int le = indexOf(r, (byte) '\n', from, p.headEnd);
        if (le < 0) le = p.headEnd;
        if (le > ls && r[le - 1] == '\r') le--;
        if (to > le) return null;
        int colon = indexOf(r, (byte) ':', ls, le);
        if (colon <= ls) return null;
        String name = latin1(r, ls, colon).trim();
        if (name.isEmpty() || name.startsWith(":") || from < colon && to > colon) return null;
        if (from < colon || (from == colon && to == colon)) return new Field(Diff.LOC_HEADER, nameFuzz(Diff.LOC_HEADER));
        if (name.equalsIgnoreCase("cookie")) return pairField(Diff.LOC_COOKIE, r, colon + 1, le, from, to, (byte) ';', true);
        return new Field(Diff.LOC_HEADER, name);
    }

    private static Field body(byte[] r, Parts p, int from, int to) {
        int blen = p.len - p.bodyStart;
        if (blen > ParsedReq.DEFAULT_MAX_BODY || p.bodyKind == BODY_NONE) return new Field(Diff.LOC_BODY, WHOLE_BODY);
        switch (p.bodyKind) {
            case BODY_FORM:
                return pairField(Diff.LOC_BODY, r, p.bodyStart, p.len, from, to, (byte) '&', true);
            case BODY_JSON: {
                String path = JsonPath.at(r, p.bodyStart, p.len, from, to);
                return path == null ? null : new Field(Diff.LOC_BODY, path);
            }
            case BODY_TEXT: {
                if (!ParsedReq.isText(r, p.bodyStart, blen)) return new Field(Diff.LOC_BODY, WHOLE_BODY);
                int vs = from;
                while (vs > p.bodyStart && from - vs < 2048 && Redactor.valueChar((char) (r[vs - 1] & 0xFF))) vs--;
                int ve = from;
                while (ve < p.len && ve - from < 2048 && Redactor.valueChar((char) (r[ve] & 0xFF))) ve++;
                if (to > ve) return null;
                int ws = Math.max(p.bodyStart, vs - 128);
                String window = latin1(r, ws, vs);
                String name = Redactor.nameBefore(window, window.length());
                return new Field(Diff.LOC_BODY, name == null ? WHOLE_BODY : name);
            }
            default:
                return null;                                                  // multipart: full parse
        }
    }

    /**
     * Field of the k=v pair containing [from, to) within [start, end) separated by sep: payload in the value → pair
     * name; payload in the name → generic name {@link #nameFuzz}. null if it spans a separator or the '='.
     */
    private static Field pairField(int loc, byte[] r, int start, int end, int from, int to, byte sep, boolean trim) {
        if (from < start) return null;
        if (from < end && r[from] == sep && to > from) return null;
        int a = lastIndexOf(r, sep, start, from);
        a = a < 0 ? start : a + 1;
        int b = indexOf(r, sep, from, end);
        if (b < 0) b = end;
        if (to > b) return null;
        int eq = indexOf(r, (byte) '=', a, b);
        if (eq < 0 || from < eq || (from == eq && to == eq)) {
            if (eq >= 0 && to > eq) return null;                          // spans '='
            return new Field(loc, nameFuzz(loc));
        }
        if (from == eq) return null;                                      // the '=' itself changed
        String name = latin1(r, a, eq);
        if (trim) name = name.trim();
        return name.isBlank() ? null : new Field(loc, name);
    }

    // ---------- byte utilities ----------

    static int indexOf(byte[] r, byte c, int from, int to) {
        for (int i = Math.max(0, from); i < to; i++) if (r[i] == c) return i;
        return -1;
    }

    /** Last index of c in [from, to). */
    static int lastIndexOf(byte[] r, byte c, int from, int to) {
        for (int i = to - 1; i >= from; i--) if (r[i] == c) return i;
        return -1;
    }

    private static boolean startsWith(byte[] r, int at, String s) {
        if (at + s.length() > r.length) return false;
        for (int i = 0; i < s.length(); i++) if (r[at + i] != s.charAt(i)) return false;
        return true;
    }

    private static boolean nameIs(byte[] r, int from, int colon, String lower) {
        int a = from, b = colon;
        while (a < b && (r[a] == ' ' || r[a] == '\t')) a++;
        while (b > a && (r[b - 1] == ' ' || r[b - 1] == '\t')) b--;
        if (b - a != lower.length()) return false;
        for (int i = 0; i < lower.length(); i++) {
            int c = r[a + i] & 0xFF;
            if (c >= 'A' && c <= 'Z') c += 32;
            if (c != lower.charAt(i)) return false;
        }
        return true;
    }

    private static boolean regionContainsIgnoreCase(byte[] r, int from, int to, String lower) {
        outer:
        for (int i = from; i + lower.length() <= to; i++) {
            for (int k = 0; k < lower.length(); k++) {
                int c = r[i + k] & 0xFF;
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != lower.charAt(k)) continue outer;
            }
            return true;
        }
        return false;
    }

    static String latin1(byte[] r, int from, int to) {
        return new String(r, from, Math.max(0, to - from), StandardCharsets.ISO_8859_1);
    }

    // ---------- comparison ----------

    /** Common prefix length of a[aFrom, aTo) and b[bFrom, bTo) (Arrays.mismatch is vectorized). */
    public static int commonPrefix(byte[] a, int aFrom, int aTo, byte[] b, int bFrom, int bTo) {
        int m = java.util.Arrays.mismatch(a, aFrom, aTo, b, bFrom, bTo);
        return m < 0 ? aTo - aFrom : m;
    }

    /** Common suffix length, not overlapping the matched prefix (max). Compares 64-byte blocks first, then bytes. */
    public static int commonSuffix(byte[] a, int aFrom, int aTo, byte[] b, int bFrom, int bTo, int max) {
        int s = 0;
        while (s + 64 <= max && java.util.Arrays.equals(a, aTo - s - 64, aTo - s, b, bTo - s - 64, bTo - s)) s += 64;
        while (s < max && a[aTo - 1 - s] == b[bTo - 1 - s]) s++;
        return s;
    }

    // ---------- JSON ----------

    /**
     * JSON path (same format as {@link JsonFlattener}) of the leaf value fully containing [from, to). Scans from the
     * body start up to the position, then stops; the path is built only when found (no string allocated per key).
     */
    static final class JsonPath {
        private final byte[] b;
        private final int end, from, to;
        private int i, leaves;
        private final int[] keyS = new int[ParsedReq.JSON_MAX_DEPTH + 2], keyE = new int[ParsedReq.JSON_MAX_DEPTH + 2],
                idx = new int[ParsedReq.JSON_MAX_DEPTH + 2];
        private final boolean[] arr = new boolean[ParsedReq.JSON_MAX_DEPTH + 2];
        private String found;
        private boolean failed;

        private JsonPath(byte[] b, int start, int end, int from, int to) {
            this.b = b; this.i = start; this.end = end; this.from = from; this.to = to;
        }

        static String at(byte[] b, int start, int end, int from, int to) {
            JsonPath j = new JsonPath(b, start, end, from, to);
            try {
                j.ws();
                j.value(0);
            } catch (RuntimeException e) {
                return null;
            }
            return j.failed ? null : j.found;
        }

        private boolean done() { return found != null || failed; }

        /** Changed range starts before the current token (in whitespace / punctuation): cannot be located. */
        private boolean before(int tokenStart) {
            if (from < tokenStart) { failed = true; return true; }
            return false;
        }

        private boolean hit(int s, int e, int depth) {
            if (from >= s && to <= e) { found = path(depth); return true; }
            if (from < e) { failed = true; return true; }                     // starts inside the token but extends past it
            return false;
        }

        private void value(int depth) {
            ws();
            if (i >= end) throw new IllegalStateException();
            if (before(i)) return;
            byte c = b[i];
            if (c == '{' || c == '[') {
                if (depth >= ParsedReq.JSON_MAX_DEPTH) {
                    int s = i;
                    skipContainer();
                    leaf(s, i, depth);
                    return;
                }
                if (c == '{') object(depth); else array(depth);
            } else if (c == '"') {
                int s = i;
                skipString();
                leaf(s, i, depth);
            } else {
                int s = i;
                while (i < end && ",}] \t\r\n".indexOf(b[i]) < 0) i++;
                if (i == s) throw new IllegalStateException();
                leaf(s, i, depth);
            }
        }

        private void leaf(int s, int e, int depth) {
            if (++leaves > ParsedReq.JSON_MAX_FIELDS) { failed = true; return; }
            hit(s, e, depth);
        }

        private void object(int depth) {
            int s = i;
            i++;
            ws();
            if (i < end && b[i] == '}') { i++; leaf(s, i, depth); return; }
            while (!done()) {
                ws();
                if (i >= end || b[i] != '"') throw new IllegalStateException();
                if (before(i)) return;
                int ks = i;
                skipString();
                int ke = i;
                keyS[depth + 1] = ks + 1; keyE[depth + 1] = ke - 1; arr[depth + 1] = false;
                if (from >= ks && to <= ke) { found = nameFuzz(Diff.LOC_BODY); return; }   // payload in the key name
                if (from < ke) { failed = true; return; }
                ws();
                if (i >= end || b[i] != ':') throw new IllegalStateException();
                i++;
                value(depth + 1);
                if (done()) return;
                ws();
                if (i >= end) throw new IllegalStateException();
                if (b[i] == ',') { i++; continue; }
                if (b[i] == '}') { i++; return; }
                throw new IllegalStateException();
            }
        }

        private void array(int depth) {
            int s = i;
            i++;
            ws();
            if (i < end && b[i] == ']') { i++; leaf(s, i, depth); return; }
            int n = 0;
            while (!done()) {
                arr[depth + 1] = true; idx[depth + 1] = n++;
                value(depth + 1);
                if (done()) return;
                ws();
                if (i >= end) throw new IllegalStateException();
                if (b[i] == ',') { i++; continue; }
                if (b[i] == ']') { i++; return; }
                throw new IllegalStateException();
            }
        }

        private String path(int depth) {
            String p = "$";
            for (int d = 1; d <= depth; d++) {
                if (arr[d]) p = p + '[' + idx[d] + ']';
                else {
                    String raw = new String(b, keyS[d], keyE[d] - keyS[d], StandardCharsets.UTF_8);
                    p = JsonFlattener.childPath(p, raw.indexOf('\\') < 0 ? raw : JsonFlattener.unescape(raw));
                }
            }
            return p;
        }

        private void ws() {
            while (i < end && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r')) i++;
        }

        private void skipString() {
            i++;
            while (i < end) {
                byte c = b[i++];
                if (c == '\\') { i++; continue; }
                if (c == '"') return;
            }
            throw new IllegalStateException();
        }

        private void skipContainer() {
            int depth = 0;
            while (i < end) {
                byte c = b[i];
                if (c == '"') { skipString(); continue; }
                if (c == '{' || c == '[') depth++;
                else if (c == '}' || c == ']') {
                    depth--;
                    if (depth == 0) { i++; return; }
                }
                i++;
            }
            throw new IllegalStateException();
        }
    }
}
