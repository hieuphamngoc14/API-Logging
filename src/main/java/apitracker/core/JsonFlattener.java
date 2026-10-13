package apitracker.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Single-pass JSON parser that flattens into a path → value map.
 * <ul>
 *   <li>Paths look like {@code $.a.b[0]}; keys with unusual chars look like {@code $["a b"]}.</li>
 *   <li>String values keep their quotes ({@code "100"}) to distinguish them from numbers ({@code 100}).</li>
 *   <li>An empty object/array is a leaf ({@code {}} / {@code []}) so added fields are visible.</li>
 *   <li>Deeper than {@code maxDepth}: the whole branch becomes one {@code #hash} leaf. Past {@code maxFields}: the rest
 *       is merged into one {@code $…} leaf.</li>
 * </ul>
 * Builds no object tree, uses no external libraries. Malformed JSON throws {@link IllegalArgumentException}.
 */
public final class JsonFlattener {
    private final String s;
    private final int maxDepth;
    private final int maxFields;
    private final Map<String, String> out = new LinkedHashMap<>();
    private int i;
    private boolean truncated;
    private long restHash = 1125899906842597L;

    private JsonFlattener(String s, int maxDepth, int maxFields) {
        this.s = s;
        this.maxDepth = maxDepth;
        this.maxFields = maxFields;
    }

    public static Map<String, String> flatten(String json, int maxDepth, int maxFields) {
        JsonFlattener f = new JsonFlattener(json, maxDepth, maxFields);
        f.skipWs();
        if (f.i >= f.s.length()) throw new IllegalArgumentException("empty");
        f.value("$", 0);
        f.skipWs();
        if (f.i != f.s.length()) throw new IllegalArgumentException("trailing data at " + f.i);
        if (f.truncated) f.out.put("$…", "#" + Long.toHexString(f.restHash));
        return f.out;
    }

    private void put(String path, String v) {
        if (truncated || out.size() >= maxFields) {
            truncated = true;
            restHash = 31 * restHash + path.hashCode() * 17L + v.hashCode();
            return;
        }
        out.put(path, v);
    }

    private void value(String path, int depth) {
        skipWs();
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end");
        char c = s.charAt(i);
        if (c == '{' || c == '[') {
            if (depth >= maxDepth) {
                int start = i;
                skipValue();
                put(path, "#" + Integer.toHexString(s.substring(start, i).hashCode()));
                return;
            }
            if (c == '{') object(path, depth); else array(path, depth);
        } else if (c == '"') {
            int start = i;
            skipString();
            put(path, s.substring(start, i));
        } else {
            int start = i;
            while (i < s.length() && ",}] \t\r\n".indexOf(s.charAt(i)) < 0) i++;
            String lit = s.substring(start, i);
            if (lit.isEmpty() || !validLiteral(lit)) throw new IllegalArgumentException("bad literal at " + start);
            put(path, lit);
        }
    }

    private static boolean validLiteral(String lit) {
        if (lit.equals("true") || lit.equals("false") || lit.equals("null")) return true;
        char c = lit.charAt(0);
        if (!(c == '-' || (c >= '0' && c <= '9'))) return false;
        for (int k = 1; k < lit.length(); k++) {
            char d = lit.charAt(k);
            if (!((d >= '0' && d <= '9') || d == '.' || d == 'e' || d == 'E' || d == '+' || d == '-')) return false;
        }
        return true;
    }

    private void object(String path, int depth) {
        i++; // {
        skipWs();
        if (peek() == '}') { i++; put(path, "{}"); return; }
        while (true) {
            skipWs();
            if (peek() != '"') throw new IllegalArgumentException("expected key at " + i);
            String key = readString();
            skipWs();
            if (peek() != ':') throw new IllegalArgumentException("expected ':' at " + i);
            i++;
            value(childPath(path, key), depth + 1);
            skipWs();
            char c = peek();
            if (c == ',') { i++; continue; }
            if (c == '}') { i++; return; }
            throw new IllegalArgumentException("expected ',' or '}' at " + i);
        }
    }

    private void array(String path, int depth) {
        i++; // [
        skipWs();
        if (peek() == ']') { i++; put(path, "[]"); return; }
        int idx = 0;
        while (true) {
            value(path + '[' + idx++ + ']', depth + 1);
            skipWs();
            char c = peek();
            if (c == ',') { i++; continue; }
            if (c == ']') { i++; return; }
            throw new IllegalArgumentException("expected ',' or ']' at " + i);
        }
    }

    static String childPath(String parent, String key) {
        boolean simple = !key.isEmpty();
        for (int k = 0; k < key.length() && simple; k++) {
            char c = key.charAt(k);
            simple = Character.isLetterOrDigit(c) || c == '_' || c == '-' || c == '$';
        }
        if (simple) return parent + '.' + key;
        return parent + "[\"" + key.replace("\\", "\\\\").replace("\"", "\\\"") + "\"]";
    }

    private char peek() {
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end");
        return s.charAt(i);
    }

    private void skipWs() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++; else break;
        }
    }

    private void skipString() {
        i++; // "
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '\\') { i++; continue; }
            if (c == '"') return;
        }
        throw new IllegalArgumentException("unterminated string");
    }

    private String readString() {
        int start = i + 1;
        skipString();
        String raw = s.substring(start, i - 1);
        return raw.indexOf('\\') < 0 ? raw : unescape(raw);
    }

    static String unescape(String raw) {
        StringBuilder b = new StringBuilder(raw.length());
        for (int k = 0; k < raw.length(); k++) {
            char c = raw.charAt(k);
            if (c != '\\' || k + 1 >= raw.length()) { b.append(c); continue; }
            char e = raw.charAt(++k);
            switch (e) {
                case 'n': b.append('\n'); break;
                case 't': b.append('\t'); break;
                case 'r': b.append('\r'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'u':
                    if (k + 4 < raw.length()) {
                        try { b.append((char) Integer.parseInt(raw.substring(k + 1, k + 5), 16)); k += 4; }
                        catch (NumberFormatException ex) { b.append("\\u"); }
                    } else b.append("\\u");
                    break;
                default: b.append(e);
            }
        }
        return b.toString();
    }

    private void skipValue() {
        int depth = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '"') { skipString(); continue; }
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') {
                depth--;
                if (depth == 0) { i++; return; }
            }
            i++;
        }
        throw new IllegalArgumentException("unterminated container");
    }
}
