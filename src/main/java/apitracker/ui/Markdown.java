package apitracker.ui;

import apitracker.core.HttpText;
import apitracker.core.ParsedReq;
import apitracker.core.Redactor;
import apitracker.store.Repo;
import apitracker.store.Rows;
import apitracker.store.Zip;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Markdown export of the log for an AI. Per API: a summary of what was tested (fields modified / removed / added, values
 * tried, Intruder positions) and which fields of the original were never touched, the original request(s) with their
 * full request and response, then every test in order with its changes and response. Reads the DB: call off the EDT.
 */
final class Markdown {
    private Markdown() {}

    /** Cap per HTTP message in the export (the full text stays in the DB). */
    static final int MAX_MESSAGE_CHARS = 8_000;
    /** Max sends exported per API (the most recent ones). */
    static final int MAX_SENDS = 2_000;
    private static final int MAX_VALUES = 8;
    private static final int MAX_UNTOUCHED = 60;
    private static final Set<String> LOCS = Set.of("method", "path", "query", "header", "cookie", "body");

    /** One untested API seen in Proxy history (for the full export). */
    record Untested(String method, String url, int requests) {}

    /** Short guide placed once at the top so the AI knows how to read the rest. */
    static String legend() {
        return """
                How to read this log (exported by the API Logging Burp extension):
                - Each API has one or more **original requests** (the baseline, shown with full request and response),
                  then every **test** sent from Repeater, an AI agent, or Intruder, in order.
                - A test lists what differs from its original: `~` modified (`old → new`), `-` removed, `+` added,
                  `§` Intruder payload position. Locations: method, path, query, header, cookie, body (`$.a.b` = JSON field).
                - `→ 403 · 82 B · 699 ms` is the response status, size and time of that test.
                - `<#a1b2c3d4>` is a masked value (field listed under Masked fields), `<userA>` a labeled token.
                - "What was tested" summarizes the tests; "Never modified" lists fields of the original no test touched yet.
                """;
    }

    /** Export of one API. */
    static String api(Repo repo, Rows.ApiRow api, Redactor r, Set<String> ignoredHeaders) throws SQLException {
        SimpleDateFormat full = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        SimpleDateFormat time = new SimpleDateFormat("HH:mm:ss");
        List<Rows.OriginalRow> origs = repo.originals(api.id());
        List<Rows.SendRow> sends = allSends(repo, api.id());
        Collections.reverse(sends);                                          // oldest first: the order things happened
        Map<Integer, Integer> origNo = new LinkedHashMap<>();
        for (Rows.OriginalRow o : origs) origNo.put(o.id(), ApiView.number(o));

        StringBuilder b = new StringBuilder(8192);
        b.append("## ").append(api.method()).append(' ').append(api.pathKey()).append("\n\n");
        b.append("- Host: `").append(api.hostKey()).append("`\n");
        b.append("- Status: ").append(api.tested() ? "tested" : "not tested yet (no send changed anything meaningful)").append('\n');
        b.append("- Tests: ").append(sourceSummary(sends)).append('\n');
        String statuses = statusSummary(sends);
        if (!statuses.isEmpty()) b.append("- Responses seen: ").append(statuses).append('\n');

        // ---- what was tested
        Coverage cov = new Coverage();
        for (Rows.SendRow s : sends) cov.add(s);
        heading(b, "### What was tested");
        if (cov.isEmpty()) b.append("- nothing changed vs the original yet\n");
        else for (String line : cov.lines()) b.append("- ").append(line).append('\n');
        if (!origs.isEmpty()) {
            List<String> untouched = untouched(repo, origs.get(0), cov, ignoredHeaders);
            if (!untouched.isEmpty()) {
                b.append("\nNever modified (fields of original #").append(ApiView.number(origs.get(0))).append("): ");
                int n = Math.min(untouched.size(), MAX_UNTOUCHED);
                b.append(String.join(", ", untouched.subList(0, n)));
                if (untouched.size() > n) b.append(", … +").append(untouched.size() - n).append(" more");
                b.append('\n');
            }
        }

        // ---- original requests with request + response
        for (Rows.OriginalRow o : origs) {
            heading(b, "### Original request #" + ApiView.number(o) + " (" + Rows.originalSourceName(o.source()) + ", "
                    + full.format(new Date(o.ts())) + ")");
            String[] text = repo.originalText(o.id());
            String req = text == null ? null : text[0];
            if (req == null) req = rawRequestText(repo, o.id());
            String resp = text == null ? null : text[1];
            b.append("Request:\n").append(fence(req == null ? null : r.maskHttp(req), "(not stored)"));
            b.append("Response:\n").append(fence(resp == null ? null : r.maskHttp(resp),
                    "(not stored: logged before response capture existed, no matching Proxy entry, or raw storage is off)"));
        }

        // ---- tests
        heading(b, "### Tests (oldest first)");
        if (sends.isEmpty()) b.append("(none yet)\n");
        else {
            b.append("```\n");
            boolean manyOriginals = origs.size() > 1;
            for (Rows.SendRow s : sends) {
                boolean intr = (s.flags() & Rows.FLAG_INTRUDER) != 0;
                b.append('#').append(ApiView.number(s)).append("  ").append(time.format(new Date(s.ts()))).append("  ")
                        .append(sourceName(s)).append("  ").append(s.firstLine());
                if (manyOriginals && s.originalId() > 0 && !intr) {
                    b.append("   (vs original #").append(origNo.getOrDefault(s.originalId(), s.originalId())).append(')');
                }
                if (!intr) b.append("   ").append(responseText(s));
                b.append('\n');
                String ch = s.changes();
                if (ch == null || ch.isEmpty()) b.append("    ").append(emptyText(s)).append('\n');
                else for (String line : ch.split("\n")) b.append("    ").append(line).append('\n');
            }
            b.append("```\n");
            if (api.sendCount() > sends.size()) {
                b.append("(only the most recent ").append(sends.size()).append(" of ").append(api.sendCount()).append(" tests are included)\n");
            }
        }
        return b.toString();
    }

    /** Full export: guide, overview, every API, then the in-scope APIs from Proxy history that were never tested. */
    static String all(Repo repo, String project, List<Rows.ApiRow> apis, List<Untested> untested, Redactor r,
                      Set<String> ignoredHeaders) throws SQLException {
        StringBuilder b = new StringBuilder(64 * 1024);
        b.append("# API test log — ").append(project).append(" (exported ")
                .append(new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date())).append(")\n\n");
        b.append(legend()).append('\n');
        int tested = 0, sends = 0;
        for (Rows.ApiRow a : apis) { if (a.tested()) tested++; sends += a.sendCount(); }
        b.append("## Overview\n\n");
        b.append("- ").append(apis.size()).append(apis.size() == 1 ? " API" : " APIs").append(" with a log: ").append(tested)
                .append(" tested, ").append(apis.size() - tested).append(" sent but not tested; ").append(sends)
                .append(sends == 1 ? " test" : " tests").append(" in total\n");
        b.append("- ").append(untested.size()).append(untested.size() == 1 ? " API" : " APIs")
                .append(" in scope seen in Proxy history but never tested (listed at the end)\n\n");
        for (Rows.ApiRow a : apis) b.append(api(repo, a, r, ignoredHeaders)).append("\n---\n\n");
        b.append("## Untested APIs in scope (from Proxy history)\n\n");
        if (untested.isEmpty()) b.append("(none)\n");
        for (Untested u : untested) {
            b.append("- ").append(u.method()).append(' ').append(u.url()).append(" (").append(u.requests())
                    .append(u.requests() == 1 ? " request" : " requests").append(")\n");
        }
        return b.toString();
    }

    // ---------- helpers ----------

    /** Heading preceded by exactly one blank line. */
    private static void heading(StringBuilder b, String h) {
        while (b.length() > 0 && b.charAt(b.length() - 1) == '\n') b.setLength(b.length() - 1);
        b.append("\n\n").append(h).append("\n\n");
    }

    private static List<Rows.SendRow> allSends(Repo repo, int apiId) throws SQLException {
        List<Rows.SendRow> all = new ArrayList<>();
        long before = Long.MAX_VALUE;
        while (all.size() < MAX_SENDS) {
            List<Rows.SendRow> page = repo.page(apiId, before, 500, Repo.Filter.ALL);
            all.addAll(page);
            if (page.size() < 500) break;
            before = page.get(page.size() - 1).id();
        }
        return all.size() > MAX_SENDS ? new ArrayList<>(all.subList(0, MAX_SENDS)) : all;
    }

    private static String rawRequestText(Repo repo, int originalId) throws SQLException {
        Repo.RawReq rr = repo.originalRaw(originalId);
        byte[] raw = rr == null ? null : Zip.inflate(rr.requestZ());
        return raw == null ? null : HttpText.of(raw, HttpText.MAX_CHARS);
    }

    private static String fence(String text, String missing) {
        if (text == null || text.isEmpty()) return missing + "\n\n";
        String t = text;
        if (t.length() > MAX_MESSAGE_CHARS) {
            t = t.substring(0, MAX_MESSAGE_CHARS) + "\n… [cut at " + String.format("%,d", MAX_MESSAGE_CHARS) + " of "
                    + String.format("%,d", text.length()) + " characters]";
        }
        String f = t.contains("```") ? "~~~~" : "```";
        return f + "http\n" + t + (t.endsWith("\n") ? "" : "\n") + f + "\n\n";
    }

    static String sourceName(Rows.SendRow s) {
        if ((s.flags() & Rows.FLAG_INTRUDER) != 0) return "[Intruder]";
        if ("repeater".equals(s.source())) return "[Repeater]";
        return s.source().startsWith("ai:") ? "[AI:" + s.source().substring(3) + "]" : "[AI]";
    }

    private static String sourceSummary(List<Rows.SendRow> sends) {
        int rep = 0, ai = 0, intr = 0;
        for (Rows.SendRow s : sends) {
            if ((s.flags() & Rows.FLAG_INTRUDER) != 0) intr++;
            else if ("repeater".equals(s.source())) rep++;
            else ai++;
        }
        List<String> parts = new ArrayList<>();
        if (rep > 0) parts.add("Repeater " + rep);
        if (ai > 0) parts.add("AI " + ai);
        if (intr > 0) parts.add("Intruder " + intr + (intr == 1 ? " attack" : " attacks"));
        return sends.size() + (sends.size() == 1 ? " test" : " tests") + (parts.isEmpty() ? "" : " (" + String.join(", ", parts) + ")");
    }

    private static String statusSummary(List<Rows.SendRow> sends) {
        TreeMap<Integer, Integer> n = new TreeMap<>();
        int none = 0;
        for (Rows.SendRow s : sends) {
            if ((s.flags() & Rows.FLAG_INTRUDER) != 0) continue;               // Intruder stats are in its own line
            if (s.status() <= 0) none++; else n.merge(s.status(), 1, Integer::sum);
        }
        List<String> parts = new ArrayList<>();
        n.forEach((st, c) -> parts.add(st + "×" + c));
        if (none > 0) parts.add("no response×" + none);
        return String.join(", ", parts);
    }

    private static String responseText(Rows.SendRow s) {
        StringBuilder b = new StringBuilder("→ ");
        if ((s.flags() & Rows.FLAG_NO_RESPONSE) != 0 || s.status() <= 0) b.append("no response");
        else {
            b.append(s.status()).append(" · ").append(String.format("%,d B", Math.max(0, s.length())));
            if (s.ms() >= 0) b.append(" · ").append(s.ms()).append(" ms");
        }
        if ((s.flags() & Rows.FLAG_REDIRECT) != 0) b.append("  [auto-followed redirect]");
        return b.toString();
    }

    private static String emptyText(Rows.SendRow s) {
        if ((s.flags() & Rows.FLAG_NO_ORIGINAL) != 0) return "(no original yet: sent by the AI, logged without diff)";
        if ((s.flags() & Rows.FLAG_SELF_ORIGINAL) != 0) return "(first send, used as the original)";
        if ((s.flags() & Rows.FLAG_ORIGINAL_UNAVAILABLE) != 0) return "(original unreadable: no diff)";
        return "(identical to the original)";
    }

    /** Fields of the original that no test modified, removed, added or fuzzed. */
    private static List<String> untouched(Repo repo, Rows.OriginalRow o, Coverage cov, Set<String> ignoredHeaders) throws SQLException {
        Repo.RawReq rr = repo.originalRaw(o.id());
        byte[] raw = rr == null ? null : Zip.inflate(rr.requestZ());
        List<String> out = new ArrayList<>();
        if (raw == null) return out;
        ParsedReq p = ParsedReq.parse(raw);
        for (String k : p.query.keySet()) if (!cov.touched("query", k)) out.add("query `" + k + "`");
        for (String k : p.headers.keySet()) {
            String base = base(k);
            if (ignoredHeaders.contains(base) || cov.touched("header", k)) continue;
            String shown = p.headerDisplay.getOrDefault(base, base);
            out.add("header `" + shown + (k.length() > base.length() ? k.substring(base.length()) : "") + "`");
        }
        for (String k : p.cookies.keySet()) if (!cov.touched("cookie", k)) out.add("cookie `" + k + "`");
        if (!cov.wholeBody) for (String k : p.bodyFields.keySet()) if (!cov.touched("body", k)) out.add("body `" + k + "`");
        return out;
    }

    private static String base(String k) {
        int h = k.indexOf('#');
        return h > 0 ? k.substring(0, h) : k;
    }

    /** Aggregates the change lines of all tests: per location + field, what was done and which values were tried. */
    static final class Coverage {
        private static final class Field {
            final String loc, name;
            int modified, removed, added, fuzzed;
            final Set<String> values = new LinkedHashSet<>();
            Field(String loc, String name) { this.loc = loc; this.name = name; }
        }
        private final Map<String, Field> fields = new LinkedHashMap<>();
        private final Set<String> touched = new java.util.HashSet<>();
        private final Set<String> methods = new LinkedHashSet<>();
        private final Set<String> paths = new LinkedHashSet<>();
        private int attacks, attackRequests;
        boolean wholeBody;

        boolean isEmpty() { return fields.isEmpty() && methods.isEmpty() && paths.isEmpty() && attacks == 0; }

        boolean touched(String loc, String name) {
            return touched.contains(loc + " " + name.toLowerCase(Locale.ROOT))
                    || touched.contains(loc + " " + base(name).toLowerCase(Locale.ROOT));
        }

        void add(Rows.SendRow s) {
            String ch = s.changes();
            if (ch == null || ch.isEmpty()) return;
            if ((s.flags() & Rows.FLAG_INTRUDER) != 0) {
                attacks++;
                attackRequests += intruderRequests(ch);
            }
            for (String line : ch.split("\n")) {
                if (line.length() < 3 || line.charAt(1) != ' ' || "+-~§".indexOf(line.charAt(0)) < 0) continue;
                char op = line.charAt(0);
                int le = 2;
                while (le < line.length() && Character.isLetter(line.charAt(le))) le++;
                String loc = line.substring(2, le);
                if (!LOCS.contains(loc)) continue;
                String rest = line.substring(le).stripLeading();
                if (loc.equals("method")) {                                   // "~ method   GET → POST"
                    methods.add(rest);
                    continue;
                }
                if (loc.equals("path") && !rest.startsWith("[") && op != '§') {   // whole path replaced
                    int a = rest.indexOf(" → ");
                    paths.add(a > 0 ? rest.substring(a + 3) : rest);
                    continue;
                }
                if (loc.equals("body") && op == '~' && (rest.startsWith("json ") || rest.startsWith("form ")
                        || rest.startsWith("text ") || rest.startsWith("multipart ") || rest.startsWith("binary "))) {
                    wholeBody = true;                                         // body type changed
                }
                String name, value = null;
                if (op == '~') {
                    int a = rest.indexOf("   ");
                    name = a < 0 ? rest : rest.substring(0, a);
                    int arrow = rest.indexOf(" → ", Math.max(0, a));
                    if (arrow > 0) value = rest.substring(arrow + 3);
                } else if (op == '+') {
                    int a = rest.indexOf(" = ");
                    name = a < 0 ? rest : rest.substring(0, a);
                    if (a > 0) value = rest.substring(a + 3);
                } else {
                    name = rest;
                }
                if (name.isEmpty()) continue;
                Field f = fields.computeIfAbsent(loc + " " + name, k -> new Field(loc, name));
                switch (op) {
                    case '~' -> f.modified++;
                    case '-' -> f.removed++;
                    case '+' -> f.added++;
                    default -> f.fuzzed++;
                }
                if (value != null && f.values.size() < MAX_VALUES) f.values.add(clip(value));
                touched.add(loc + " " + name.toLowerCase(Locale.ROOT));
                touched.add(loc + " " + base(name).toLowerCase(Locale.ROOT));
            }
        }

        private static int intruderRequests(String changes) {
            int i = changes.lastIndexOf("→ ");
            if (i < 0) return 0;
            int j = i + 2, n = 0;
            while (j < changes.length() && (Character.isDigit(changes.charAt(j)) || changes.charAt(j) == ',')) {
                if (changes.charAt(j) != ',') n = n * 10 + (changes.charAt(j) - '0');
                j++;
            }
            return n;
        }

        private static String clip(String v) {
            return v.length() > 40 ? v.substring(0, 39) + "…" : v;
        }

        List<String> lines() {
            List<String> out = new ArrayList<>();
            for (String m : methods) out.add("method changed: " + m);
            for (String p : paths) out.add("path replaced: " + p);
            for (Field f : fields.values()) {
                List<String> what = new ArrayList<>();
                if (f.modified > 0) what.add("modified " + f.modified + "×");
                if (f.removed > 0) what.add("removed " + f.removed + "×");
                if (f.added > 0) what.add("added " + f.added + "×");
                if (f.fuzzed > 0) what.add("Intruder payload position");
                String line = f.loc + " `" + f.name + "`: " + String.join(", ", what);
                if (!f.values.isEmpty()) line += " — values tried: " + String.join(", ", f.values);
                out.add(line);
            }
            if (attacks > 0) {
                out.add("Intruder: " + attacks + (attacks == 1 ? " attack" : " attacks")
                        + (attackRequests > 0 ? ", " + String.format("%,d", attackRequests) + " requests" : ""));
            }
            return out;
        }
    }
}
