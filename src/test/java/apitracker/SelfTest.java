package apitracker;

import apitracker.core.ApiKeys;
import apitracker.core.Diff;
import apitracker.core.Events;
import apitracker.core.FieldLocator;
import apitracker.core.IntruderTracker;
import apitracker.core.JsonFlattener;
import apitracker.core.KeyRegistry;
import apitracker.core.ParsedReq;
import apitracker.core.Redactor;
import apitracker.core.Settings;
import apitracker.core.StatusIndex;
import apitracker.core.TabNames;
import apitracker.core.Tracker;
import apitracker.store.Db;
import apitracker.store.DbWriter;
import apitracker.store.Repo;
import apitracker.store.Rows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Self-test without Burp or JUnit: run with {@code java -cp ... apitracker.SelfTest}.
 * Exits with code 1 if any test fails.
 */
public final class SelfTest {
    private static int passed, failed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        run("ApiKeys.normalize", SelfTest::apiKeys);
        run("ApiKeys.variant", SelfTest::variant);
        run("JsonFlattener", SelfTest::json);
        run("ParsedReq", SelfTest::parsed);
        run("Redactor", SelfTest::redactor);
        run("Diff", SelfTest::diff);
        run("TabNames", SelfTest::tabNames);
        run("UI: log cell shows everything", SelfTest::logCellFull);
        run("Settings.excluded", SelfTest::excluded);
        run("Tracker + DB end-to-end", SelfTest::trackerEndToEnd);
        run("Tracker: response before request / no response", SelfTest::trackerOrdering);
        run("Tracker: Proxy lookup as original", SelfTest::trackerLookup);
        run("Tracker: redirect not counted as a test", SelfTest::trackerRedirect);
        run("Tracker: sibling paths not merged, variants still merged", SelfTest::trackerSiblings);
        run("Tracker: AI request never becomes the original", SelfTest::trackerAiNoOriginal);
        run("Tracker: rotating cookie not counted as a test", SelfTest::trackerNoise);
        run("Tracker: repeated AI sends to an API without original look up Proxy only once", SelfTest::trackerAiLookupOnce);
        run("Tracker: original > 1 MB yields no bogus body diff after reload", SelfTest::trackerTruncated);
        run("Tracker: late Proxy lookup result is dropped", SelfTest::trackerStaleLookup);
        run("HttpText: readable request/response for AI context", SelfTest::httpText);
        run("Tracker: original request + response stored as AI context", SelfTest::originalContext);
        run("Log numbering per API (#1 = original, then #2, #3…)", SelfTest::logNumbering);
        run("Export for AI: original request + response, tests, coverage", SelfTest::aiExport);
        run("DbWriter: DB close handoff, byte limit", SelfTest::writerLifecycle);
        run("Repo: search and filter", SelfTest::repoSearch);
        run("FieldLocator: locate field by offset", SelfTest::fieldLocator);
        run("FieldLocator: fast path matches slow path", SelfTest::fieldLocatorMatchesDiff);
        run("Intruder: sniper / pitchfork / Content-Length / fuzz path", SelfTest::intruderPositions);
        run("Intruder: one log row per attack, updated while running", SelfTest::intruderLog);
        run("Storage: compression against the original, batched counters, originals loaded on demand", SelfTest::storage);
        run("Search: multiple terms, incremental narrowing, LIKE and FTS give the same results", SelfTest::searchPlans);
        run("Intruder: review cases (long payloads, cluster bomb, name fuzzing, broken JSON, XML, redirects…)", SelfTest::intruderReviewCases);
        run("Intruder performance", SelfTest::intruderPerf);
        run("Performance", SelfTest::perf);
        System.out.println();
        System.out.println("PASSED " + passed + "  FAILED " + failed);
        for (String f : failures) System.out.println("  - " + f);
        System.exit(failed == 0 ? 0 : 1);
    }

    interface Body { void run() throws Exception; }

    static void run(String name, Body b) {
        try {
            b.run();
            System.out.println("ok   " + name);
        } catch (Throwable t) {
            failed++;
            failures.add(name + ": " + t);
            System.out.println("FAIL " + name + ": " + t);
            t.printStackTrace(System.out);
        }
    }

    static void eq(Object expected, Object actual, String what) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(what + ": expected <" + expected + "> but was <" + actual + ">");
        }
        passed++;
    }

    static void yes(boolean cond, String what) {
        if (!cond) throw new AssertionError(what);
        passed++;
    }

    // ---------------------------------------------------------------

    static void apiKeys() {
        eq("/orders/{id}/cancel", ApiKeys.normalize("/orders/8831/cancel"), "digits");
        eq("/u/{uuid}", ApiKeys.normalize("/u/3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90"), "uuid");
        eq("/f/{hex}", ApiKeys.normalize("/f/a3f9c0d1e2b3a4f5"), "hex");
        eq("/getUserProfileByAccountId2", ApiKeys.normalize("/getUserProfileByAccountId2"), "endpoint name with digits");
        eq("/t/{token}", ApiKeys.normalize("/t/aB3dE5gH7jK9mN1pQ3rS5"), "token");
        eq("/a/b", ApiKeys.normalize("/a;jsessionid=ABC123/b"), "jsessionid");
        eq("/..;/admin", ApiKeys.normalize("/..;/admin"), "keep ;");
        eq("/", ApiKeys.normalize(""), "empty");
        eq("/a/b", ApiKeys.normalize("//a//b/"), "extra slashes");
        eq("/a", ApiKeys.normalize("/a?x=1"), "strip query");
        eq("/api/v1/x", ApiKeys.normalize("https://h.com/api/v1/x?q"), "absolute URL");
        eq("https://[::1]:443", ApiKeys.hostKey("::1", 443, true), "IPv6");
        eq("https://api.example.com:443", ApiKeys.hostKey("API.Example.com", 443, true), "lowercase host");
        ApiKeys k = new ApiKeys();
        eq("POST https://h:443/so-order/{id}", k.statusKey("post", "https://h:443", "/so-order/12"), "statusKey");
        eq("/condition-orders/underlying-order/api/v1/so-order",
                ApiKeys.normalize("/condition-orders/underlying-order/api/v1/so-order"), "long path unchanged");
    }

    static void variant() {
        yes(ApiKeys.isVariant(new String[]{"orders", "{id}"}, new String[]{"orders", "5'"}), "differs in 1");
        yes(!ApiKeys.isVariant(new String[]{"a", "b"}, new String[]{"c", "d"}), "differs in 2");
        yes(!ApiKeys.isVariant(new String[]{"a"}, new String[]{"a", "b"}), "different length");
        yes(!ApiKeys.isVariant(new String[]{"login"}, new String[]{"logout"}), "single segment is not a variant");
    }

    static void json() {
        Map<String, String> m = JsonFlattener.flatten("{\"a\":{\"b\":[1,\"x\",{\"c\":null}]},\"q\":\"100\",\"n\":100,\"e\":{},\"w e\":true}", 8, 1000);
        eq("1", m.get("$.a.b[0]"), "number in array");
        eq("\"x\"", m.get("$.a.b[1]"), "string keeps quotes");
        eq("null", m.get("$.a.b[2].c"), "null");
        eq("\"100\"", m.get("$.q"), "numeric string");
        eq("100", m.get("$.n"), "number");
        eq("{}", m.get("$.e"), "empty object");
        eq("true", m.get("$[\"w e\"]"), "key with space");
        Map<String, String> deep = JsonFlattener.flatten("{\"a\":{\"b\":{\"c\":1}}}", 2, 1000);
        yes(deep.get("$.a.b").startsWith("#"), "too deep becomes hash");
        Map<String, String> many = JsonFlattener.flatten("{\"a\":1,\"b\":2,\"c\":3}", 8, 2);
        eq(3, many.size(), "over field limit merges the rest");
        yes(many.containsKey("$…"), "merged leaf");
        boolean threw = false;
        try { JsonFlattener.flatten("{\"a\":1,}", 8, 100); } catch (IllegalArgumentException e) { threw = true; }
        yes(threw, "invalid JSON throws");
        eq("\"a\\\"b\"", JsonFlattener.flatten("{\"k\":\"a\\\"b\"}", 8, 10).get("$.k"), "escape in string");
    }

    static byte[] req(String s) { return s.replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8); }

    static final String ORIG = "POST /condition-orders/underlying-order/api/v1/so-order?x=1 HTTP/1.1\n"
            + "Host: api.example.com\n"
            + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQSJ9.sig-aaaaaaaa\n"
            + "Cookie: SESSION=abc123; lang=vi\n"
            + "Content-Type: application/json\n"
            + "Content-Length: 59\n"
            + "\n"
            + "{\"accountNo\":\"0001\",\"symbol\":\"VNM\",\"qty\":100,\"price\":65000}";

    static void parsed() {
        ParsedReq p = ParsedReq.parse(req(ORIG));
        eq("POST", p.method, "method");
        eq("/condition-orders/underlying-order/api/v1/so-order", p.path, "path");
        eq("api.example.com", p.hostHeader, "host");
        eq("1", p.query.get("x"), "query");
        eq("abc123", p.cookies.get("SESSION"), "cookie");
        eq(ParsedReq.BodyKind.JSON, p.bodyKind, "body json");
        eq("\"0001\"", p.bodyFields.get("$.accountNo"), "field");
        ParsedReq dup = ParsedReq.parse(req("GET /a?id=1&id=2 HTTP/1.1\nHost: h\n\n"));
        eq("2", dup.query.get("id#2"), "repeated param");
        ParsedReq form = ParsedReq.parse(req("POST /l HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\nu=a&p=b"));
        eq(ParsedReq.BodyKind.FORM, form.bodyKind, "form");
        eq("b", form.bodyFields.get("p"), "form field");
        ParsedReq mp = ParsedReq.parse(req("POST /up HTTP/1.1\nHost: h\nContent-Type: multipart/form-data; boundary=XX\n\n"
                + "--XX\nContent-Disposition: form-data; name=\"a\"\n\n1\n--XX\nContent-Disposition: form-data; name=\"f\"; filename=\"x.php\"\n\n<?php ?>\n--XX--\n"));
        eq(ParsedReq.BodyKind.MULTIPART, mp.bodyKind, "multipart");
        eq("1", mp.bodyFields.get("a"), "multipart field");
        yes(mp.bodyFields.get("f").startsWith("<file \"x.php\""), "multipart file");
        ParsedReq broken = ParsedReq.parse(new byte[]{0, 1, 2});
        yes(broken != null, "broken request does not throw");
        ParsedReq lf = ParsedReq.parse("GET /x HTTP/1.1\nHost: h\n\n".getBytes(StandardCharsets.UTF_8));
        eq("/x", lf.path, "LF line endings");
        ParsedReq h2 = ParsedReq.parse(req("GET /x HTTP/2\nHost: h\n\n"));
        eq("HTTP/2", h2.version, "HTTP/2");
    }

    static Redactor newRedactor() { return new Redactor(new byte[32], List.of()); }

    static void redactor() {
        // default: no masked fields, everything cleartext (tokens, JWTs, passwords included)
        Redactor none = newRedactor();
        yes(!none.masked("Authorization") && !none.masked("password") && !none.masked("accessToken"), "nothing masked by default");
        String jwtv = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQSJ9.sig";
        eq(jwtv, none.display("Authorization", jwtv, false), "JWT shown in cleartext");
        String tgt = "/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdef?access_token=xyz&page=2";
        eq(tgt, none.redactTarget(tgt), "request target unchanged");
        eq("user=alice&password=hunter2", none.redactText("user=alice&password=hunter2"), "free text unchanged");

        // fields listed in Settings → Masked fields
        Redactor r = new Redactor(new byte[32], List.of("password", "token", "Authorization", "otp", "jsessionid", "secret"));
        yes(r.masked("Authorization"), "listed header");
        yes(r.masked("accessToken"), "camelCase word");
        yes(r.masked("x-csrf-token"), "dash-separated word");
        yes(r.masked("$.user.password"), "json path: last key");
        yes(r.masked("refresh_token#2"), "occurrence suffix");
        yes(r.masked("$.tokens[0]"), "plural array name");
        yes(r.masked("passwords"), "plural");
        yes(!r.masked("tokenizer"), "longer word not matched");
        yes(!r.masked("accountNo"), "unlisted field cleartext");
        yes(!r.masked("x-api-key"), "unlisted header cleartext");
        String f1 = r.fp("tokenA"), f2 = r.fp("tokenB");
        yes(f1.matches("<#[0-9a-f]{8}>"), "fingerprint format");
        yes(!f1.equals(f2), "different token, different fingerprint");
        eq(f1, r.fp("tokenA"), "stable");
        Redactor other = new Redactor(new byte[]{1, 2, 3}, List.of());
        yes(!f1.equals(other.fp("tokenA")), "different key → different fingerprint");
        eq(r.fp("abc"), r.display("$.password", "\"abc\"", false), "masked JSON string: fingerprint of the content");
        String t = r.redactTarget(tgt);
        yes(t.contains("eyJ") && !t.contains("xyz") && t.contains("page=2"), "only the listed query value masked: " + t);
        String js = r.redactTarget("/app;jsessionid=0123456789ABCDEF;v=2/list");
        yes(js.contains(";jsessionid=<#") && !js.contains("0123456789ABCDEF") && js.contains(";v=2"), "listed ;matrix param masked: " + js);
        String txt = r.redactText("user=alice&password=hunter2&otp=123456&note=hello");
        yes(!txt.contains("hunter2") && !txt.contains("123456") && txt.contains("user=alice") && txt.contains("note=hello"),
                "text masked by listed name: " + txt);
        String xml = r.redactText("<user>alice</user><secret>topsecret</secret>");
        yes(!xml.contains("topsecret") && xml.contains("alice"), "XML masked by listed name: " + xml);
        eq("a\\nb", Redactor.clip("a\nb"), "clip newline");
        yes(Redactor.clip("x".repeat(500)).contains("…(+440)"), "clip long");

        // labels: a labeled value shows as its label even in an unlisted field
        Redactor lr = newRedactor();
        Set<String> labeled = java.util.concurrent.ConcurrentHashMap.newKeySet();
        lr.setLabeled(labeled);
        eq("tokA", lr.display("X-Token", "tokA", false), "unlabeled: cleartext");
        labeled.add(lr.fullHmac("tokA"));
        eq(lr.fp("tokA"), lr.display("X-Token", "tokA", false), "labeled header value → fingerprint (label)");
        eq(lr.fp("tokA"), lr.display("$.t", "\"tokA\"", false), "labeled JSON string → same fingerprint");
        eq("/a?t=" + lr.fp("tokA") + "&p=1", lr.redactTarget("/a?t=tokA&p=1"), "labeled query value");
        eq("other", lr.display("X-Token", "other", false), "other values stay cleartext");
    }

    static void diff() {
        Redactor r = newRedactor();
        ParsedReq a = ParsedReq.parse(req(ORIG));
        String mod = ORIG.replace("POST /", "PUT /").replace("\"0001\"", "\"0002\"").replace("Cookie: SESSION=abc123; lang=vi\n", "Cookie: lang=vi\n")
                .replace("?x=1", "?x=1&debug=true").replace("Host: api.example.com\n", "Host: api.example.com\nX-Forwarded-For: 127.0.0.1\n");
        ParsedReq b = ParsedReq.parse(req(mod));
        List<Diff.Change> ch = Diff.compute(a, b, r, Set.of("content-length", "connection"));
        String text = Diff.format(ch);
        yes(text.contains("~ method   POST → PUT"), "method: " + text);
        yes(text.contains("+ query   debug = true"), "query added: " + text);
        yes(text.contains("+ header  X-Forwarded-For = 127.0.0.1"), "header added: " + text);
        yes(text.contains("- cookie  SESSION"), "cookie removed: " + text);
        yes(text.contains("~ body    $.accountNo   \"0001\" → \"0002\""), "body: " + text);
        yes(!text.contains("content-length") && !text.contains("Content-Length"), "content-length ignored");
        int mask = Diff.locMask(ch);
        yes((mask & Diff.LOC_METHOD) != 0 && (mask & Diff.LOC_BODY) != 0 && (mask & Diff.LOC_COOKIE) != 0, "locMask");

        ParsedReq c = ParsedReq.parse(req(ORIG.replace("sig-aaaaaaaa", "sig-bbbbbbbb")));
        String t2 = Diff.format(Diff.compute(a, c, r, Set.of()));
        yes(t2.contains("~ header  Authorization   Bearer eyJ") && t2.contains("sig-bbbbbbbb"), "changed token in cleartext: " + t2);
        Redactor mr = new Redactor(new byte[32], List.of("authorization", "password", "token", "sid", "session"));
        String t2m = Diff.format(Diff.compute(a, c, mr, Set.of()));
        yes(t2m.contains("~ header  Authorization   <#") && !t2m.contains("eyJ"), "listed header masked: " + t2m);

        String rh = Diff.format(Diff.compute(ParsedReq.parse(req("GET / HTTP/1.1\nHost: h\nX-Device-Id: 1\n\n")),
                ParsedReq.parse(req("GET / HTTP/1.1\nHost: h\n\n")), r, Set.of()));
        eq("- header  X-Device-Id", rh, "removed header keeps its original spelling");
        ParsedReq p1 = ParsedReq.parse(req("GET /orders/8831 HTTP/1.1\nHost: h\n\n"));
        ParsedReq p2 = ParsedReq.parse(req("GET /orders/8832 HTTP/1.1\nHost: h\n\n"));
        eq("~ path    [1]   8831 → 8832", Diff.format(Diff.compute(p1, p2, r, Set.of())), "path segment");

        ParsedReq same = ParsedReq.parse(req(ORIG));
        eq(0, Diff.compute(a, same, r, Set.of()).size(), "no change");

        ParsedReq t1 = ParsedReq.parse(req("POST /x HTTP/1.1\nHost: h\nContent-Type: text/xml\n\n<a><b>1</b></a>"));
        ParsedReq t3 = ParsedReq.parse(req("POST /x HTTP/1.1\nHost: h\nContent-Type: text/xml\n\n<a><b>2</b></a>"));
        String xt = Diff.format(Diff.compute(t1, t3, r, Set.of()));
        yes(xt.contains("\"1\" → \"2\""), "text diff of middle part: " + xt);

        ParsedReq h1 = ParsedReq.parse(req("GET /a?id=1 HTTP/1.1\nHost: h\n\n"));
        ParsedReq h2 = ParsedReq.parse(req("GET /a?id=1&id=2 HTTP/1.1\nHost: h\n\n"));
        yes(Diff.format(Diff.compute(h1, h2, r, Set.of())).contains("+ query   id#2 = 2"), "HPP");

        ParsedReq type1 = ParsedReq.parse(req("POST /x HTTP/1.1\nHost: h\nContent-Type: application/json\n\n{\"qty\":100}"));
        ParsedReq type2 = ParsedReq.parse(req("POST /x HTTP/1.1\nHost: h\nContent-Type: application/json\n\n{\"qty\":\"100\"}"));
        yes(Diff.format(Diff.compute(type1, type2, r, Set.of())).contains("100 → \"100\""), "data type change");
        ParsedReq ws = ParsedReq.parse(req("POST /x HTTP/1.1\nHost: h\nContent-Type: application/json\n\n{ \"qty\" : 100 }"));
        yes(Diff.format(Diff.compute(type1, ws, r, Set.of())).contains("(formatting)"), "formatting-only difference");

        // body text: a listed name masks the value even when the name is outside the differing part
        ParsedReq pw1 = ParsedReq.parse(req("POST /login HTTP/1.1\nHost: h\nContent-Type: text/plain\n\nuser=alice;password=hunter2;remember=1"));
        ParsedReq pw2 = ParsedReq.parse(req("POST /login HTTP/1.1\nHost: h\nContent-Type: text/plain\n\nuser=alice;password=s3cr3tPw;remember=1"));
        String pt = Diff.format(Diff.compute(pw1, pw2, mr, Set.of()));
        yes(!pt.contains("hunter2") && !pt.contains("s3cr3tPw") && pt.contains("password") && pt.contains("<#"), "masked body text: " + pt);
        String ptc = Diff.format(Diff.compute(pw1, pw2, r, Set.of()));
        yes(ptc.contains("hunter2") && ptc.contains("s3cr3tPw"), "same body in cleartext without a masked field: " + ptc);
        ParsedReq x1 = ParsedReq.parse(req("POST /s HTTP/1.1\nHost: h\nContent-Type: text/xml\n\n<r><token>abc</token><q>1</q></r>"));
        ParsedReq x2 = ParsedReq.parse(req("POST /s HTTP/1.1\nHost: h\nContent-Type: text/xml\n\n<r><token>xyz</token><q>1</q></r>"));
        String xt2 = Diff.format(Diff.compute(x1, x2, mr, Set.of()));
        yes(!xt2.contains("abc") && !xt2.contains("xyz"), "masked XML body: " + xt2);
        ParsedReq m1 = ParsedReq.parse(req("GET /a;jsessionid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/b;sid=s1 HTTP/1.1\nHost: h\n\n"));
        ParsedReq m2 = ParsedReq.parse(req("GET /a;jsessionid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/b;sid=s2 HTTP/1.1\nHost: h\n\n"));
        String mt = Diff.format(Diff.compute(m1, m2, mr, Set.of()));
        yes(!mt.contains("s1") && !mt.contains("s2") && mt.contains(";sid=<#"), "masked ;sid param in path: " + mt);
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdefgh";
        ParsedReq q1 = ParsedReq.parse(req("GET /a?x=1 HTTP/1.1\nHost: h\n\n"));
        ParsedReq q2 = ParsedReq.parse(req("GET /a?x=1&" + jwt + " HTTP/1.1\nHost: h\n\n"));
        String qt = Diff.format(Diff.compute(q1, q2, mr, Set.of()));
        yes(qt.contains("+ query   " + jwt), "bare JWT query in cleartext (no name to list): " + qt);
        ParsedReq sp1 = ParsedReq.parse(req("POST /l HTTP/1.1\nHost: h\nContent-Type: text/plain\n\n{\"password\" : \"hunter2\", x"));
        ParsedReq sp2 = ParsedReq.parse(req("POST /l HTTP/1.1\nHost: h\nContent-Type: text/plain\n\n{\"password\" : \"hunter3\", x"));
        String spt = Diff.format(Diff.compute(sp1, sp2, mr, Set.of()));
        yes(!spt.contains("hunter"), "whitespace around ':' still masked: " + spt);
        String hex64 = "0123456789abcdef".repeat(4);
        ParsedReq h64a = ParsedReq.parse(req("POST /s HTTP/1.1\nHost: h\nContent-Type: text/xml\n\n<r><session>" + hex64 + "</session></r>"));
        ParsedReq h64b = ParsedReq.parse(req("POST /s HTTP/1.1\nHost: h\nContent-Type: text/xml\n\n<r><session>" + hex64.replace('f', 'e') + "</session></r>"));
        yes(!Diff.format(Diff.compute(h64a, h64b, mr, Set.of())).contains("0123456789"), "listed <session> masked");
        yes(Diff.format(Diff.compute(h64a, h64b, r, Set.of())).contains("0123456789"), "unlisted: long hex shown in cleartext");
        ParsedReq ck1 = ParsedReq.parse(req("GET /a HTTP/1.1\nHost: h\nCookie: SESSION=abc123\n\n"));
        ParsedReq ck2 = ParsedReq.parse(req("GET /a HTTP/1.1\nHost: h\nCookie: SESSION=zzz999\n\n"));
        yes(Diff.format(Diff.compute(ck1, ck2, r, Set.of())).contains("abc123 → zzz999"), "cookies in cleartext unless listed");
        yes(Diff.format(Diff.compute(ck1, ck2, mr, Set.of())).contains("SESSION   <#"), "listed cookie masked");

        // noise: load balancer cookie, browser headers, changed CSRF value
        yes(apitracker.core.Noise.ignorableForStatus(new Diff.Change('~', Diff.LOC_COOKIE, "AWSALB", "a", "b")), "AWSALB");
        yes(apitracker.core.Noise.ignorableForStatus(new Diff.Change('~', Diff.LOC_HEADER, "Sec-Fetch-Site", "a", "b")), "sec-fetch");
        yes(apitracker.core.Noise.ignorableForStatus(new Diff.Change('~', Diff.LOC_HEADER, "X-CSRF-Token", "a", "b")), "CSRF changed");
        yes(!apitracker.core.Noise.ignorableForStatus(new Diff.Change('-', Diff.LOC_HEADER, "X-CSRF-Token", null, null)), "CSRF removed is a test");
        yes(!apitracker.core.Noise.ignorableForStatus(new Diff.Change('-', Diff.LOC_HEADER, "Authorization", null, null)), "removing auth is a test");
    }

    static void logCellFull() {
        StringBuilder ch = new StringBuilder();
        for (int i = 0; i < 15; i++) ch.append(i == 0 ? "" : "\n").append("~ header  X-H").append(i).append("   a → b");
        String[] l = apitracker.ui.UiProbe.cellLines(ch.toString(), 0);
        eq(17, l.length, "all 15 change lines + head line + response");
        yes(l[15].contains("X-H14") && l[16].trim().startsWith("→ 200"), "change lines not cut, response last");
        yes(java.util.Arrays.stream(l).noneMatch(x -> x.contains("Changes tab")), "no longer points to the Changes tab");
        StringBuilder ich = new StringBuilder();
        for (int i = 0; i < 14; i++) ich.append("§ body $.f").append(i).append('\n');
        ich.append("40 requests · 200×40");
        String[] il = apitracker.ui.UiProbe.cellLines(ich.toString(), Rows.FLAG_INTRUDER);
        eq(16, il.length, "Intruder: all 14 positions + stats, no extra response line");
        String[] ll = apitracker.ui.UiProbe.cellLines("~ body  $.x   " + "a".repeat(1500), 0);
        yes(ll[1].length() <= 1001 && ll[1].endsWith("…"), "only overlong lines are cut");
        // columns for proportional fonts (Burp UI font)
        String fmtLine = "    " + new Diff.Change('~', Diff.LOC_HEADER, "Authorization", "<#aaaa>", "<#bbbb>").format();
        String[] cc = apitracker.ui.UiProbe.changeCols(fmtLine);
        yes(cc != null && cc[0].equals("~") && cc[1].equals("header") && cc[2].startsWith("Authorization"), "split change line into columns: " + fmtLine);
        String[] cm = apitracker.ui.UiProbe.changeCols("    " + new Diff.Change('~', Diff.LOC_METHOD, "", "GET", "POST").format());
        yes(cm != null && cm[1].equals("method") && cm[2].equals("GET → POST"), "split method change into columns");
        String[] ci = apitracker.ui.UiProbe.changeCols("    § body    $.orderId");
        yes(ci != null && ci[0].equals("§") && ci[2].equals("$.orderId"), "split Intruder position into columns");
        yes(apitracker.ui.UiProbe.changeCols("#3  02:38:46  POST /x HTTP/1.1") == null, "head line not split");
        yes(apitracker.ui.UiProbe.changeCols("    → 200 · 10 B") == null, "response line not split");
        yes(apitracker.ui.UiProbe.changeCols("    + bodyx foo") == null, "unknown word not treated as a position");
    }

    static void tabNames() {
        eq("GET /iis-server/watchlist", TabNames.tabName("GET", "/iis-server/watchlist?customerId=0009003785", Set.of()), "strip query");
        eq("POST /condition-orders/underlying-order/api/v1/so-order",
                TabNames.tabName("POST", "/condition-orders/underlying-order/api/v1/so-order", Set.of()), "full path");
        eq("GET /so-order/8831/items", TabNames.tabName("get", "/so-order/8831/items#top", Set.of()), "keep real id, strip fragment, uppercase method");
        eq("GET /app/login.do", TabNames.tabName("GET", "/app/login.do;jsessionid=ABC123?x=1", Set.of()), "strip jsessionid");
        eq("GET /a/b", TabNames.tabName("GET", "https://h.example:8443/a/b?q=1", Set.of()), "absolute URL");
        eq("GET /", TabNames.tabName("GET", "?x=1", Set.of()), "query only");
        eq("GET /x (2)", TabNames.tabName("GET", "/x", Set.of("GET /x")), "duplicate name");
        eq("GET /x (3)", TabNames.tabName("GET", "/x?a=1", Set.of("GET /x", "GET /x (2)")), "duplicate name, 3rd time");
        eq("GET /", TabNames.tabName("GET", "/", Set.of()), "root");
        eq("GET /open-api/inq/accounts/{id}/availableTrade", TabNames.tabName("GET", "/open-api/inq/accounts/{id}/availableTrade", null), "name in API list: full path, keep {id}");
        eq("GET /iis-server/watchlist", TabNames.fromRequestLine("GET /iis-server/watchlist?customerId=0009003785 HTTP/1.1", Set.of()), "from request line");
        String longPath = "/" + "a".repeat(400);
        String ln = TabNames.tabName("GET", longPath, Set.of());
        yes(ln.length() <= 4 + TabNames.MAX_PATH && ln.contains("…"), "overlong path shortened");
        yes(TabNames.isDefaultName("12"), "numeric name");
        yes(!TabNames.isDefaultName("POST /x"), "user-set name");
    }

    static void excluded() {
        Settings s = new Settings();
        yes(s.excluded("OPTIONS", "/api"), "OPTIONS");
        yes(s.excluded("GET", "/static/app.js"), "js");
        yes(s.excluded("GET", "/health"), "health");
        yes(!s.excluded("GET", "/api/v1.2/orders"), "dot in middle segment");
        yes(!s.excluded("POST", "/so-order"), "regular API");
    }

    // ---------------- Tracker ----------------

    static final class Harness implements AutoCloseable {
        final Path dir;
        final Db db;
        final DbWriter writer;
        final Tracker tracker;
        final StatusIndex status = new StatusIndex();
        final KeyRegistry registry = new KeyRegistry();
        final Settings settings = new Settings();
        final List<Rows.SendRow> sends = new CopyOnWriteArrayList<>();
        final List<String> tested = new CopyOnWriteArrayList<>();
        final List<String> renames = new CopyOnWriteArrayList<>();
        final List<Rows.ApiRow> apiRows = new CopyOnWriteArrayList<>();
        int msg = 1;

        Harness() throws Exception {
            dir = Files.createTempDirectory("apitracker-test");
            Path f = Db.chooseFile(dir, "Test Project", "pid-1", null);
            db = Db.open(f, "pid-1", false);
            writer = new DbWriter(db.writeConnection(), db.readOnly);
            registry.setOnNew((id, key) -> writer.submit(DbWriter.insertStatusKey(id, key)));
            Redactor r = new Redactor(db.hmacKey(), List.of());
            tracker = new Tracker(new ApiKeys(), status, registry, writer, settings, r);
            tracker.load(db.load());
            tracker.setListener(new Tracker.Listener() {
                @Override public void apiChanged(Rows.ApiRow row) { apiRows.add(row); }
                @Override public void sendAdded(Rows.SendRow row) { sends.add(row); }
                @Override public void renameHint(String fl, String host, String name) { renames.add(name); }
            });
            tracker.setTestedListener(tested::add);
            writer.start();
        }

        Events.RequestSource src(String raw) { return new Events.StaticRequest(req(raw), "api.example.com", 443, true); }

        void send(String raw, int status) {
            int id = msg++;
            long now = System.nanoTime();
            tracker.submit(new Events.SendEvent(Events.KIND_REPEATER, id, now, System.currentTimeMillis(), src(raw), "repeater"));
            tracker.submit(new Events.ResponseEvent(Events.KIND_REPEATER, id, now + 5_000_000, status, 100, null, src(raw)));
            tracker.drainForTest();
        }

        @Override public void close() {
            writer.stop(2000);
            db.close();
        }
    }

    static void trackerEndToEnd() throws Exception {
        try (Harness h = new Harness()) {
            // original from the tracked menu
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG)));
            h.tracker.drainForTest();
            h.send(ORIG, 200);                                   // send unchanged
            eq(1, h.sends.size(), "1 send");
            eq("", h.sends.get(0).changes(), "no change");
            String sk = "POST https://api.example.com:443/condition-orders/underlying-order/api/v1/so-order";
            eq(StatusIndex.SENT, h.status.get(sk), "status sent");
            yes(h.tested.isEmpty(), "not tested yet");

            h.send(ORIG.replace("\"qty\":100", "\"qty\":-1"), 400);
            eq(2, h.sends.size(), "2 sends");
            yes(h.sends.get(1).changes().contains("$.qty   100 → -1"), "diff qty: " + h.sends.get(1).changes());
            eq(StatusIndex.TESTED, h.status.get(sk), "tested");
            eq(List.of(sk), h.tested, "tested reported exactly once");
            h.send(ORIG.replace("\"qty\":100", "\"qty\":0"), 400);
            eq(1, h.tested.size(), "not reported again");
            yes(h.renames.isEmpty(), "tracked original: no tier-3 rename");

            // multiple tabs: second original for userB; a send resembling userB must pick the userB original
            String origB = ORIG.replace("eyJzdWIiOiJ1c2VyQSJ9", "eyJzdWIiOiJ1c2VyQiJ9").replace("\"0001\"", "\"0002\"");
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(origB)));
            h.tracker.drainForTest();
            h.send(origB.replace("\"price\":65000", "\"price\":1"), 200);
            String last = h.sends.get(h.sends.size() - 1).changes();
            eq("~ body    $.price   65000 → 1", last, "picks the userB original");

            // path variant (edited segment) is logged under the original API
            h.send(ORIG.replace("/so-order?", "/so-order'?"), 500);
            Rows.SendRow v = h.sends.get(h.sends.size() - 1);
            eq(h.sends.get(0).apiId(), v.apiId(), "variant logged under the original API");
            yes(v.changes().contains("~ path    [4]   so-order → so-order'"), "diff path: " + v.changes());

            h.writer.awaitIdle(3000);
            // reopen DB: state intact
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                List<Rows.SendRow> page = repo.page(h.sends.get(0).apiId(), Long.MAX_VALUE, 200, Repo.Filter.ALL);
                eq(5, page.size(), "5 sends written");
                yes(page.get(0).id() > page.get(1).id(), "newest first");
                yes(repo.blob(page.get(0).id()) != null, "raw request present");
            }
            Db.State st = h.db.load();
            eq(1, st.apis.size(), "1 API");
            eq(5, st.apis.get(0).sendCount(), "batched send counter correct");
            eq(2, st.originals.size(), "2 originals");
            yes(st.statusState.containsValue(2), "tested status saved");
        }
    }

    static void trackerOrdering() throws Exception {
        try (Harness h = new Harness()) {
            // orphan response (SendEvent dropped) is still logged via initiatingRequest
            h.tracker.submit(new Events.ResponseEvent(Events.KIND_REPEATER, 99, System.nanoTime(), 200, 10, null, h.src(ORIG)));
            h.tracker.drainForTest();
            eq(1, h.sends.size(), "orphan response logged");
            yes((h.sends.get(0).flags() & Rows.FLAG_SELF_ORIGINAL) != 0, "becomes its own original");
            eq(1, h.renames.size(), "tier-3 rename hint");
            // no response: logged with the no-response flag on timeout
            h.tracker.submit(new Events.SendEvent(Events.KIND_REPEATER, 100, System.nanoTime(), System.currentTimeMillis(),
                    h.src(ORIG.replace("VNM", "FPT")), "repeater"));
            h.tracker.drainForTest();
            eq(1, h.sends.size(), "not logged while awaiting response");
            h.tracker.sweepForTest(System.nanoTime() + 200_000_000_000L);
            eq(2, h.sends.size(), "logged on timeout");
            yes((h.sends.get(1).flags() & Rows.FLAG_NO_RESPONSE) != 0, "no-response flag");
        }
    }

    static void trackerLookup() throws Exception {
        try (Harness h = new Harness()) {
            List<String> asked = new ArrayList<>();
            h.tracker.setLookup((method, hostKey, pathKey, parked, token) -> {
                asked.add(method + " " + hostKey + pathKey);
                // simulate the history thread returning the original Proxy request
                h.tracker.submitInternal(new Events.LookupResult(parked, token, h.src(ORIG), 123L));
            });
            String modified = ORIG.replace("\"symbol\":\"VNM\"", "\"symbol\":\"VNM' OR 1=1--\"");
            h.send(modified, 400);
            h.tracker.drainForTest();                            // process LookupResult
            eq(1, asked.size(), "Proxy looked up once");
            eq(1, h.sends.size(), "send logged once the original is known");
            yes(h.sends.get(0).changes().contains("$.symbol"), "diff vs Proxy request: " + h.sends.get(0).changes());
            eq(1, h.tested.size(), "tested on the first send (Ctrl+R → edit → Send)");
            eq(1, h.renames.size(), "rename hint since the original came from Proxy");
        }
    }

    static void trackerRedirect() throws Exception {
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(),
                    h.src("GET /login HTTP/1.1\nHost: api.example.com\n\n")));
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(),
                    h.src("GET /home HTTP/1.1\nHost: api.example.com\nX-A: 1\n\n")));
            h.tracker.drainForTest();
            long now = System.nanoTime();
            h.tracker.submit(new Events.SendEvent(Events.KIND_REPEATER, 1, now, System.currentTimeMillis(),
                    h.src("GET /login?x=1 HTTP/1.1\nHost: api.example.com\n\n"), "repeater"));
            h.tracker.submit(new Events.ResponseEvent(Events.KIND_REPEATER, 1, now + 1000, 302, 0, "/home",
                    h.src("GET /login?x=1 HTTP/1.1\nHost: api.example.com\n\n")));
            // auto-followed redirect: differs from the original (no X-A) but must not count as a test
            h.tracker.submit(new Events.SendEvent(Events.KIND_REPEATER, 2, now + 2000, System.currentTimeMillis(),
                    h.src("GET /home HTTP/1.1\nHost: api.example.com\n\n"), "repeater"));
            h.tracker.submit(new Events.ResponseEvent(Events.KIND_REPEATER, 2, now + 3000, 200, 10, null,
                    h.src("GET /home HTTP/1.1\nHost: api.example.com\n\n")));
            h.tracker.drainForTest();
            eq(2, h.sends.size(), "2 sends");
            yes((h.sends.get(1).flags() & Rows.FLAG_REDIRECT) != 0, "redirect flag");
            eq(List.of("GET https://api.example.com:443/login"), h.tested, "only /login tested");
        }
    }

    static void httpText() {
        String json = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"Xin ch\u00e0o\"}";
        String t = apitracker.core.HttpText.of(json.getBytes(StandardCharsets.UTF_8), 1000);
        eq("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"name\":\"Xin ch\u00e0o\"}", t, "text body decoded as UTF-8, CR removed");
        eq("GET / HTTP/1.1\nHost: x\n\n", apitracker.core.HttpText.of(req("GET / HTTP/1.1\nHost: x\n\n"), 1000), "request without body");
        byte[] bin = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\u0000\u0001PNG".getBytes(StandardCharsets.ISO_8859_1);
        yes(apitracker.core.HttpText.of(bin, 1000).endsWith("[binary body: 5 bytes]"), "binary body replaced by a placeholder");
        String big = "HTTP/1.1 200 OK\r\n\r\n" + "a".repeat(5000);
        String bt = apitracker.core.HttpText.of(big.getBytes(StandardCharsets.UTF_8), 1000);
        yes(bt.length() <= 1000 + 20 && bt.endsWith("[truncated]"), "capped with a truncation marker");
        yes(apitracker.core.HttpText.of(new byte[0], 1000) == null, "empty message gives null");
    }

    static final String CTX_RESP = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"orderId\":42}";

    static String[] ctxOf(Harness h, int originalId) throws Exception {
        h.tracker.drainForTest();
        h.writer.awaitIdle(3000);
        try (Repo repo = new Repo(h.db.newReadConnection())) { return repo.originalText(originalId); }
    }

    static void originalContext() throws Exception {
        // 1. Send to Repeater (tracked) from Proxy: the selected item's response comes with the original
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG),
                    new Events.StaticResponse(CTX_RESP.getBytes(StandardCharsets.UTF_8))));
            String[] c = ctxOf(h, 1);
            yes(c != null && c[0] != null && c[0].startsWith("POST /condition-orders/underlying-order/api/v1/so-order?x=1 HTTP/1.1\n"),
                    "original request stored as text");
            yes(c != null && c[1] != null && c[1].contains("{\"orderId\":42}"), "original response stored as text");
        }
        // 2. original found in Proxy history: its response comes with the lookup result
        try (Harness h = new Harness()) {
            h.tracker.setLookup((method, hostKey, pathKey, parked, token) -> h.tracker.submitInternal(new Events.LookupResult(
                    parked, token, h.src(ORIG), 123L, new Events.StaticResponse(CTX_RESP.getBytes(StandardCharsets.UTF_8)))));
            h.send(ORIG.replace("VNM", "FPT"), 200);
            String[] c = ctxOf(h, 1);
            yes(c != null && c[1] != null && c[1].startsWith("HTTP/1.1 200 OK"), "Proxy original: response stored");
        }
        // 3. original from the Repeater tab hook (no response): looked up in Proxy history afterwards
        try (Harness h = new Harness()) {
            List<Integer> askedFor = new ArrayList<>();
            h.tracker.setLookup(new Tracker.OriginalLookup() {
                @Override public void lookup(String method, String hostKey, String pathKey, String parked, long token) {
                    h.tracker.submitInternal(new Events.LookupResult(parked, token, null, 0));
                }
                @Override public void lookupResponse(int originalId, String statusKey, byte[] requestRaw) {
                    askedFor.add(originalId);
                    h.tracker.submitInternal(new Events.OriginalResponse(originalId,
                            new Events.StaticResponse("HTTP/1.1 201 Created\r\n\r\nok".getBytes(StandardCharsets.UTF_8))));
                }
            });
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TABHOOK, System.currentTimeMillis(),
                    new Events.HookText(ORIG.replace("\n", "\r\n"))));
            h.send(ORIG.replace("VNM", "FPT"), 200);
            String[] c = ctxOf(h, 1);
            eq(List.of(1), askedFor, "tab-hook original: response looked up once");
            yes(c != null && c[0] != null && c[1] != null && c[1].startsWith("HTTP/1.1 201 Created"), "tab-hook original: response stored");
        }
        // 4. first send becomes its own original: that send's response is the original's response
        try (Harness h = new Harness()) {
            long now = System.nanoTime();
            h.tracker.submit(new Events.SendEvent(Events.KIND_REPEATER, 7, now, System.currentTimeMillis(), h.src(USERS), "repeater"));
            h.tracker.submit(new Events.ResponseEvent(Events.KIND_REPEATER, 7, now + 1000, 200, 12, null, h.src(USERS),
                    new Events.StaticResponse("HTTP/1.1 200 OK\r\n\r\n[{\"id\":1}]".getBytes(StandardCharsets.UTF_8))));
            String[] c = ctxOf(h, 1);
            yes(c != null && c[1] != null && c[1].endsWith("[{\"id\":1}]"), "self original: response of the first send stored");
        }
        // 5. "store raw requests" off: nothing stored
        try (Harness h = new Harness()) {
            h.settings.storeRaw = false;
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG),
                    new Events.StaticResponse(CTX_RESP.getBytes(StandardCharsets.UTF_8))));
            String[] c = ctxOf(h, 1);
            yes(c != null && c[0] == null && c[1] == null, "option off: no request/response text");
        }
    }

    static void aiExport() throws Exception {
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG),
                    new Events.StaticResponse(CTX_RESP.getBytes(StandardCharsets.UTF_8))));
            h.send(ORIG.replace("VNM", "FPT"), 200);
            h.send(ORIG.replace("VNM", "HPG"), 403);
            h.send(ORIG.replace("Cookie: SESSION=abc123; lang=vi\n", "").replace("?x=1", "?x=1&debug=true"), 401);
            h.tracker.drainForTest();
            h.writer.awaitIdle(3000);
            int apiId = h.sends.get(0).apiId();
            Rows.ApiRow row = null;
            for (Rows.ApiRow a : h.apiRows) if (a.id() == apiId) row = a;
            yes(row != null, "API row available");
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                String md = apitracker.ui.UiProbe.exportApi(repo, row, newRedactor(), h.settings.ignoredHeaders);
                if (System.getenv("SHOW_EXPORT") != null) System.out.println(md);
                yes(md.startsWith("## POST /condition-orders/underlying-order/api/v1/so-order\n"), "API heading");
                yes(md.contains("- Tests: 3 tests (Repeater 3)") && md.contains("- Responses seen: 200×1, 401×1, 403×1"), "summary: " + md.substring(0, Math.min(400, md.length())));
                yes(md.contains("body `$.symbol`: modified 2× — values tried: \"FPT\", \"HPG\""), "coverage: values tried");
                yes(md.contains("cookie `SESSION`: removed 1×") && md.contains("query `debug`: added 1× — values tried: true"), "coverage: removed / added");
                yes(md.contains("Never modified (fields of original #1): ") && md.contains("header `Authorization`")
                        && md.contains("body `$.accountNo`") && !md.contains("header `Content-Length`"), "never-modified fields (ignored headers left out)");
                yes(md.contains("### Original request #1 (Send to Repeater, tracked, ") && md.contains("Request:\n```http\nPOST /condition-orders")
                        && md.contains("Response:\n```http\nHTTP/1.1 200 OK") && md.contains("{\"orderId\":42}"), "original request + response included");
                int t2 = md.indexOf("\n#2  "), t4 = md.indexOf("\n#4  ");
                yes(t2 > 0 && t4 > t2 && md.contains("[Repeater]  POST /condition-orders") && md.contains("→ 401 · 100 B"), "tests oldest first with response");
                String masked = apitracker.ui.UiProbe.exportApi(repo, row, new Redactor(new byte[32], List.of("authorization")), h.settings.ignoredHeaders);
                yes(masked.contains("Authorization: <#") && !masked.contains("eyJhbGciOiJIUzI1NiJ9"), "masked fields are masked in the original request too");
                String all = apitracker.ui.UiProbe.exportAll(repo, List.of(row), newRedactor(), h.settings.ignoredHeaders);
                yes(all.startsWith("# API test log — Test project") && all.contains("How to read this log")
                        && all.contains("- 1 API with a log: 1 tested") && all.contains("## Untested APIs in scope (from Proxy history)")
                        && all.contains("- GET https://h:443/untested (3 requests)"), "full export: guide, overview, untested list");
            }
        }
        // masking a raw HTTP message (original request/response in the export)
        Redactor mr = new Redactor(new byte[32], List.of("authorization", "password", "session"));
        String http = "POST /login?session=abc&x=1 HTTP/1.1\nHost: h\nAuthorization: Bearer tok\nCookie: SESSION=s1; lang=vi\n\n{\"user\":\"a\",\"password\":\"p1\"}";
        String m = mr.maskHttp(http);
        yes(m.contains("?session=<#") && m.contains("&x=1") && m.contains("Authorization: <#") && m.contains("SESSION=<#")
                && m.contains("lang=vi") && !m.contains("p1\"") && m.contains("\"user\":\"a\""), "maskHttp: " + m);
        eq(http, newRedactor().maskHttp(http), "maskHttp unchanged without masked fields");
    }

    static void logNumbering() throws Exception {
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG)));
            h.send(ORIG.replace("VNM", "FPT"), 200);
            h.send(ORIG.replace("VNM", "HPG"), 403);
            h.send(USERS, 200);                                       // another API: its own numbering, self original
            h.tracker.drainForTest();
            h.writer.awaitIdle(3000);
            eq(List.of(2, 3, 2), h.sends.stream().map(Rows.SendRow::seq).toList(), "sends numbered per API after the original");
            int soOrder = h.sends.get(0).apiId(), users = h.sends.get(2).apiId();
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                eq(1, repo.originals(soOrder).get(0).seq(), "original is #1");
                eq(1, repo.originals(users).get(0).seq(), "self original of the other API is #1");
                eq(List.of(3, 2), repo.page(soOrder, Long.MAX_VALUE, 50, Repo.Filter.ALL).stream().map(Rows.SendRow::seq).toList(),
                        "numbers read back from the DB");
            }
            eq(3, h.db.load().maxSeq.get(soOrder), "highest number reloaded (numbering continues after reopening)");
            // DB from an older version: rows without numbers get them on open, by time, originals first
            try (var st = h.db.writeConnection().createStatement()) {
                st.execute("UPDATE sends SET seq = NULL");
                st.execute("UPDATE originals SET seq = NULL");
            }
            h.db.backfillSeq();
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                eq(1, repo.originals(soOrder).get(0).seq(), "migration: original #1");
                eq(List.of(3, 2), repo.page(soOrder, Long.MAX_VALUE, 50, Repo.Filter.ALL).stream().map(Rows.SendRow::seq).toList(),
                        "migration: sends #2, #3");
                eq(List.of(2), repo.page(users, Long.MAX_VALUE, 50, Repo.Filter.ALL).stream().map(Rows.SendRow::seq).toList(),
                        "migration: numbering restarts per API");
            }
        }
        // log head lines: no "ORIGINAL" word, the API's own numbers
        Rows.OriginalRow o = new Rows.OriginalRow(17, 1, 0L, Rows.SRC_TABHOOK, "POST", "POST /x HTTP/1.1", 0, 0, 1);
        yes(apitracker.ui.UiProbe.head(o).startsWith("#1  ") && apitracker.ui.UiProbe.head(o).endsWith("(Repeater tab)")
                && !apitracker.ui.UiProbe.head(o).contains("ORIGINAL"), "original head line: " + apitracker.ui.UiProbe.head(o));
        Rows.SendRow s = new Rows.SendRow(88, 1, 17, 0L, 403, 82, 600, 0, "repeater", 0, "POST /x HTTP/1.1", "", 2);
        String hs = apitracker.ui.UiProbe.head(s, 1);
        yes(hs.startsWith("#2  ") && hs.endsWith("(vs original #1)"), "send head line: " + hs);
    }

    static final String USERS = "GET /api/v1/users HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer t\n\n";
    static final String ORDERS = "GET /api/v1/orders HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer t\n\n";

    static void trackerSiblings() throws Exception {
        try (Harness h = new Harness()) {
            // Proxy has a real /orders: a send to /orders is its own API, not merged into /users (which has a tracked original)
            h.tracker.setLookup((method, hostKey, pathKey, parked, token) -> h.tracker.submitInternal(
                    new Events.LookupResult(parked, token, pathKey.endsWith("/orders") ? h.src(ORDERS) : null, 1L)));
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(USERS)));
            h.tracker.drainForTest();
            h.send(USERS, 200);
            h.send(ORDERS.replace("Bearer t", "Bearer u"), 200);
            h.tracker.drainForTest();
            eq(2, h.sends.size(), "2 sends");
            yes(h.sends.get(0).apiId() != h.sends.get(1).apiId(), "orders is a separate API");
            yes(h.sends.get(1).changes().contains("Authorization"), "orders diff vs the orders Proxy original: " + h.sends.get(1).changes());
            yes(h.tested.contains("GET https://api.example.com:443/api/v1/orders"), "orders tested");
            yes(!h.tested.contains("GET https://api.example.com:443/api/v1/users"), "users not mismarked");
            // path not in Proxy, differs in exactly one segment: still merged into the original API (path edited to test)
            h.send(USERS.replace("/users", "/users'"), 500);
            h.tracker.drainForTest();
            Rows.SendRow v = h.sends.get(h.sends.size() - 1);
            eq(h.sends.get(0).apiId(), v.apiId(), "variant merged into users");
            yes(v.changes().contains("~ path    [2]   users → users'"), "diff path: " + v.changes());
        }
    }

    static void trackerAiNoOriginal() throws Exception {
        try (Harness h = new Harness()) {
            long now = System.nanoTime();
            h.tracker.submit(new Events.SendEvent(Events.KIND_AI, 1, now, System.currentTimeMillis(), h.src(ORDERS), "ai:claude"));
            h.tracker.submit(new Events.ResponseEvent(Events.KIND_AI, 1, now + 1000, 200, 10, null, h.src(ORDERS)));
            h.tracker.drainForTest();
            eq(1, h.sends.size(), "AI send logged");
            yes((h.sends.get(0).flags() & Rows.FLAG_NO_ORIGINAL) != 0, "no-original flag");
            eq(0, h.sends.get(0).originalId(), "no original");
            yes(h.tested.isEmpty(), "AI does not make the API tested without an original");
            // a human sends next: the human's first send becomes the original, not the AI request
            h.send(ORDERS.replace("Bearer t", "Bearer z"), 200);
            Rows.SendRow human = h.sends.get(1);
            yes((human.flags() & Rows.FLAG_SELF_ORIGINAL) != 0 && human.changes().isEmpty(), "original is the human send");
            h.writer.awaitIdle(3000);
            Db.State st = h.db.load();
            eq(1, st.originals.size(), "only one original (the human's)");
            eq("GET", st.apis.get(0).method(), "API method saved");
        }
    }

    static void trackerAiLookupOnce() throws Exception {
        try (Harness h = new Harness()) {
            List<Long> asked = new ArrayList<>();
            h.tracker.setLookup((method, hostKey, pathKey, parked, token) -> {
                asked.add(token);
                yes(h.tracker.lookupWanted(token), "token pending");
                h.tracker.submitInternal(new Events.LookupResult(parked, token, null, 0L));
            });
            for (int i = 1; i <= 5; i++) {
                long now = System.nanoTime();
                h.tracker.submit(new Events.SendEvent(Events.KIND_AI, i, now, System.currentTimeMillis(), h.src(ORDERS), "ai"));
                h.tracker.submit(new Events.ResponseEvent(Events.KIND_AI, i, now + 1000, 200, 10, null, h.src(ORDERS)));
                h.tracker.drainForTest();
            }
            eq(5, h.sends.size(), "5 AI sends");
            eq(1, asked.size(), "Proxy looked up only once in 30 s");
            yes(!h.tracker.lookupWanted(asked.get(0)), "finished token no longer pending");
        }
    }

    static void trackerNoise() throws Exception {
        try (Harness h = new Harness()) {
            String base = "GET /api/v1/me HTTP/1.1\nHost: api.example.com\nSec-Fetch-Site: none\nCookie: AWSALB=aaa; sid=1\n\n";
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(base)));
            h.tracker.drainForTest();
            h.send(base.replace("AWSALB=aaa", "AWSALB=bbb").replace("Sec-Fetch-Site: none", "Sec-Fetch-Site: same-origin"), 200);
            yes(!h.sends.get(0).changes().isEmpty(), "changes still shown in the log");
            yes(h.tested.isEmpty(), "noise only: not tested");
            h.send(base.replace("sid=1", "sid=2"), 200);
            eq(1, h.tested.size(), "session cookie changed: tested");
        }
    }

    static void trackerTruncated() throws Exception {
        try (Harness h = new Harness()) {
            String big = "POST /upload HTTP/1.1\nHost: api.example.com\nContent-Type: application/octet-stream\n\n" + "A".repeat(1_500_000);
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(big)));
            h.tracker.drainForTest();
            h.send(big, 200);
            eq("", h.sends.get(0).changes(), "no change (cache)");
            h.writer.awaitIdle(3000);
            // reload from DB as on the next Burp start: only the first 1 MB of the original remains
            StatusIndex st2 = new StatusIndex();
            Tracker t2 = new Tracker(new ApiKeys(), st2, new KeyRegistry(), h.writer, h.settings, h.tracker.redactor());
            Db.State loaded = h.db.load();
            yes(loaded.originals.get(0).requestZ() == null, "opening the project does not load originals into RAM");
            Db.OriginalLoader ol = h.db.newOriginalLoader();
            t2.setOriginalLoader(ol::load);
            t2.load(loaded);
            List<Rows.SendRow> got = new ArrayList<>();
            t2.setListener(new Tracker.Listener() {
                @Override public void apiChanged(Rows.ApiRow row) {}
                @Override public void sendAdded(Rows.SendRow row) { got.add(row); }
            });
            long now = System.nanoTime();
            t2.submit(new Events.SendEvent(Events.KIND_REPEATER, 500, now, System.currentTimeMillis(), h.src(big), "repeater"));
            t2.submit(new Events.ResponseEvent(Events.KIND_REPEATER, 500, now + 1000, 200, 1, null, h.src(big)));
            t2.drainForTest();
            eq(1, got.size(), "logged after reload");
            eq("", got.get(0).changes(), "no bogus body diff");
            eq(StatusIndex.SENT, st2.get("POST https://api.example.com:443/upload"), "does not become tested");
            yes((got.get(0).flags() & Rows.FLAG_RAW_DROPPED) == 0, "1.5 MB still stores the raw request (< 4 MB)");
        }
    }

    static void trackerStaleLookup() throws Exception {
        try (Harness h = new Harness()) {
            List<long[]> tokens = new ArrayList<>();
            List<String> parkedKeys = new ArrayList<>();
            h.tracker.setLookup((method, hostKey, pathKey, parked, token) -> { tokens.add(new long[]{token}); parkedKeys.add(parked); });
            h.send(USERS, 200);
            eq(0, h.sends.size(), "awaiting lookup");
            // wait timed out: becomes its own original
            h.tracker.sweepForTest(System.nanoTime() + 60_000_000_000L);
            eq(1, h.sends.size(), "logged after timeout");
            // a late result of an old lookup, arriving while another API waits on the same key: dropped
            h.send(ORDERS, 200);
            eq(2, tokens.size(), "second lookup");
            h.tracker.submitInternal(new Events.LookupResult(parkedKeys.get(1), tokens.get(0)[0], h.src(ORDERS), 1L));
            h.tracker.drainForTest();
            eq(1, h.sends.size(), "old token does not release the new wait");
            h.tracker.submitInternal(new Events.LookupResult(parkedKeys.get(1), tokens.get(1)[0], null, 0L));
            h.tracker.drainForTest();
            eq(2, h.sends.size(), "correct token releases");
        }
    }

    static void writerLifecycle() throws Exception {
        Path dir = Files.createTempDirectory("apitracker-w");
        Db db = Db.open(Db.chooseFile(dir, "W", "pid-w", null), "pid-w", false);
        DbWriter w = new DbWriter(db.writeConnection(), false);
        w.start();
        // large secondary commands are dropped over the byte budget, primary commands still get in
        yes(w.submit(DbWriter.insertApi(1, "https://h:443", "/a", "GET", 1L)), "primary command");
        int accepted = 0;
        for (int i = 0; i < 100; i++) if (w.submit(DbWriter.insertBlob(i, new byte[1024 * 1024]))) accepted++;
        yes(accepted < 100, "queue byte limit: accepted " + accepted + "/100");
        boolean done = w.stop(5_000);
        yes(done, "writer thread stopped");
        yes(!w.closeWhenDone(db::close), "already stopped: caller closes");
        db.close();
        // reopen: lock released, writable
        Db again = Db.open(db.file, "pid-w", false);
        yes(!again.readOnly, "reopened for writing");
        eq(1, again.load().apis.size(), "API written");
        again.close();
    }

    static void repoSearch() throws Exception {
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG)));
            h.tracker.drainForTest();
            h.send(ORIG.replace("\"qty\":100", "\"qty\":-1"), 400);
            h.send(ORIG.replace("\"accountNo\":\"0001\"", "\"accountNo\":\"0002\""), 200);
            h.send(ORIG.replace("Cookie: SESSION=abc123; lang=vi\n", ""), 401);
            h.writer.awaitIdle(3000);
            int apiId = h.sends.get(0).apiId();
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                eq(1, repo.search(apiId, "accountNo", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 200).size(), "FTS accountNo");
                eq(1, repo.search(apiId, "ACCOUNTNO", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 200).size(), "case-insensitive");
                eq(1, repo.search(apiId, "$.qty", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 200).size(), "special characters");
                eq(0, repo.search(apiId, "\"; DROP TABLE sends; --", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 200).size(), "odd string, no error");
                eq(1, repo.search(apiId, "-1", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 200).size(), "short term uses LIKE");
                eq(1, repo.page(apiId, Long.MAX_VALUE, 200, new Repo.Filter(Diff.LOC_COOKIE, 0, 0)).size(), "chip cookie");
                eq(1, repo.page(apiId, Long.MAX_VALUE, 200, new Repo.Filter(0, Repo.ST_2XX, 0)).size(), "chip 2xx");
                eq(2, repo.page(apiId, Long.MAX_VALUE, 200, new Repo.Filter(0, Repo.ST_4XX, 0)).size(), "chip 4xx");
                eq(0, repo.page(apiId, Long.MAX_VALUE, 200, new Repo.Filter(0, 0, Repo.SRC_AI)).size(), "chip AI");
                eq(3, repo.page(apiId, Long.MAX_VALUE, 200, new Repo.Filter(0, 0, Repo.SRC_REPEATER)).size(), "chip Repeater");
                eq(0, repo.page(apiId, Long.MAX_VALUE, 200, new Repo.Filter(0, 0, Repo.SRC_INTRUDER)).size(), "chip Intruder");
                Map<Integer, Integer> all = repo.searchAll("accountNo", List.of());
                eq(1, all.get(apiId), "search all APIs");
                List<Rows.SendRow> p1 = repo.page(apiId, Long.MAX_VALUE, 2, Repo.Filter.ALL);
                List<Rows.SendRow> p2 = repo.page(apiId, p1.get(1).id(), 2, Repo.Filter.ALL);
                eq(1, p2.size(), "keyset pagination");
            }
        }
    }

    // ---------------- Intruder ----------------

    static final String IBASE = "POST /api/v1/orders/place?id=1001&lang=vi HTTP/1.1\nHost: api.example.com\n"
            + "Authorization: Bearer tokenA\nCookie: sid=s1; theme=dark\nContent-Type: application/json\n"
            + "Content-Length: 61\nX-Trace: t\n\n{\"account\":{\"no\":\"0001\"},\"items\":[{\"qty\":1},{\"qty\":2}],\"note\":\"hi\"}";

    static FieldLocator.Field locate(String raw, String mark) {
        byte[] b = req(raw);
        String s = new String(b, StandardCharsets.ISO_8859_1);
        int at = s.indexOf(mark);
        return FieldLocator.locate(b, FieldLocator.parts(b), at, at + mark.length());
    }

    static void fieldLocator() {
        eq(new FieldLocator.Field(Diff.LOC_METHOD, ""), locate(IBASE, "POST"), "method");
        eq(new FieldLocator.Field(Diff.LOC_PATH, "[3]"), locate(IBASE, "place"), "segment path");
        eq(new FieldLocator.Field(Diff.LOC_QUERY, "id"), locate(IBASE, "1001"), "query");
        eq(new FieldLocator.Field(Diff.LOC_HEADER, "Authorization"), locate(IBASE, "tokenA"), "header");
        eq(new FieldLocator.Field(Diff.LOC_COOKIE, "theme"), locate(IBASE, "dark"), "cookie");
        eq(new FieldLocator.Field(Diff.LOC_BODY, "$.account.no"), locate(IBASE, "0001"), "nested JSON");
        byte[] b = req(IBASE);
        String s = new String(b, StandardCharsets.ISO_8859_1);
        int q2 = s.indexOf("\"qty\":2") + 6;
        eq(new FieldLocator.Field(Diff.LOC_BODY, "$.items[1].qty"), FieldLocator.locate(b, FieldLocator.parts(b), q2, q2 + 1), "array");
        yes(locate(IBASE, "orders/place") == null, "spans two segments: not located");
        yes(locate(IBASE, "1001&lang") == null, "spans two params: not located");
        String form = "POST /f HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\nuser=alice&pin=1234";
        eq(new FieldLocator.Field(Diff.LOC_BODY, "pin"), locate(form, "1234"), "form");
        String text = "POST /t HTTP/1.1\nHost: h\nContent-Type: text/xml\n\n<r><amount>500</amount></r>";
        eq(new FieldLocator.Field(Diff.LOC_BODY, "amount"), locate(text, "500"), "body text by name");
    }

    /** Every single-field mutation: if the fast path locates it, the name must match the slow path (full parse). */
    static void fieldLocatorMatchesDiff() {
        String[][] muts = {
                {"POST /api", "PUT /api"}, {"place?", "cancel?"}, {"id=1001", "id=1"}, {"lang=vi", "lang=en'"},
                {"Bearer tokenA", "Bearer tokenBBBB"}, {"sid=s1", "sid=zz"}, {"\"0001\"", "\"0002' OR 1=1\""},
                {"\"qty\":2", "\"qty\":-99"}, {"\"note\":\"hi\"", "\"note\":\"<script>\""}, {"X-Trace: t", "X-Trace: ../../etc"}};
        ParsedReq a = ParsedReq.parse(req(IBASE));
        int fast = 0;
        for (String[] m : muts) {
            String mod = IBASE.replace(m[0], m[1]);
            byte[] x = req(IBASE), y = req(mod);
            FieldLocator.Parts px = FieldLocator.parts(x), py = FieldLocator.parts(y);
            long[] d = IntruderTracker.chunkDiffs(x, px, y, py);
            List<FieldLocator.Field> got = new ArrayList<>();
            boolean ok = true;
            for (int k = 0; k < d.length; k += 4) {
                if (d[k] == d[k + 1] && d[k + 2] == d[k + 3]) continue;
                FieldLocator.Field f = FieldLocator.locate(x, px, (int) d[k], (int) d[k + 1]);
                if (f == null) { ok = false; break; }
                got.add(f);
            }
            List<FieldLocator.Field> slow = Diff.changedFields(a, ParsedReq.parse(y), Set.of("content-length", "connection"));
            if (ok) { fast++; eq(slow, got, "fast = slow for " + m[0] + " → " + m[1]); }
        }
        yes(fast >= 9, "most mutations take the fast path: " + fast + "/" + muts.length);
    }

    static final class Sink implements java.util.function.Predicate<Events.AttackEvent> {
        final List<Events.AttackEvent> events = new ArrayList<>();
        @Override public boolean test(Events.AttackEvent e) { events.add(e); return true; }
        Events.AttackEvent last() { return events.get(events.size() - 1); }
        long attacks() { return events.stream().map(Events.AttackEvent::attackId).distinct().count(); }
    }

    /** Runs a batch of requests through IntruderTracker, returns the sink. */
    static Sink attack(List<IntruderTracker.Hit> hits) {
        Sink sink = new Sink();
        IntruderTracker it = new IntruderTracker(new Settings(), sink);
        for (IntruderTracker.Hit h : hits) { it.submit(h); it.drainForTest(); }
        it.finishAllForTest();
        return sink;
    }

    static IntruderTracker.Hit hit(String raw, int status) {
        byte[] b = req(raw);
        return new IntruderTracker.Hit(System.nanoTime(), System.currentTimeMillis(), status, 100 + b.length,
                new Events.StaticRequest(b, "api.example.com", 443, true));
    }

    static String withBody(String raw, String body) {
        int i = raw.indexOf("\n\n");
        String head = raw.substring(0, i).replaceAll("Content-Length: \\d+", "Content-Length: " + body.length());
        return head + "\n\n" + body;
    }

    static List<String> names(Events.AttackEvent e) {
        List<String> out = new ArrayList<>();
        for (FieldLocator.Field f : e.positions()) out.add(Diff.locName(f.loc()) + " " + f.name());
        return out;
    }

    static void intruderPositions() {
        Settings settings = new Settings();
        String body = "{\"account\":{\"no\":\"0001\"},\"items\":[{\"qty\":1},{\"qty\":2}],\"note\":\"hi\"}";
        // sniper: position 1 = query id (50 payloads), position 2 = $.account.no (50 payloads, length changes → Content-Length changes)
        Sink sink = new Sink();
        IntruderTracker it = new IntruderTracker(settings, sink);
        for (int i = 0; i < 50; i++) it.submit(hit(IBASE.replace("id=1001", "id=" + (i * 37)), 200));
        for (int i = 0; i < 50; i++) {
            it.submit(hit(withBody(IBASE, body.replace("0001", "x".repeat(i % 7 + 1))), i % 10 == 0 ? 500 : 200));
        }
        it.drainForTest();
        it.finishAllForTest();
        Events.AttackEvent e = sink.last();
        yes(e.finished(), "attack finished");
        eq(100, e.requests(), "counts 100 requests");
        eq(List.of("query id", "body $.account.no"), names(e), "sniper: exactly 2 positions");
        eq(1L, sink.events.stream().map(Events.AttackEvent::attackId).distinct().count(), "one attack");
        eq(5, e.statuses().get(500), "status stats");
        yes(it.slowPath.sum() <= 2, "sniper almost all fast path (slow " + it.slowPath.sum() + ")");

        // pitchfork: 2 positions change together → slow path, positions still correct
        Sink s2 = new Sink();
        IntruderTracker pf = new IntruderTracker(settings, s2);
        for (int i = 0; i < 20; i++) {
            pf.submit(hit(IBASE.replace("Bearer tokenA", "Bearer t" + i).replace("theme=dark", "theme=" + i), 200));
        }
        pf.drainForTest();
        pf.finishAllForTest();
        eq(List.of("header Authorization", "cookie theme"), names(s2.last()), "pitchfork");

        // fuzz path: GET /api/v1/§word§
        Sink s3 = new Sink();
        IntruderTracker pt = new IntruderTracker(settings, s3);
        for (String w : new String[]{"admin", "backup", "config", ".git", "debug"}) {
            pt.submit(hit("GET /api/v1/" + w + " HTTP/1.1\nHost: api.example.com\nAccept: */*\n\n", 404));
        }
        pt.drainForTest();
        pt.finishAllForTest();
        eq(List.of("path [2]"), names(s3.last()), "fuzz path: one position");
        eq(1L, s3.events.stream().map(Events.AttackEvent::attackId).distinct().count(), "fuzz path: one attack though each path is its own API");

        // two completely different attacks on the same host are not merged
        Sink s4 = new Sink();
        IntruderTracker two = new IntruderTracker(settings, s4);
        for (int i = 0; i < 5; i++) two.submit(hit(IBASE.replace("id=1001", "id=" + i), 200));
        for (int i = 0; i < 5; i++) {
            two.submit(hit("GET /static/very/different/endpoint/with/long/path?q=" + i + " HTTP/1.1\nHost: api.example.com\n"
                    + "User-Agent: completely-different-client/1.0\nAccept-Language: vi\n\n", 200));
        }
        two.drainForTest();
        two.finishAllForTest();
        eq(2L, s4.events.stream().map(Events.AttackEvent::attackId).distinct().count(), "two separate attacks");
    }

    static void intruderLog() throws Exception {
        try (Harness h = new Harness()) {
            String orig = IBASE;
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(orig)));
            h.tracker.drainForTest();
            IntruderTracker it = new IntruderTracker(h.settings, h.tracker::submit);
            for (int i = 0; i < 30; i++) it.submit(hit(IBASE.replace("id=1001", "id=" + i + "'"), i < 25 ? 200 : 500));
            it.drainForTest();                          // first snapshot (positions seen) → row inserted
            h.tracker.drainForTest();
            eq(1, h.sends.size(), "one log row for the whole attack");
            Rows.SendRow first = h.sends.get(0);
            yes((first.flags() & Rows.FLAG_INTRUDER) != 0 && (first.flags() & Rows.FLAG_RUNNING) != 0, "Intruder row running");
            yes(first.firstLine().contains("id=§"), "head line as template: " + first.firstLine());
            for (int i = 0; i < 20; i++) it.submit(hit(IBASE.replace("Bearer tokenA", "Bearer x" + i), 200));
            it.drainForTest();
            it.finishAllForTest();
            h.tracker.drainForTest();
            Rows.SendRow last = h.sends.get(h.sends.size() - 1);
            eq(first.id(), last.id(), "same row updated");
            yes((last.flags() & Rows.FLAG_RUNNING) == 0, "finished");
            yes(last.changes().contains("§ query   id") && last.changes().contains("§ header  Authorization"), "positions: " + last.changes());
            yes(last.changes().contains("50 requests") && last.changes().contains("500×5"), "stats: " + last.changes());
            yes(!last.changes().contains("tokenA") && !last.changes().contains("x1"), "payloads not logged");
            eq(StatusIndex.TESTED, h.status.get("POST https://api.example.com:443/api/v1/orders/place"), "API becomes tested");
            h.writer.awaitIdle(3000);
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                List<Rows.SendRow> rows = repo.page(last.apiId(), Long.MAX_VALUE, 50, new Repo.Filter(0, 0, Repo.SRC_INTRUDER));
                eq(1, rows.size(), "DB: one Intruder row");
                yes(rows.get(0).changes().contains("§ header  Authorization"), "DB has the last update");
                eq(1, repo.search(last.apiId(), "intruder", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 10).size(), "search 'intruder'");
                byte[] raw = repo.sendRaw(last.id());
                yes(raw != null && new String(raw, StandardCharsets.UTF_8).startsWith("POST /api/v1/orders/place?id=0'"), "first request of the attack");
            }
            Db.State st = h.db.load();
            eq(1, st.apis.get(0).sendCount(), "attack counts as one send");
        }
        // API hit only by Intruder (no original yet): still shown as "tested"
        try (Harness h = new Harness()) {
            IntruderTracker it = new IntruderTracker(h.settings, h.tracker::submit);
            for (int i = 0; i < 4; i++) it.submit(hit(IBASE.replace("id=1001", "id=" + i), 200));
            it.drainForTest();
            it.finishAllForTest();
            h.tracker.drainForTest();
            yes(h.apiRows.get(h.apiRows.size() - 1).tested(), "Intruder-only API shown as tested");
            eq("POST", h.apiRows.get(h.apiRows.size() - 1).method(), "API method from Intruder");
        }
        // path fuzzing with an existing API: attached to the API matching the template
        try (Harness h = new Harness()) {
            String o = "GET /api/v1/users HTTP/1.1\nHost: api.example.com\nAccept: */*\n\n";
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(o)));
            h.tracker.drainForTest();
            IntruderTracker it = new IntruderTracker(h.settings, h.tracker::submit);
            for (String w : new String[]{"admin", "backup", "config"}) it.submit(hit(o.replace("users", w), 404));
            it.drainForTest();
            it.finishAllForTest();
            h.tracker.drainForTest();
            Rows.SendRow r = h.sends.get(h.sends.size() - 1);
            h.writer.awaitIdle(3000);
            Db.State st = h.db.load();
            eq(2, st.apis.size(), "no new API per payload path: only the template API /api/v1/§ is added");
            yes(h.apiRows.get(h.apiRows.size() - 1).tested(), "template API shown as tested");
            yes(st.apis.stream().anyMatch(a -> a.id() == r.apiId() && a.pathKey().equals("/api/v1/§")), "attack attached to the template API");
            yes(h.status.get("GET https://api.example.com:443/api/v1/users") != StatusIndex.TESTED, "/users not considered tested");
            yes(r.firstLine().startsWith("GET /api/v1/§"), "head line: " + r.firstLine());
        }
    }

    static void storage() throws Exception {
        byte[] orig = req(ORIG);
        byte[] send = req(ORIG.replace("\"qty\":100", "\"qty\":-1"));
        byte[] dict = apitracker.store.Zip.dictOf(orig);
        byte[] plain = apitracker.store.Zip.deflate(send);
        byte[] delta = apitracker.store.Zip.deflate(send, dict);
        yes(java.util.Arrays.equals(send, apitracker.store.Zip.inflate(delta, dict)), "dictionary decompression correct");
        yes(apitracker.store.Zip.inflate(delta, null) == null, "missing dictionary: returns null, no error");
        yes(java.util.Arrays.equals(send, apitracker.store.Zip.inflate(plain)), "old data still readable");
        System.out.printf("     raw request: %d B → plain deflate %d B → deflate vs original %d B%n", send.length, plain.length, delta.length);
        yes(delta.length * 3 < plain.length, "original-based compression at least 3x smaller");
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG)));
            h.tracker.drainForTest();
            for (int i = 0; i < 30; i++) h.send(ORIG.replace("\"qty\":100", "\"qty\":" + i), 200);
            h.writer.awaitIdle(3000);
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                long id = h.sends.get(7).id();
                yes(new String(repo.sendRaw(id), StandardCharsets.UTF_8).contains("\"qty\":7"), "send's raw request read back");
                yes(repo.blob(id).length < 120, "small stored copy: " + repo.blob(id).length + " B");
            }
            eq(30, h.db.load().apis.get(0).sendCount(), "30 sends across batches: counter correct");
        }
    }

    static void searchPlans() throws Exception {
        String[] t = apitracker.ui.SearchTerms.terms("  POST  Order ");
        eq(List.of("post", "order"), List.of(t), "split terms");
        yes(apitracker.ui.SearchTerms.matchesAll("post /so-order https://h:443", t), "matches all terms");
        yes(!apitracker.ui.SearchTerms.matchesAll("get /so-order https://h:443", t), "one missing term means no match");
        yes(apitracker.ui.SearchTerms.narrows(apitracker.ui.SearchTerms.terms("ord"), apitracker.ui.SearchTerms.terms("order")), "typing more: narrows");
        yes(apitracker.ui.SearchTerms.narrows(apitracker.ui.SearchTerms.terms("post"), t), "adding a term: narrows");
        yes(!apitracker.ui.SearchTerms.narrows(apitracker.ui.SearchTerms.terms("order"), apitracker.ui.SearchTerms.terms("ord")), "deleting characters: does not narrow");
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG)));
            h.tracker.drainForTest();
            for (int i = 0; i < 40; i++) h.send(ORIG.replace("\"qty\":100", "\"qty\":" + (i % 3 == 0 ? "-1" : i)), 200);
            h.writer.awaitIdle(3000);
            int apiId = h.sends.get(0).apiId();
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                for (String q : new String[]{"$.qty", "-1", "QTY", "accountNo", "kh\u00f4ng c\u00f3"}) {   // non-ASCII term with no match
                    List<Long> like = repo.search(apiId, q, List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 200, 40)
                            .stream().map(Rows.SendRow::id).toList();
                    List<Long> fts = repo.search(apiId, q, List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 200, Integer.MAX_VALUE)
                            .stream().map(Rows.SendRow::id).toList();
                    eq(fts, like, "LIKE (small API) = FTS (large API) for '" + q + "'");
                }
            }
        }
    }

    static void intruderReviewCases() throws Exception {
        // long payloads (300–500 B) on a small form request: still one attack
        String form = "POST /login HTTP/1.1\nHost: api.example.com\nContent-Type: application/x-www-form-urlencoded\n\nuser=admin&pass=x";
        List<IntruderTracker.Hit> hits = new ArrayList<>();
        java.util.Random rnd = new java.util.Random(1);
        for (int i = 0; i < 200; i++) {
            StringBuilder p = new StringBuilder();
            for (int k = 0, n = 300 + rnd.nextInt(200); k < n; k++) p.append((char) ('a' + rnd.nextInt(26)));
            hits.add(hit(withBody(form, "user=admin&pass=" + p), 200));
        }
        Sink s = attack(hits);
        eq(1L, s.attacks(), "long payload: one attack");
        eq(List.of("body pass"), names(s.last()), "long payload: correct position");

        // cluster bomb 60 × 3 and sniper 2 positions × 60: one attack, all positions
        hits.clear();
        for (int u = 0; u < 3; u++) for (int p = 0; p < 60; p++) hits.add(hit(withBody(form, "user=u" + u + "&pass=p" + p), 200));
        s = attack(hits);
        eq(1L, s.attacks(), "cluster bomb: one attack");
        eq(java.util.Set.of("body user", "body pass"), new java.util.HashSet<>(names(s.last())), "cluster bomb: two positions");
        hits.clear();
        for (int p = 0; p < 60; p++) hits.add(hit(withBody(form, "user=v" + p + "&pass=x"), 200));
        for (int p = 0; p < 60; p++) hits.add(hit(withBody(form, "user=admin&pass=w" + p), 200));
        s = attack(hits);
        eq(1L, s.attacks(), "sniper 2 positions: one attack");
        eq(List.of("body user", "body pass"), names(s.last()), "sniper: two positions");

        // fuzzing param name / JSON key / header name: one shared position, payloads not logged
        hits.clear();
        for (String w : new String[]{"debug", "admin", "isAdmin", "test"}) hits.add(hit("GET /a?" + w + "=1&x=2 HTTP/1.1\nHost: h\n\n", 200));
        eq(List.of("query (param name)"), names(attack(hits).last()), "fuzz query param name");
        hits.clear();
        for (String w : new String[]{"role", "isAdmin", "debug"}) hits.add(hit(withBody("POST /j HTTP/1.1\nHost: h\nContent-Type: application/json\nContent-Length: 1\n\n{}", "{\"" + w + "\":true,\"x\":1}"), 200));
        eq(List.of("body (field name)"), names(attack(hits).last()), "fuzz JSON key");
        hits.clear();
        for (String w : new String[]{"X-Forwarded-For", "X-Real-IP", "X-Originating-IP"}) hits.add(hit("GET /h HTTP/1.1\nHost: h\n" + w + ": 127.0.0.1\nAccept: */*\n\n", 200));
        eq(List.of("header (header name)"), names(attack(hits).last()), "fuzz header name");

        // payload breaks the JSON: still one name $.id (no extra "(body)")
        hits.clear();
        String jb = "POST /j HTTP/1.1\nHost: h\nContent-Type: application/json\nContent-Length: 1\n\n";
        for (String v : new String[]{"1", "1\"", "2", "'\"", "3"}) hits.add(hit(withBody(jb + "{}", "{\"id\":\"" + v + "\",\"n\":1}"), 200));
        eq(List.of("body $.id"), names(attack(hits).last()), "JSON broken by payload");

        // payload containing '/' in path: one position path [1]
        hits.clear();
        for (String v : new String[]{"a", "../etc/passwd", "b", "x/y"}) hits.add(hit("GET /files/" + v + " HTTP/1.1\nHost: h\n\n", 200));
        eq(List.of("path [1]"), names(attack(hits).last()), "payload containing '/'");

        // battering ram on two XML fields: both positions
        hits.clear();
        String xb = "POST /x HTTP/1.1\nHost: h\nContent-Type: text/xml\nContent-Length: 1\n\n";
        for (String v : new String[]{"a", "bb", "ccc", "' OR 1=1"}) hits.add(hit(withBody(xb + "x", "<r><user>" + v + "</user><pin>" + v + "</pin></r>"), 200));
        eq(java.util.Set.of("body user", "body pin"), new java.util.HashSet<>(names(attack(hits).last())), "XML battering ram");

        // slow attack (9 s between responses): still one attack
        Sink slow = new Sink();
        IntruderTracker it = new IntruderTracker(new Settings(), slow);
        long[] t = {1_000_000_000L};
        it.setClockForTest(() -> t[0]);
        for (int i = 0; i < 6; i++) {
            it.submit(hit(form.replace("pass=x", "pass=sleep(" + i + ")"), 200));
            it.drainForTest();
            t[0] += 9_000_000_000L;
            it.sweepForTest(t[0]);
        }
        it.finishAllForTest();
        eq(1L, slow.attacks(), "slow attack: one attack");
        eq(6, slow.last().requests(), "slow attack: all 6 requests");

        // auto-followed redirect requests are not counted in the attack
        Sink rd = new Sink();
        IntruderTracker r2 = new IntruderTracker(new Settings(), rd);
        byte[] b1 = req(form.replace("pass=x", "pass=1"));
        r2.submit(new IntruderTracker.Hit(1, 1, 302, 0, "/home", 0, new Events.StaticRequest(b1, "api.example.com", 443, true)));
        r2.submit(hit("GET /home HTTP/1.1\nHost: api.example.com\nCookie: JSESSIONID=abc\n\n", 200));
        r2.submit(hit(form.replace("pass=x", "pass=2"), 200));
        r2.drainForTest();
        r2.finishAllForTest();
        eq(1L, r2.followUps.sum(), "redirect follow-up request skipped");
        eq(2, rd.last().requests(), "attack has only 2 attack requests");

        // two consecutive attacks on sibling endpoints (IDOR /users/§id§ then /orders/§id§): two rows, one position each
        hits.clear();
        for (int i = 0; i < 60; i++) hits.add(hit("GET /api/users/" + (1000 + i) + " HTTP/1.1\nHost: h\nAccept: */*\n\n", 200));
        for (int i = 0; i < 60; i++) hits.add(hit("GET /api/orders/" + (5000 + i) + " HTTP/1.1\nHost: h\nAccept: */*\n\n", 200));
        Sink sib = attack(hits);
        eq(2L, sib.attacks(), "sibling endpoints: two attacks");
        yes(sib.events.stream().filter(Events.AttackEvent::finished).allMatch(e -> names(e).equals(List.of("path [2]"))),
                "each attack has only position path [2]");

        // time-based SQLi: 20 fast requests, one 29 s sleep request, 20 fast requests: one attack
        Sink tb = new Sink();
        IntruderTracker tbi = new IntruderTracker(new Settings(), tb);
        long[] clk = {1_000_000_000L};
        tbi.setClockForTest(() -> clk[0]);
        for (int i = 0; i < 41; i++) {
            clk[0] += i == 20 ? 29_000_000_000L : 100_000_000L;
            tbi.sweepForTest(clk[0] - 1);
            tbi.submit(hit(form.replace("pass=x", "pass=" + (i == 20 ? "sleep(29)" : "p" + i)), 200));
            tbi.drainForTest();
        }
        tbi.finishAllForTest();
        eq(1L, tb.attacks(), "time-based SQLi: one attack");
        eq(41, tb.last().requests(), "all 41 requests");

        // two in-flight redirects to the same target: both follow-ups counted; a POST to the Location URL is not swallowed
        Sink rd2 = new Sink();
        IntruderTracker r3 = new IntruderTracker(new Settings(), rd2);
        String post = form.replace("POST /login", "POST /home");
        for (int i = 0; i < 2; i++) {
            r3.submit(new IntruderTracker.Hit(1, 1, 302, 0, "/home", 0,
                    new Events.StaticRequest(req(post.replace("pass=x", "pass=r" + i)), "api.example.com", 443, true)));
        }
        r3.submit(hit("GET /home HTTP/1.1\nHost: api.example.com\nCookie: JSESSIONID=a\n\n", 200));
        r3.submit(hit("GET /home HTTP/1.1\nHost: api.example.com\nCookie: JSESSIONID=b\n\n", 200));
        r3.submit(hit(post.replace("pass=x", "pass=r9"), 200));
        r3.drainForTest();
        r3.finishAllForTest();
        eq(2L, r3.followUps.sum(), "both redirect follow-ups counted");
        eq(1L, rd2.attacks(), "no bogus attack on GET /home");
        eq(3, rd2.last().requests(), "POST to the same URL is still an attack request");

        // a lone request that fits no attack: no row logged
        Sink lone = attack(List.of(hit("GET /x HTTP/1.1\nHost: h\n\n", 200)));
        eq(0L, lone.attacks(), "lone request not logged");

        // query param name fuzzing: head line does not leak payload names
        try (Harness h = new Harness()) {
            IntruderTracker nf = new IntruderTracker(h.settings, h.tracker::submit);
            for (String w : new String[]{"secretDebugFlag", "admin", "isAdmin"}) nf.submit(hit("GET /a?" + w + "=1&x=2 HTTP/1.1\nHost: h\n\n", 200));
            nf.drainForTest();
            nf.finishAllForTest();
            h.tracker.drainForTest();
            Rows.SendRow r = h.sends.get(h.sends.size() - 1);
            yes(r.firstLine().equals("GET /a?§ HTTP/1.1") && !r.changes().contains("secretDebugFlag"), "payload name not leaked: " + r.firstLine());
        }

        // fuzzing /api/§ from /api/users while /api/orders was used more recently: not attached to /api/orders
        try (Harness h = new Harness()) {
            String users = "GET /api/users HTTP/1.1\nHost: api.example.com\nAccept: */*\n\n";
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(users)));
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis() + 1000, h.src(users.replace("users", "orders"))));
            h.tracker.drainForTest();
            IntruderTracker pt = new IntruderTracker(h.settings, h.tracker::submit);
            for (String w : new String[]{"admin", "backup", "config"}) pt.submit(hit(users.replace("users", w), 404));
            pt.drainForTest();
            pt.finishAllForTest();
            h.tracker.drainForTest();
            Rows.SendRow r = h.sends.get(h.sends.size() - 1);
            h.writer.awaitIdle(3000);
            Db.State st = h.db.load();
            String path = st.apis.stream().filter(a -> a.id() == r.apiId()).findFirst().map(Db.ApiRec::pathKey).orElse("?");
            eq("/api/§", path, "path fuzzing attached to the template API");
            yes(h.status.get("GET https://api.example.com:443/api/orders") != StatusIndex.TESTED, "sibling API not marked tested");
            // status filter: an attack with both 200 and 500 shows under the 5xx chip
            IntruderTracker mixed = new IntruderTracker(h.settings, h.tracker::submit);
            for (int i = 0; i < 10; i++) mixed.submit(hit(users.replace("Accept: */*", "Accept: a" + i), i == 3 ? 500 : 200));
            mixed.drainForTest();
            mixed.finishAllForTest();
            h.tracker.drainForTest();
            h.writer.awaitIdle(3000);
            Rows.SendRow mr = h.sends.get(h.sends.size() - 1);
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                eq(1, repo.page(mr.apiId(), Long.MAX_VALUE, 50, new Repo.Filter(0, Repo.ST_5XX, Repo.SRC_INTRUDER)).size(), "5xx chip finds the attack with a 500");
            }
        }

        // a stuck "running" row (Burp killed) is cleared on reopen; an update with no row creates one
        Path dir = Files.createTempDirectory("apitracker-run");
        Path f = Db.chooseFile(dir, "R", "pid-r", null);
        Db db = Db.open(f, "pid-r", false);
        DbWriter w = new DbWriter(db.writeConnection(), false);
        w.start();
        w.submit(DbWriter.insertApi(1, "https://h:443", "/a", "GET", 1L));
        Rows.SendRow running = new Rows.SendRow(5, 1, 0, 1L, 200, 10, 1, Rows.FLAG_INTRUDER | Rows.FLAG_RUNNING, "intruder", 32, "GET /a", "§ body    x");
        w.submit(DbWriter.updateSend(running, "intruder get /a", 1));
        w.stop(3000);
        db.close();
        Db again = Db.open(f, "pid-r", false);
        try (Repo repo = new Repo(again.newReadConnection())) {
            List<Rows.SendRow> rows = repo.page(1, Long.MAX_VALUE, 10, Repo.Filter.ALL);
            eq(1, rows.size(), "upsert creates the row if missing");
            eq(0, rows.get(0).flags() & Rows.FLAG_RUNNING, "running flag cleared on reopen");
        }
        eq(1, again.load().apis.get(0).sendCount(), "upsert counts as one send");
        again.close();

        // original request unreadable: no empty copy cached, no bogus diff, not marked tested
        try (Harness h = new Harness()) {
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(ORIG)));
            h.tracker.drainForTest();
            h.writer.awaitIdle(3000);
            StatusIndex st2 = new StatusIndex();
            Tracker t2 = new Tracker(new ApiKeys(), st2, new KeyRegistry(), h.writer, h.settings, h.tracker.redactor());
            t2.setOriginalLoader(id -> null);
            t2.load(h.db.load());
            List<Rows.SendRow> got = new ArrayList<>();
            t2.setListener(new Tracker.Listener() {
                @Override public void apiChanged(Rows.ApiRow row) {}
                @Override public void sendAdded(Rows.SendRow row) { got.add(row); }
            });
            long now = System.nanoTime();
            t2.submit(new Events.SendEvent(Events.KIND_REPEATER, 900, now, System.currentTimeMillis(), h.src(ORIG), "repeater"));
            t2.submit(new Events.ResponseEvent(Events.KIND_REPEATER, 900, now + 1000, 200, 1, null, h.src(ORIG)));
            t2.drainForTest();
            yes((got.get(0).flags() & Rows.FLAG_ORIGINAL_UNAVAILABLE) != 0 && got.get(0).changes().isEmpty(), "logged without diff");
            yes(st2.get("POST https://api.example.com:443/condition-orders/underlying-order/api/v1/so-order") != StatusIndex.TESTED, "does not become tested");
        }

        // searching accented text (Vietnamese, as Unicode escapes): LIKE (small API) and FTS (large API) give the same results
        try (Harness h = new Harness()) {
            String vi = "POST /n HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"note\":\"a\"}";
            h.tracker.submit(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(), h.src(vi)));
            h.tracker.drainForTest();
            h.send(vi.replace("\"a\"", "\"\u0110\u01a0N H\u00c0NG\""), 200);
            h.writer.awaitIdle(3000);
            int apiId = h.sends.get(0).apiId();
            try (Repo repo = new Repo(h.db.newReadConnection())) {
                eq(1, repo.search(apiId, "\u0111\u01a1n h\u00e0ng", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 10, 1).size(), "LIKE finds accented text in a different case");
                eq(1, repo.search(apiId, "\u0111\u01a1n h\u00e0ng", List.of(), Repo.Filter.ALL, Long.MAX_VALUE, 10, Integer.MAX_VALUE).size(), "FTS finds accented text");
            }
        }
    }

    static void intruderPerf() {
        Settings settings = new Settings();
        Sink sink = new Sink();
        IntruderTracker it = new IntruderTracker(settings, sink);
        StringBuilder big = new StringBuilder("{");
        for (int i = 0; i < 200; i++) big.append(i == 0 ? "" : ",").append("\"f").append(i).append("\":\"value-").append(i).append("\"");
        big.append('}');
        String base = withBody(IBASE, big.toString());
        List<IntruderTracker.Hit> hits = new ArrayList<>();
        for (int i = 0; i < 4_000; i++) hits.add(hit(base.replace("value-150", "v" + i), 200));
        for (IntruderTracker.Hit x : hits.subList(0, 1000)) it.submit(x);
        it.drainForTest();
        long t0 = System.nanoTime();
        for (IntruderTracker.Hit x : hits.subList(1000, 4000)) { it.submit(x); }
        it.drainForTest();
        double us = (System.nanoTime() - t0) / 1000.0 / 3000;
        System.out.printf("     Intruder: %.1f µs/request (body JSON %d KB, fast path %d, slow path %d)%n", us,
                req(base).length / 1024, it.fastPath.sum(), it.slowPath.sum());
        yes(us < 200, "Intruder < 200 µs/request");
    }

    static void perf() {
        ApiKeys k = new ApiKeys();
        String path = "/condition-orders/underlying-order/api/v1/so-order/8831";
        for (int i = 0; i < 200_000; i++) k.statusKey("POST", "https://api.example.com:443", path);
        long t0 = System.nanoTime();
        int n = 1_000_000;
        for (int i = 0; i < n; i++) k.statusKey("POST", "https://api.example.com:443", path);
        double nsKey = (System.nanoTime() - t0) / (double) n;
        System.out.printf("     statusKey (cache hit): %.0f ns/op%n", nsKey);
        yes(nsKey < 2_000, "statusKey < 2 µs");

        StringBuilder json = new StringBuilder("{");
        for (int i = 0; i < 300; i++) json.append(i == 0 ? "" : ",").append("\"field").append(i).append("\":\"value-").append(i).append("\"");
        json.append('}');
        String body = json.toString();
        String raw1 = "POST /api/v1/x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz0123\r\n\r\n" + body;
        String raw2 = raw1.replace("value-150", "value-XYZ");
        byte[] b1 = raw1.getBytes(StandardCharsets.UTF_8), b2 = raw2.getBytes(StandardCharsets.UTF_8);
        Redactor r = newRedactor();
        ParsedReq a = ParsedReq.parse(b1);
        for (int i = 0; i < 2_000; i++) Diff.compute(a, ParsedReq.parse(b2), r, Set.of());
        int m = 2_000;
        long t1 = System.nanoTime();
        for (int i = 0; i < m; i++) Diff.compute(a, ParsedReq.parse(b2), r, Set.of());
        double usDiff = (System.nanoTime() - t1) / 1000.0 / m;
        System.out.printf("     parse + diff JSON %d KB: %.0f µs/op%n", b1.length / 1024, usDiff);
        yes(usDiff < 2_000, "parse + diff < 2 ms");
    }
}
