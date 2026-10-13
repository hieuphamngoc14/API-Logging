package apitracker;

import apitracker.burp.ProxyTagger;
import apitracker.burp.TrackerHttpHandler;
import apitracker.core.ApiKeys;
import apitracker.core.KeyRegistry;
import apitracker.core.Redactor;
import apitracker.core.Settings;
import apitracker.core.StatusIndex;
import apitracker.core.Tracker;
import apitracker.store.DbWriter;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;

import java.util.List;

/**
 * Measures the cost of handlers running on Burp threads at steady state (after JIT warmup).
 * Fake objects use dynamic proxies, so the numbers are upper bounds: each method call on a fake request adds ~0.1–0.5 µs.
 */
public final class HotPathBench {
    public static void main(String[] args) {
        FakeBurp fb = new FakeBurp();
        Settings settings = new Settings();
        ApiKeys keys = new ApiKeys();
        StatusIndex status = new StatusIndex();
        Tracker tracker = new Tracker(keys, status, new KeyRegistry(), new DbWriter(null, true), settings,
                new Redactor(new byte[32], List.of()));
        ProxyTagger tagger = new ProxyTagger(() -> tracker, settings, keys, status);
        tagger.setReady(true);
        apitracker.core.IntruderTracker intr = new apitracker.core.IntruderTracker(settings, e -> true);
        TrackerHttpHandler http = new TrackerHttpHandler(() -> tracker, () -> intr, settings);

        String raw = "POST /condition-orders/underlying-order/api/v1/so-order/8831 HTTP/1.1\nHost: api.example.com\n"
                + "Authorization: Bearer abc\nContent-Type: application/json\nUser-Agent: x\nAccept: */*\n\n{\"a\":1}";
        HttpRequest untested = fb.request(raw, "api.example.com", 443, true, ToolType.PROXY, new FakeBurp.Ann(), 1, true);
        HttpRequest tested = fb.request(raw.replace("so-order", "tested-api"), "api.example.com", 443, true, ToolType.PROXY, new FakeBurp.Ann(), 2, true);
        status.raise(keys.statusKey("POST", "https://api.example.com:443", "/condition-orders/underlying-order/api/v1/tested-api/8831"), StatusIndex.TESTED);
        HttpRequest repeater = fb.request(raw, "api.example.com", 443, true, ToolType.REPEATER, new FakeBurp.Ann(), 3, true);
        HttpRequest proxyTool = fb.request(raw, "api.example.com", 443, true, ToolType.PROXY, new FakeBurp.Ann(), 4, true);

        bench("Proxy received (no AI header)", () -> tagger.handleRequestReceived((InterceptedRequest) untested));
        bench("Proxy to-be-sent: untested API (highlight yellow)", () -> tagger.handleRequestToBeSent((InterceptedRequest) untested));
        bench("Proxy to-be-sent: tested API", () -> tagger.handleRequestToBeSent((InterceptedRequest) tested));
        bench("HttpHandler: request from Proxy (early exit)", () -> http.handleHttpRequestToBeSent((HttpRequestToBeSent) proxyTool));
        bench("HttpHandler: request from Repeater (offer)", () -> {
            http.handleHttpRequestToBeSent((HttpRequestToBeSent) repeater);
            if (tracker.queueSize() > 1_500) tracker.drainForTest();
        });
        HttpRequest intruderReq = fb.request(raw, "api.example.com", 443, true, ToolType.INTRUDER, new FakeBurp.Ann(), 5, true);
        Object intruderResp = fb.response(200, 1200, null, intruderReq, ToolType.INTRUDER, 5);
        bench("HttpHandler: response Intruder (offer)", () -> {
            http.handleHttpResponseReceived((burp.api.montoya.http.handler.HttpResponseReceived) intruderResp);
            if (intr.queueSize() > 6_000) intr.drainForTest();
        });
        // dynamic proxy overhead alone, for reference
        bench("(reference) 3 method calls on a fake request", () -> {
            untested.method();
            untested.pathWithoutQuery();
            untested.httpService();
        });
        System.out.println("HttpHandler stats: avg " + String.format("%.2f", http.stats.avgMicros()) + " µs");
        System.out.println("Proxy request stats: avg " + String.format("%.2f", tagger.requestStats.avgMicros()) + " µs");
    }

    static void bench(String name, Runnable r) {
        for (int i = 0; i < 300_000; i++) r.run();
        int n = 500_000;
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) r.run();
        double ns = (System.nanoTime() - t0) / (double) n;
        System.out.printf("%-52s %8.0f ns/op%n", name, ns);
    }
}
