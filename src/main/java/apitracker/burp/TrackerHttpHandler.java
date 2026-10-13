package apitracker.burp;

import apitracker.core.Events;
import apitracker.core.IntruderTracker;
import apitracker.core.Settings;
import apitracker.core.Tracker;
import apitracker.util.HandlerStats;
import apitracker.util.Log;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.function.Supplier;

/**
 * Hot path for Repeater and Intruder: only compares the sending tool, builds a small event and offers it to a bounded
 * queue. No parsing, no body copy, no blocking. Repeater goes to tracker-core; Intruder takes only responses (one event
 * per request) into its own tracker-intruder queue so it doesn't crowd the Repeater log.
 */
public final class TrackerHttpHandler implements HttpHandler {
    private final Supplier<Tracker> tracker;
    private final Supplier<IntruderTracker> intruder;
    private final Settings settings;
    public final HandlerStats stats = new HandlerStats("HttpHandler");

    public TrackerHttpHandler(Supplier<Tracker> tracker, Settings settings) {
        this(tracker, () -> null, settings);
    }

    public TrackerHttpHandler(Supplier<Tracker> tracker, Supplier<IntruderTracker> intruder, Settings settings) {
        this.tracker = tracker;
        this.intruder = intruder;
        this.settings = settings;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        long t0 = System.nanoTime();
        HttpRequest out = null;
        try {
            ToolType tool = req.toolSource().toolType();
            // last line of defense for the AI header in tools other than Proxy (Repeater resending an AI request, Intruder,
            // Scanner...), regardless of the circuit breaker or logging options. ProxyTagger already stripped Proxy requests:
            // skip the redundant header scan for the highest-traffic tool.
            String hdr = settings.aiHeader;
            if (tool != ToolType.PROXY && hdr != null && !hdr.isEmpty() && req.hasHeader(hdr)) {
                HttpRequest clean = ProxyTagger.stripHeader(req, hdr);
                if (clean != null) out = clean;
                else Log.warn("Could not strip header " + hdr + " from a request sent by " + tool + ".");
            }
            if (settings.trackingEnabled && !stats.tripped() && tool == ToolType.REPEATER) {
                Tracker t = tracker.get();
                if (t != null) {
                    t.submit(new Events.SendEvent(Events.KIND_REPEATER, req.messageId(), t0, System.currentTimeMillis(),
                            new BurpRequest(out != null ? out : req), "repeater"));
                }
            }
        } catch (Throwable e) {
            Log.rateLimited(e);
        } finally {
            stats.record(System.nanoTime() - t0);
        }
        return out != null ? RequestToBeSentAction.continueWith(out) : RequestToBeSentAction.continueWith(req);
    }

    /**
     * Body size without copying the body: reads Content-Length; only when absent (chunked, undeclared HTTP/2) calls
     * body(), which may copy the whole body (a multi-MB response → a few ms on Burp's thread).
     */
    static int bodyLength(HttpResponse resp, int status) {
        return bodyLength(resp, status, true);
    }

    /** allowCopy = false: without Content-Length, returns -1 instead of reading the body (Intruder: thousands of responses/s). */
    static int bodyLength(HttpResponse resp, int status, boolean allowCopy) {
        if (status == 204 || status == 304) return 0;
        String cl = resp.headerValue("Content-Length");
        if (cl != null) {
            try {
                long n = Long.parseLong(cl.trim());
                if (n >= 0) return (int) Math.min(Integer.MAX_VALUE, n);
            } catch (NumberFormatException ignored) {
                // odd value: measure it
            }
        }
        return allowCopy ? resp.body().length() : -1;
    }

    private static int parseLen(String v) {
        if (v == null) return 0;
        try { return (int) Math.min(Integer.MAX_VALUE, Math.max(0, Long.parseLong(v.trim()))); }
        catch (NumberFormatException e) { return 0; }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        long t0 = System.nanoTime();
        try {
            if (settings.trackingEnabled && !stats.tripped()) {
                ToolType tool = resp.toolSource().toolType();
                if (tool == ToolType.REPEATER) {
                    Tracker t = tracker.get();
                    if (t != null) {
                        short st = resp.statusCode();
                        String loc = (st >= 300 && st < 400) ? resp.headerValue("Location") : null;
                        // the response object is only referenced here; its bytes are read on the worker, and only
                        // when this send becomes the API's original
                        t.submit(new Events.ResponseEvent(Events.KIND_REPEATER, resp.messageId(), t0, st,
                                bodyLength(resp, st), loc, new BurpRequest(resp.initiatingRequest()), BurpResponse.of(resp)));
                    }
                } else if (tool == ToolType.INTRUDER && settings.intruderEnabled) {
                    IntruderTracker it = intruder.get();
                    if (it != null) {
                        short st = resp.statusCode();
                        String loc = (st >= 300 && st < 400) ? resp.headerValue("Location") : null;
                        HttpRequest ir = resp.initiatingRequest();
                        // estimate request size (bounds queue memory) from Content-Length, without copying bytes
                        int est = parseLen(ir.headerValue("Content-Length")) + 1024;
                        it.submit(new IntruderTracker.Hit(t0, System.currentTimeMillis(), st, bodyLength(resp, st, false),
                                loc, est, new BurpRequest(ir)));
                    }
                }
            }
        } catch (Throwable e) {
            Log.rateLimited(e);
        } finally {
            stats.record(System.nanoTime() - t0);
        }
        return ResponseReceivedAction.continueWith(resp);
    }
}
