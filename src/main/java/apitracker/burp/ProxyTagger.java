package apitracker.burp;

import apitracker.core.ApiKeys;
import apitracker.core.Events;
import apitracker.core.Settings;
import apitracker.core.StatusIndex;
import apitracker.core.Tracker;
import apitracker.util.HandlerStats;
import apitracker.util.Log;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;

/**
 * Two jobs on Proxy:
 * <ol>
 *   <li>AI requests with the {@code x-burp} header: strip the header (always), add an [AI] note + magenta, bypass
 *       Intercept, and log it like a Repeater send.</li>
 *   <li>Highlight yellow requests of untested APIs, decided when the request leaves Proxy (after Intercept).</li>
 * </ol>
 */
public final class ProxyTagger implements ProxyRequestHandler, ProxyResponseHandler {
    static final long AI_PENDING_TTL_NS = 120_000_000_000L;

    private final Supplier<Tracker> tracker;
    private final Settings settings;
    private final ApiKeys keys;
    private final StatusIndex status;
    private final Map<Integer, Long> aiPending = new ConcurrentHashMap<>();
    public final HandlerStats requestStats = new HandlerStats("Proxy request");
    public final HandlerStats responseStats = new HandlerStats("Proxy response");
    /** New Proxy entries since the last history sync pass. */
    public final LongAdder newProxyItems = new LongAdder();
    private volatile boolean ready;

    public ProxyTagger(Supplier<Tracker> tracker, Settings settings, ApiKeys keys, StatusIndex status) {
        this.tracker = tracker;
        this.settings = settings;
        this.keys = keys;
        this.status = status;
    }

    public void setReady(boolean r) { ready = r; }

    // ---------- request entering Proxy: detect AI ----------

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest r) {
        long t0 = System.nanoTime();
        try {
            String hdr = settings.aiHeader;
            String tag = (hdr == null || hdr.isEmpty()) ? null : r.headerValue(hdr);   // null for nearly every request
            if (tag != null) return handleAi(r, hdr, tag, t0);
        } catch (Throwable e) {
            Log.rateLimited(e);
        } finally {
            requestStats.record(System.nanoTime() - t0);
        }
        return ProxyRequestReceivedAction.continueWith(r);
    }

    /**
     * Request with the AI header. Stripping always runs (even with logging off or the circuit breaker tripped) and
     * never leaks: if it fails, the request is dropped. If logging / noting fails, the stripped request is still sent.
     */
    private ProxyRequestReceivedAction handleAi(InterceptedRequest r, String hdr, String tag, long t0) {
        HttpRequest clean;
        try {
            clean = stripHeader(r, hdr);
        } catch (Throwable e) {
            clean = null;
            Log.rateLimited(e);
        }
        if (clean == null) {
            Log.warn("Could not strip header " + hdr + " from an AI request; dropped the request so the header never reaches the server.");
            return ProxyRequestReceivedAction.drop();
        }
        Annotations an = null;
        try {
            String label = agentLabel(tag);
            Tracker t = tracker.get();
            if (ready && t != null && settings.aiEnabled && settings.trackingEnabled && !requestStats.tripped()) {
                aiPending.put(r.messageId(), t0);
                t.submit(new Events.SendEvent(Events.KIND_AI, r.messageId(), t0, System.currentTimeMillis(),
                        new BurpRequest(clean), label.isEmpty() ? "ai" : "ai:" + label));
            }
            an = r.annotations()
                    .withNotes(label.isEmpty() ? "[AI]" : "[AI] " + label)
                    .withHighlightColor(HighlightColor.MAGENTA);
        } catch (Throwable e) {
            Log.rateLimited(e);
        }
        return an != null ? ProxyRequestReceivedAction.doNotIntercept(clean, an) : ProxyRequestReceivedAction.doNotIntercept(clean);
    }

    /** Removes every occurrence of the header (case-insensitive). Returns null if any remain afterwards. */
    public static HttpRequest stripHeader(HttpRequest r, String name) {
        HttpRequest clean = r;
        for (int i = 0; i < 64 && clean.hasHeader(name); i++) clean = clean.withRemovedHeader(name);
        List<HttpHeader> left = new ArrayList<>();
        for (HttpHeader h : clean.headers()) if (h.name() != null && h.name().trim().equalsIgnoreCase(name)) left.add(h);
        if (!left.isEmpty()) clean = clean.withRemovedHeaders(left);
        for (HttpHeader h : clean.headers()) if (h.name() != null && h.name().trim().equalsIgnoreCase(name)) return null;
        return clean;
    }

    static String agentLabel(String tag) {
        String v = tag.trim();
        if (v.isEmpty() || v.equals("1") || v.equalsIgnoreCase("true")) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < v.length() && b.length() < 24; i++) {
            char c = v.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '.') b.append(c);
        }
        return b.toString();
    }

    // ---------- request leaving Proxy: highlight yellow ----------

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest r) {
        long t0 = System.nanoTime();
        try {
            newProxyItems.increment();
            if (ready && settings.highlightEnabled && !requestStats.tripped()) {
                Annotations an = r.annotations();
                if (HistorySync.canColor(an)) {                                  // don't overwrite an existing color / note
                    String m = r.method(), path = r.pathWithoutQuery();
                    if (!settings.excluded(m, path)) {                            // OPTIONS, .js, .png, /health…
                        HttpService s = r.httpService();
                        String sk = keys.statusKey(m, ApiKeys.hostKey(s.host(), s.port(), s.secure()), path);
                        if (!status.isTested(sk) && r.isInScope()) {             // scope checked last
                            Annotations out = an.withHighlightColor(HighlightColor.YELLOW);
                            if (settings.markerNote) out = out.withNotes(settings.marker);
                            return ProxyRequestToBeSentAction.continueWith(r, out);
                        }
                    }
                }
            }
        } catch (Throwable e) {
            Log.rateLimited(e);
        } finally {
            requestStats.record(System.nanoTime() - t0);
        }
        return ProxyRequestToBeSentAction.continueWith(r);
    }

    // ---------- response: AI requests only ----------

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {
        long t0 = System.nanoTime();
        try {
            if (!aiPending.isEmpty() && aiPending.remove(resp.messageId()) != null) {   // usually empty
                Tracker t = tracker.get();
                if (t != null) {
                    short st = resp.statusCode();
                    String loc = (st >= 300 && st < 400) ? resp.headerValue("Location") : null;
                    t.submit(new Events.ResponseEvent(Events.KIND_AI, resp.messageId(), t0, st, TrackerHttpHandler.bodyLength(resp, st),
                            loc, new BurpRequest(resp.initiatingRequest())));
                }
            }
        } catch (Throwable e) {
            Log.rateLimited(e);
        } finally {
            responseStats.record(System.nanoTime() - t0);
        }
        return ProxyResponseReceivedAction.continueWith(resp);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
        return ProxyResponseToBeSentAction.continueWith(resp);
    }

    /** Cleans up AI requests that never get a response. Called periodically from a background thread. */
    public void sweep(long nowNs) {
        for (Iterator<Map.Entry<Integer, Long>> it = aiPending.entrySet().iterator(); it.hasNext(); ) {
            if (nowNs - it.next().getValue() > AI_PENDING_TTL_NS) it.remove();
        }
    }
}
