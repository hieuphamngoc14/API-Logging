package apitracker.burp;

import apitracker.core.Events;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Wraps Burp's HttpRequest. Reads nothing in the constructor: all byte/service reads happen on the worker,
 * not on Burp's thread.
 */
final class BurpRequest implements Events.RequestSource {
    private final HttpRequest r;
    private HttpService svc;

    BurpRequest(HttpRequest r) { this.r = r; }

    private HttpService svc() {
        if (svc == null) svc = r.httpService();
        return svc;
    }

    @Override public byte[] bytes() { return r.toByteArray().getBytes(); }
    @Override public String host() { HttpService s = svc(); return s == null ? "" : s.host(); }
    @Override public int port() { HttpService s = svc(); return s == null ? 0 : s.port(); }
    @Override public boolean secure() { HttpService s = svc(); return s != null && s.secure(); }

    /** Snapshots bytes + service right away (used on the EDT for "Send to Repeater (tracked)"). */
    static Events.StaticRequest snapshot(HttpRequest r) {
        HttpService s = r.httpService();
        return new Events.StaticRequest(r.toByteArray().getBytes(), s == null ? "" : s.host(),
                s == null ? 0 : s.port(), s != null && s.secure());
    }
}
