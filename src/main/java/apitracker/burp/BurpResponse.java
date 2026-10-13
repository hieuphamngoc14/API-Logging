package apitracker.burp;

import apitracker.core.Events;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;

/** Wraps Burp's HttpResponse. Copies nothing until the worker calls bytes(max), and never more than max bytes. */
final class BurpResponse implements Events.ResponseSource {
    private final HttpResponse r;

    private BurpResponse(HttpResponse r) { this.r = r; }

    /** null when there is no response. */
    static BurpResponse of(HttpResponse r) { return r == null ? null : new BurpResponse(r); }

    @Override public byte[] bytes(int max) {
        ByteArray b = r.toByteArray();
        if (b == null) return null;
        int n = b.length();
        return n <= max ? b.getBytes() : b.subArray(0, max).getBytes();
    }
}
