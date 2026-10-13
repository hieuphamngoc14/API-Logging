package apitracker.core;

/** Events fed to the {@link Tracker} worker. Handlers on Burp threads only create these small objects and offer them. */
public final class Events {
    private Events() {}

    public static final int KIND_REPEATER = 1;
    public static final int KIND_AI = 2;

    /** Abstract request source so the core does not depend on Montoya. bytes() is only called on the worker. */
    public interface RequestSource {
        byte[] bytes();
        String host();
        int port();
        boolean secure();
    }

    /**
     * Abstract response source (raw HTTP response). bytes(max) is only called on the worker and returns at most max
     * bytes, so a huge response is never copied in full.
     */
    public interface ResponseSource {
        byte[] bytes(int max);
    }

    /** Response whose bytes are already available (tests). */
    public record StaticResponse(byte[] data) implements ResponseSource {
        @Override public byte[] bytes(int max) {
            return data == null || data.length <= max ? data : java.util.Arrays.copyOf(data, max);
        }
    }

    public interface Event {}

    /** One send (Repeater, or AI via Proxy). source: "repeater" or the agent label. */
    public record SendEvent(int kind, int messageId, long nano, long millis, RequestSource req, String source)
            implements Event {}

    /**
     * Response to a send. initiating = the request actually sent (after other handlers modified it);
     * response = the raw response (may be null), read only when the send becomes its own original.
     */
    public record ResponseEvent(int kind, int messageId, long nano, int status, int length, String location,
                                RequestSource initiating, ResponseSource response) implements Event {
        public ResponseEvent(int kind, int messageId, long nano, int status, int length, String location,
                             RequestSource initiating) {
            this(kind, messageId, nano, status, length, location, initiating, null);
        }
    }

    /**
     * Original request chosen by the user: the "Send to Repeater (tracked)" menu/hotkey (has a service),
     * or the Repeater tab hook (text only, no service: req.host() is empty).
     */
    public record OriginalEvent(int sourceKind, long millis, RequestSource req, ResponseSource response) implements Event {
        public OriginalEvent(int sourceKind, long millis, RequestSource req) { this(sourceKind, millis, req, null); }
    }

    /**
     * Result of looking up a Proxy request as the original for an API without one. found = null if none.
     * token identifies the lookup (late results from an older lookup are dropped).
     */
    public record LookupResult(String parkedApiKey, long token, RequestSource found, long foundMillis,
                               ResponseSource foundResponse) implements Event {
        public LookupResult(String parkedApiKey, long token, RequestSource found, long foundMillis) {
            this(parkedApiKey, token, found, foundMillis, null);
        }
    }

    /**
     * Snapshot of an Intruder attack (sent periodically while running and once when finished, same attackId).
     * base = first request of the attack; positions = fields seen changing between requests.
     */
    public record AttackEvent(long attackId, boolean finished, String host, int port, boolean secure, byte[] base,
                              java.util.List<FieldLocator.Field> positions, int moreParams, int requests,
                              java.util.Map<Integer, Integer> statuses, int minLen, int maxLen, long startMillis,
                              long endMillis, boolean approximate) implements Event {}

    /** Response of an original request, found later in Proxy history (originals from the Repeater tab hook). */
    public record OriginalResponse(int originalId, ResponseSource response) implements Event {}

    /** Wakes the worker to run its periodic work now. */
    public record Tick() implements Event {}

    /** Request whose bytes are already available (for tests and data read from the DB). */
    public record StaticRequest(byte[] data, String host, int port, boolean secure) implements RequestSource {
        @Override public byte[] bytes() { return data; }
    }

    /**
     * Text read from the Repeater tab editor (hook): service unknown. Newline normalization and UTF-8 encoding run on
     * the worker when bytes() is called, not on the EDT.
     */
    public static final class HookText implements RequestSource {
        private final String text;
        private byte[] cached;
        public HookText(String text) { this.text = text; }
        @Override public byte[] bytes() {
            if (cached == null) cached = ParsedReq.normalizeHeaderNewlines(text).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return cached;
        }
        @Override public String host() { return ""; }
        @Override public int port() { return 0; }
        @Override public boolean secure() { return false; }
    }
}
