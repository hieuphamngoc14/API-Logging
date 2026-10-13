package apitracker.core;

import java.util.concurrent.ConcurrentHashMap;

/**
 * State per statusKey: 0 = not sent, 1 = sent but unmodified, 2 = tested (at least one change).
 * The worker writes, proxy threads read. State only goes up.
 */
public final class StatusIndex {
    public static final byte NONE = 0, SENT = 1, TESTED = 2;
    private final ConcurrentHashMap<String, Byte> map = new ConcurrentHashMap<>(4096);

    public byte get(String statusKey) {
        Byte b = map.get(statusKey);
        return b == null ? NONE : b;
    }

    public boolean isTested(String statusKey) {
        Byte b = map.get(statusKey);
        return b != null && b == TESTED;
    }

    /** Raises the state if the new one is higher. Returns true if it changed. */
    public boolean raise(String statusKey, byte state) {
        boolean[] changed = {false};
        map.compute(statusKey, (k, old) -> {
            if (old == null || old < state) { changed[0] = true; return state; }
            return old;
        });
        return changed[0];
    }

    public void load(String statusKey, byte state) {
        if (state > NONE) map.merge(statusKey, state, (a, b) -> a >= b ? a : b);
    }

    public int size() { return map.size(); }
}
