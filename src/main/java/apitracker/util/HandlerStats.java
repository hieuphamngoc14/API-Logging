package apitracker.util;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Times a handler running on a Burp thread and trips itself (circuit breaker) when the handler is slow.
 * record() only uses LongAdder/AtomicLong, so it is thread-safe and nearly free.
 */
public final class HandlerStats {
    public static final long SLOW_NS = 1_000_000L;         // 1 ms
    private static final long MIN_CALLS_TO_TRIP = 5_000;
    private static final int WARMUP_WINDOWS = 2;            // skip the first 2 minutes (JIT, class loading)

    public final String name;
    private final LongAdder calls = new LongAdder();
    private final LongAdder totalNs = new LongAdder();
    private final AtomicLong maxNs = new AtomicLong();
    // current window for the circuit breaker
    private final LongAdder windowCalls = new LongAdder();
    private final LongAdder windowSlow = new LongAdder();
    private volatile boolean tripped;
    private int windows;

    public HandlerStats(String name) { this.name = name; }

    public void record(long ns) {
        calls.increment();
        totalNs.add(ns);
        windowCalls.increment();
        if (ns > SLOW_NS) windowSlow.increment();
        long m = maxNs.get();
        while (ns > m && !maxNs.compareAndSet(m, ns)) m = maxNs.get();
    }

    public boolean tripped() { return tripped; }

    public void reset() {
        tripped = false;
        windowCalls.reset();
        windowSlow.reset();
        maxNs.set(0);
    }

    /** Call every 60 seconds (from a single thread). Returns true if it just tripped. Displayed max is the latest window's max. */
    public boolean checkWindow() {
        long c = windowCalls.sumThenReset();
        long s = windowSlow.sumThenReset();
        windowMax = maxNs.getAndSet(0);
        if (++windows <= WARMUP_WINDOWS) return false;
        if (!tripped && c >= MIN_CALLS_TO_TRIP && s * 100 > c) {
            tripped = true;
            return true;
        }
        return false;
    }

    public long calls() { return calls.sum(); }

    public double avgMicros() {
        long c = calls.sum();
        return c == 0 ? 0 : totalNs.sum() / 1000.0 / c;
    }

    private volatile long windowMax;

    public double maxMicros() { return Math.max(maxNs.get(), windowMax) / 1000.0; }
}
