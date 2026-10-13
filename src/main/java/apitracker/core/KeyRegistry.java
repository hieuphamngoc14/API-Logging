package apitracker.core;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;

/**
 * Assigns numeric ids to statusKeys (shared by the worker and the history thread). New keys are reported to {@code onNew}
 * exactly once (to be written to the DB).
 */
public final class KeyRegistry {
    private final ConcurrentHashMap<String, Integer> idByKey = new ConcurrentHashMap<>(4096);
    private final ConcurrentHashMap<Integer, String> keyById = new ConcurrentHashMap<>(4096);
    private final AtomicInteger next = new AtomicInteger(1);
    private volatile BiConsumer<Integer, String> onNew = (i, k) -> {};

    public void setOnNew(BiConsumer<Integer, String> cb) { onNew = cb; }

    public void load(int id, String key) {
        idByKey.put(key, id);
        keyById.put(id, key);
        next.accumulateAndGet(id + 1, Math::max);
    }

    public int idOf(String key) {
        Integer id = idByKey.get(key);
        if (id != null) return id;
        return idByKey.computeIfAbsent(key, k -> {
            int n = next.getAndIncrement();
            keyById.put(n, k);
            onNew.accept(n, k);
            return n;
        });
    }

    public Integer find(String key) { return idByKey.get(key); }

    public String keyOf(int id) { return keyById.get(id); }

    public Map<Integer, String> snapshot() { return Map.copyOf(keyById); }
}
