package apitracker.ui;

import apitracker.core.Tracker;
import apitracker.store.Rows;

import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.BiConsumer;

/**
 * Worker → EDT bridge. Workers only push to a lock-free queue; the EDT drains it every 300 ms, merges API updates by id
 * (keeping only the latest) and applies them once.
 */
public final class UiBus implements Tracker.Listener {
    public interface Sink {
        void apply(List<Rows.ApiRow> apis, List<Rows.SendRow> sends);
    }

    private final ConcurrentLinkedQueue<Object> q = new ConcurrentLinkedQueue<>();
    private volatile Sink sink;
    private volatile BiConsumer<String, String> renameHint = (fl, name) -> {};
    private Timer timer;

    public void setSink(Sink s) { sink = s; }
    public void setRenameHint(BiConsumer<String, String> r) { renameHint = r; }

    public void start() {
        SwingUtilities.invokeLater(() -> {
            timer = new Timer(300, e -> flush());
            timer.start();
        });
    }

    public void stop() {
        SwingUtilities.invokeLater(() -> { if (timer != null) timer.stop(); });
    }

    @Override public void apiChanged(Rows.ApiRow row) { q.add(row); }
    @Override public void sendAdded(Rows.SendRow row) { q.add(row); }
    @Override public void renameHint(String rawFirstLine, String hostHeader, String tabName) {
        renameHint.accept(rawFirstLine, tabName);
    }

    private void flush() {
        if (q.isEmpty()) return;
        Map<Integer, Rows.ApiRow> apis = new LinkedHashMap<>();
        List<Rows.SendRow> sends = new ArrayList<>();
        Object o;
        int n = 0;
        while (n < 5_000 && (o = q.poll()) != null) {
            n++;
            if (o instanceof Rows.ApiRow a) apis.put(a.id(), a);
            else if (o instanceof Rows.SendRow s) sends.add(s);
        }
        Sink s = sink;
        if (s != null) s.apply(new ArrayList<>(apis.values()), sends);
    }
}
