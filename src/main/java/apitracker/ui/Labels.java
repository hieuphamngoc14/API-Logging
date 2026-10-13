package apitracker.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Labels for values (tokens userA, userB...). A labeled value is stored in the log as its fingerprint
 * {@code <#a1b2c3d4>} and the label is substituted at display time. A label search becomes a fingerprint search.
 */
public final class Labels {
    private static final Pattern FP = Pattern.compile("<#([0-9a-f]{8})>");
    private final ConcurrentHashMap<String, String> byPrefix = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> byFull = new ConcurrentHashMap<>();
    private volatile int version;

    public void load(Map<String, String> fullToLabel) {
        fullToLabel.forEach(this::put);
    }

    public void put(String fullHmac, String label) {
        if (fullHmac == null || fullHmac.length() < 8) return;
        byFull.put(fullHmac, label);
        byPrefix.put(fullHmac.substring(0, 8), label);
        version++;
    }

    public void remove(String fullHmac) {
        if (fullHmac == null || fullHmac.length() < 8) return;
        byFull.remove(fullHmac);
        byPrefix.remove(fullHmac.substring(0, 8));
        version++;
    }

    public int version() { return version; }

    /** Live view of the labeled values' full HMACs (the redactor masks those values so their label shows). */
    public java.util.Set<String> fullKeys() { return byFull.keySet(); }

    public String apply(String text) {
        if (text == null || byPrefix.isEmpty() || text.indexOf("<#") < 0) return text;
        Matcher m = FP.matcher(text);
        StringBuilder b = new StringBuilder(text.length());
        while (m.find()) {
            String label = byPrefix.get(m.group(1));
            m.appendReplacement(b, Matcher.quoteReplacement(label == null ? m.group() : "<" + label + ">"));
        }
        m.appendTail(b);
        return b.toString();
    }

    /** Keyword equal to a label → add the matching fingerprint to the query. */
    public List<String> alternativesFor(String query) {
        List<String> out = new ArrayList<>();
        String q = query.trim().replace("<", "").replace(">", "").toLowerCase(Locale.ROOT);
        if (q.isEmpty()) return out;
        for (Map.Entry<String, String> e : byPrefix.entrySet()) {
            if (e.getValue().toLowerCase(Locale.ROOT).equals(q)) out.add("#" + e.getKey());
        }
        return out;
    }

    /** label → full hmac, sorted by label. */
    public Map<String, String> all() {
        Map<String, String> out = new TreeMap<>();
        byFull.forEach((h, l) -> out.put(l + "  (" + h.substring(0, 8) + ")", h));
        return out;
    }
}
