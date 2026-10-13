package apitracker.ui;

import java.util.Locale;

/** Filters the API list by multiple keywords (AND, lowercase) and detects when refiltering previous results is enough. */
public final class SearchTerms {
    private SearchTerms() {}

    public static String[] terms(String q) {
        String t = q == null ? "" : q.trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? new String[0] : t.split("\\s+");
    }

    public static boolean matchesAll(String key, String[] terms) {
        for (String t : terms) if (!key.contains(t)) return false;
        return true;
    }

    /** Every old term is inside some new term: the new matches are a subset of the old ones (just refilter old results). */
    public static boolean narrows(String[] prev, String[] cur) {
        if (prev.length == 0) return false;
        outer:
        for (String p : prev) {
            for (String c : cur) if (c.contains(p)) continue outer;
            return false;
        }
        return true;
    }
}
