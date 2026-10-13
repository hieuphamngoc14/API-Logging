package apitracker.ui;

import apitracker.store.Rows;

/** Gateway for SelfTest into package-private UI code (no visible Swing needed). */
public final class UiProbe {
    private UiProbe() {}

    public static String[] cellLines(String changes, int flags) {
        Rows.SendRow s = new Rows.SendRow(9, 1, 1, 0L, 200, 10, 5, flags, "repeater", 0, "POST /x HTTP/1.1", changes);
        return ApiView.cellLines(new ApiView.LogItem(null, s), new Labels());
    }

    /** Columns of a change line: {marker, position name, rest} or null. */
    public static String[] changeCols(String line) {
        int[] c = ApiView.changeCols(line);
        return c == null ? null : new String[]{line.substring(c[0], c[0] + 1), line.substring(c[1], c[2]), line.substring(c[3])};
    }

    /** Head line of an original / a send compared against original #origSeq, as shown in the log. */
    public static String head(Rows.OriginalRow o) { return ApiView.cellLines(new ApiView.LogItem(o, null), new Labels())[0]; }

    public static String head(Rows.SendRow s, int origSeq) {
        ApiView.LogItem it = new ApiView.LogItem(null, s);
        it.origSeq = origSeq;
        return ApiView.cellLines(it, new Labels())[0];
    }

    /** Markdown export of one API for an AI. */
    public static String exportApi(apitracker.store.Repo repo, Rows.ApiRow api, apitracker.core.Redactor r,
                                   java.util.Set<String> ignored) throws java.sql.SQLException {
        return Markdown.api(repo, api, r, ignored);
    }

    /** Full export with one fake untested API from Proxy history. */
    public static String exportAll(apitracker.store.Repo repo, java.util.List<Rows.ApiRow> apis, apitracker.core.Redactor r,
                                   java.util.Set<String> ignored) throws java.sql.SQLException {
        return Markdown.all(repo, "Test project", apis, java.util.List.of(new Markdown.Untested("GET", "https://h:443/untested", 3)),
                r, ignored);
    }

    /** Runs "Export all logs for AI" of the extension tab under root into the given file (no file chooser). */
    public static void exportAllFromUi(java.awt.Component root, java.io.File out) throws Exception {
        ApiView[] v = new ApiView[1];
        javax.swing.SwingUtilities.invokeAndWait(() -> { v[0] = find(root); if (v[0] != null) v[0].exportAllForAi(out); });
        if (v[0] == null) throw new IllegalStateException("API view not found");
    }

    private static ApiView find(java.awt.Component c) {
        if (c instanceof ApiView a) return a;
        if (c instanceof java.awt.Container ct) for (java.awt.Component ch : ct.getComponents()) {
            ApiView a = find(ch);
            if (a != null) return a;
        }
        return null;
    }
}
