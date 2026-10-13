package apitracker.burp;

import apitracker.core.Settings;
import burp.api.montoya.persistence.Preferences;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Reads / writes {@link Settings} in Burp's Preferences (shared by all Burp projects). */
public final class SettingsStore {
    private static final String P = "apitracker.";

    private SettingsStore() {}

    public static Settings load(Preferences p) {
        Settings s = new Settings();
        s.storageDir = str(p, "storageDir", s.storageDir);
        s.trackingEnabled = bool(p, "tracking", true);
        s.highlightEnabled = bool(p, "highlight", true);
        s.markerNote = bool(p, "markerNote", true);
        s.marker = str(p, "marker", Settings.DEFAULT_MARKER);
        s.aiEnabled = bool(p, "ai", true);
        s.intruderEnabled = bool(p, "intruder", true);
        s.aiHeader = str(p, "aiHeader", Settings.DEFAULT_AI_HEADER).trim();
        s.storeRaw = bool(p, "storeRaw", true);
        s.tabHook = bool(p, "tabHook", true);
        s.hotkey = str(p, "hotkey", s.hotkey);
        s.excludedExt = Settings.parseList(str(p, "excludedExt", Settings.DEFAULT_EXT));
        Pattern re = Settings.compileOrNull(str(p, "excludedPath", Settings.DEFAULT_PATH_REGEX));
        s.excludedPath = re;
        Set<String> ign = Settings.parseList(str(p, "ignoredHeaders", "content-length,connection"));
        s.ignoredHeaders = Set.copyOf(ign);
        s.sensitiveTokens = List.copyOf(Settings.parseList(str(p, "sensitiveTokens", "")));
        return s;
    }

    public static void save(Preferences p, Settings s, String excludedExt, String excludedPath, String ignoredHeaders,
                            String sensitiveTokens) {
        p.setString(P + "storageDir", s.storageDir);
        p.setBoolean(P + "tracking", s.trackingEnabled);
        p.setBoolean(P + "highlight", s.highlightEnabled);
        p.setBoolean(P + "markerNote", s.markerNote);
        p.setString(P + "marker", s.marker);
        p.setBoolean(P + "ai", s.aiEnabled);
        p.setBoolean(P + "intruder", s.intruderEnabled);
        p.setString(P + "aiHeader", s.aiHeader);
        p.setBoolean(P + "storeRaw", s.storeRaw);
        p.setBoolean(P + "tabHook", s.tabHook);
        p.setString(P + "hotkey", s.hotkey);
        p.setString(P + "excludedExt", excludedExt);
        p.setString(P + "excludedPath", excludedPath);
        p.setString(P + "ignoredHeaders", ignoredHeaders);
        p.setString(P + "sensitiveTokens", sensitiveTokens);
    }

    public static String raw(Preferences p, String key, String def) { return str(p, key, def); }

    private static String str(Preferences p, String k, String def) {
        try {
            String v = p.getString(P + k);
            return v == null ? def : v;
        } catch (Throwable t) {
            return def;
        }
    }

    private static boolean bool(Preferences p, String k, boolean def) {
        try {
            Boolean v = p.getBoolean(P + k);
            return v == null ? def : v;
        } catch (Throwable t) {
            return def;
        }
    }

    static String join(Set<String> s) { return String.join(",", s); }

    static List<String> split(String s) { return Arrays.asList(s.split(",")); }
}
