package apitracker.core;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

/** Settings. Fields are volatile so proxy threads see new values without locking. */
public final class Settings {
    public static final String DEFAULT_AI_HEADER = "x-burp";
    public static final String DEFAULT_MARKER = "untested";
    public static final String DEFAULT_EXT = "js,mjs,css,png,jpg,jpeg,gif,svg,ico,webp,bmp,woff,woff2,ttf,otf,eot,map,mp3,mp4,webm,avi,pdf,zip";
    public static final String DEFAULT_PATH_REGEX = "(?i)/(health|healthz|ping|favicon\\.ico)$";

    public volatile String storageDir = Path.of(System.getProperty("user.home"), "BurpTracker").toString();
    public volatile boolean trackingEnabled = true;
    public volatile boolean highlightEnabled = true;
    public volatile boolean markerNote = true;
    public volatile String marker = DEFAULT_MARKER;
    public volatile boolean aiEnabled = true;
    /** Writes one log line per Intruder attack (payload positions + stats), not one per request. */
    public volatile boolean intruderEnabled = true;
    public volatile String aiHeader = DEFAULT_AI_HEADER;
    public volatile boolean storeRaw = true;
    public volatile boolean tabHook = true;
    public volatile String hotkey = "Ctrl+Alt+R";
    public volatile Set<String> excludedExt = parseList(DEFAULT_EXT);
    public volatile Pattern excludedPath = Pattern.compile(DEFAULT_PATH_REGEX);
    public volatile Set<String> ignoredHeaders = Set.of("content-length", "connection");
    public volatile List<String> sensitiveTokens = List.of();

    public static Set<String> parseList(String s) {
        if (s == null || s.isBlank()) return Set.of();
        return Arrays.stream(s.split("[,\\s]+")).map(x -> x.trim().toLowerCase(Locale.ROOT))
                .filter(x -> !x.isEmpty()).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public static Pattern compileOrNull(String regex) {
        if (regex == null || regex.isBlank()) return null;
        try { return Pattern.compile(regex); } catch (PatternSyntaxException e) { return null; }
    }

    /** Whether to skip this path/method when highlighting yellow. Runs on proxy threads: cheap, no big allocations. */
    public boolean excluded(String method, String path) {
        if ("OPTIONS".equalsIgnoreCase(method) || "CONNECT".equalsIgnoreCase(method)) return true;
        if (path == null) return false;
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        if (dot > slash && dot < path.length() - 1) {
            String ext = path.substring(dot + 1).toLowerCase(Locale.ROOT);
            if (excludedExt.contains(ext)) return true;
        }
        Pattern p = excludedPath;
        return p != null && p.matcher(path).find();
    }
}
