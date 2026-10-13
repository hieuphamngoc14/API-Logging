package apitracker.core;

import java.util.Locale;
import java.util.Set;

/**
 * "Noise" changes still show in the log but do not mark the API as "tested": rotating load balancer /
 * analytics cookies, browser and tracing headers, CSRF tokens changing value (removing CSRF still counts as a test).
 */
public final class Noise {
    private Noise() {}

    private static final Set<String> HEADERS = Set.of(
            "if-none-match", "if-modified-since", "cache-control", "pragma", "priority", "accept-encoding",
            "accept-language", "upgrade-insecure-requests", "te", "dnt", "x-request-id", "x-correlation-id",
            "traceparent", "tracestate", "baggage", "sentry-trace", "x-amzn-trace-id", "x-cloud-trace-context",
            "x-datadog-trace-id", "x-datadog-parent-id", "x-datadog-sampling-priority", "x-b3-traceid",
            "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "b3", "request-id", "x-client-trace-id");
    private static final String[] HEADER_PREFIXES = {"sec-ch-", "sec-fetch-"};
    private static final String[] COOKIE_PREFIXES = {"awsalb", "__cf_bm", "cf_clearance", "_ga", "_gid", "_gat", "_fbp",
            "_fbc", "_hj", "__utm", "ai_session", "ai_user", "_dd_s", "_clck", "_clsk", "mp_", "amplitude", "optimizely",
            "_uetsid", "_uetvid", "_gcl", "__hs", "hubspotutk", "intercom-", "ts01", "bm_sv", "bm_sz", "ak_bmsc", "_abck"};

    /** true if this change is not enough to count as tested. */
    public static boolean ignorableForStatus(Diff.Change c) {
        if (Diff.FORMAT_ONLY.equals(c.name())) return true;
        String name = base(c.name());
        if (c.loc() == Diff.LOC_HEADER) {
            if (HEADERS.contains(name)) return true;
            for (String p : HEADER_PREFIXES) if (name.startsWith(p)) return true;
        } else if (c.loc() == Diff.LOC_COOKIE) {
            for (String p : COOKIE_PREFIXES) if (name.startsWith(p)) return true;
        }
        // rotating CSRF token: ignored only when the value changes, not when removed / added
        return c.op() == '~' && (c.loc() == Diff.LOC_HEADER || c.loc() == Diff.LOC_COOKIE
                || c.loc() == Diff.LOC_BODY || c.loc() == Diff.LOC_QUERY) && csrfLike(name);
    }

    static boolean csrfLike(String lower) {
        return lower.contains("csrf") || lower.contains("xsrf") || lower.contains("requestverificationtoken")
                || lower.contains("authenticity_token");
    }

    private static String base(String n) {
        if (n == null) return "";
        int h = n.indexOf('#');
        String s = h > 0 ? n.substring(0, h) : n;
        int dot = s.lastIndexOf('.');
        if (s.startsWith("$") && dot >= 0) s = s.substring(dot + 1);
        return s.toLowerCase(Locale.ROOT);
    }
}
