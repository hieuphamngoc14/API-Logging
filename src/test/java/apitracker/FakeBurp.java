package apitracker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.project.Project;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.swing.SwingUtils;

import javax.swing.JFrame;
import javax.swing.JTextArea;
import java.awt.Color;
import java.awt.Component;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Fake Burp built from dynamic proxies, enough to run the real extension outside Burp: handlers, Proxy history, Repeater, UI, persistence.
 */
public final class FakeBurp {
    // ---------- observable state ----------
    public final List<ProxyHttpRequestResponse> history = new CopyOnWriteArrayList<>();
    public final List<String> repeaterSends = new CopyOnWriteArrayList<>();
    public final List<HttpHandler> httpHandlers = new CopyOnWriteArrayList<>();
    public final List<ProxyRequestHandler> proxyReq = new CopyOnWriteArrayList<>();
    public final List<ProxyResponseHandler> proxyResp = new CopyOnWriteArrayList<>();
    public final List<ContextMenuItemsProvider> menus = new CopyOnWriteArrayList<>();
    public final List<ExtensionUnloadingHandler> unloading = new CopyOnWriteArrayList<>();
    public final Map<String, Object> prefs = new HashMap<>();
    public final Map<String, Object> extData = new HashMap<>();
    public final List<String> logs = new CopyOnWriteArrayList<>();
    /** Fake Burp scope: a URL is in scope if it starts with one of these prefixes. */
    public final List<String> scopePrefixes = new CopyOnWriteArrayList<>(List.of("https://api.example.com"));
    public final List<burp.api.montoya.scope.ScopeChangeHandler> scopeHandlers = new CopyOnWriteArrayList<>();
    public Component suiteTab;
    public JFrame suiteFrame;
    public String projectName = "KBSV mobile";
    public String projectId = "proj-1234";
    public final AtomicInteger historyCalls = new AtomicInteger();
    private final AtomicInteger msgIds = new AtomicInteger(1000);
    private int historyId = 0;
    public final MontoyaApi api;

    public FakeBurp() {
        installFactory();
        api = proxy(MontoyaApi.class, (p, m, a) -> switch (m.getName()) {
            case "proxy" -> proxyApi();
            case "http" -> httpApi();
            case "userInterface" -> uiApi();
            case "persistence" -> persistence();
            case "project" -> proxy(Project.class, (p2, m2, a2) -> m2.getName().equals("name") ? projectName : projectId);
            case "extension" -> extension();
            case "logging" -> logging();
            case "scope" -> scopeApi();
            case "repeater" -> proxy(Repeater.class, (p2, m2, a2) -> {
                repeaterSends.add(a2.length > 1 ? (String) a2[1] : "(no name)");
                return null;
            });
            default -> null;
        });
    }

    // ---------- fake objects ----------

    @SuppressWarnings("unchecked")
    static <T> T proxy(Class<T> type, InvocationHandler h) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(FakeBurp.class.getClassLoader(), new Class<?>[]{type}, h);
    }

    static Object proxyMulti(InvocationHandler h, Class<?>... types) {
        return java.lang.reflect.Proxy.newProxyInstance(FakeBurp.class.getClassLoader(), types, h);
    }

    static Object defaultValue(Method m) {
        Class<?> r = m.getReturnType();
        if (r == boolean.class) return false;
        if (r == int.class) return 0;
        if (r == long.class) return 0L;
        if (r == short.class) return (short) 0;
        if (m.getName().equals("toString")) return "fake";
        if (m.getName().equals("hashCode")) return 0;
        if (m.getName().equals("equals")) return false;
        if (r == Registration.class) return proxy(Registration.class, (p, mm, a) -> mm.getName().equals("isRegistered") ? true : null);
        return null;
    }

    public static ByteArray bytes(byte[] b) {
        return proxy(ByteArray.class, (p, m, a) -> switch (m.getName()) {
            case "getBytes" -> b.clone();
            case "length" -> b.length;
            case "toString" -> new String(b, StandardCharsets.ISO_8859_1);
            default -> defaultValue(m);
        });
    }

    public static HttpService service(String host, int port, boolean secure) {
        return proxy(HttpService.class, (p, m, a) -> switch (m.getName()) {
            case "host" -> host;
            case "port" -> port;
            case "secure" -> secure;
            case "toString" -> (secure ? "https://" : "http://") + host + ":" + port;
            default -> defaultValue(m);
        });
    }

    /** Mutable Annotations, like Burp's. */
    public static final class Ann implements InvocationHandler {
        public volatile String notes;
        public volatile HighlightColor color = HighlightColor.NONE;
        public volatile int sets;
        public Annotations as() { return proxy(Annotations.class, this); }
        @Override public Object invoke(Object p, Method m, Object[] a) {
            switch (m.getName()) {
                case "notes": return notes;
                case "hasNotes": return notes != null && !notes.isEmpty();
                case "highlightColor": return color;
                case "hasHighlightColor": return color != null && color != HighlightColor.NONE;
                case "setNotes": notes = (String) a[0]; sets++; return null;
                case "setHighlightColor": color = (HighlightColor) a[0]; sets++; return null;
                case "withNotes": { Ann c = copy(); c.notes = (String) a[0]; return c.as(); }
                case "withHighlightColor": { Ann c = copy(); c.color = (HighlightColor) a[0]; return c.as(); }
                default: return defaultValue(m);
            }
        }
        Ann copy() { Ann c = new Ann(); c.notes = notes; c.color = color; return c; }
        static Ann of(Annotations an) {
            Ann x = (Ann) java.lang.reflect.Proxy.getInvocationHandler(an);
            return x;
        }
    }

    /** Fake request, also an HttpRequestToBeSent and an InterceptedRequest. */
    public HttpRequest request(String raw, String host, int port, boolean secure, ToolType tool, Ann ann, int messageId, boolean inScope) {
        byte[] b = raw.replace("\r\n", "\n").replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8);
        return requestBytes(b, host, port, secure, tool, ann, messageId, inScope);
    }

    HttpRequest requestBytes(byte[] b, String host, int port, boolean secure, ToolType tool, Ann ann, int messageId, boolean inScope) {
        String text = new String(b, StandardCharsets.UTF_8);
        String head = text.contains("\r\n\r\n") ? text.substring(0, text.indexOf("\r\n\r\n")) : text;
        String[] lines = head.split("\r\n");
        String[] rl = lines[0].split(" ");
        String target = rl.length > 1 ? rl[1] : "/";
        HttpService svc = service(host, port, secure);
        InvocationHandler h = (p, m, a) -> {
            switch (m.getName()) {
                case "toByteArray": return bytes(b);
                case "httpService": return svc;
                case "method": return rl[0];
                case "path": return target;
                case "pathWithoutQuery": return target.contains("?") ? target.substring(0, target.indexOf('?')) : target;
                case "messageId": return messageId;
                case "isInScope": return inScope;
                case "annotations": return ann.as();
                case "toolSource": return toolSource(tool);
                case "headerValue": {
                    String name = ((String) a[0]).toLowerCase(Locale.ROOT);
                    for (int i = 1; i < lines.length; i++) {
                        int c = lines[i].indexOf(':');
                        if (c > 0 && lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT).equals(name)) return lines[i].substring(c + 1).trim();
                    }
                    return null;
                }
                case "hasHeader": {
                    if (a.length != 1 || !(a[0] instanceof String)) return false;
                    String name = ((String) a[0]).toLowerCase(Locale.ROOT);
                    for (int i = 1; i < lines.length; i++) {
                        int c = lines[i].indexOf(':');
                        if (c > 0 && lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT).equals(name)) return true;
                    }
                    return false;
                }
                case "withRemovedHeader": {
                    String name = ((String) a[0]).toLowerCase(Locale.ROOT);
                    StringBuilder out = new StringBuilder(lines[0]);
                    boolean removed = false;
                    for (int i = 1; i < lines.length; i++) {
                        int c = lines[i].indexOf(':');
                        if (!removed && c > 0 && lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT).equals(name)) { removed = true; continue; }
                        out.append("\r\n").append(lines[i]);
                    }
                    String body = text.contains("\r\n\r\n") ? text.substring(text.indexOf("\r\n\r\n")) : "\r\n\r\n";
                    return requestBytes((out + body).getBytes(StandardCharsets.UTF_8), host, port, secure, tool, ann, messageId, inScope);
                }
                case "headers": {
                    List<burp.api.montoya.http.message.HttpHeader> out = new ArrayList<>();
                    for (int i = 1; i < lines.length; i++) {
                        int c = lines[i].indexOf(':');
                        if (c <= 0) continue;
                        String hn = lines[i].substring(0, c), hv = lines[i].substring(c + 1).trim();
                        out.add(proxy(burp.api.montoya.http.message.HttpHeader.class, (p2, m2, a2) -> switch (m2.getName()) {
                            case "name" -> hn;
                            case "value" -> hv;
                            case "toString" -> hn + ": " + hv;
                            default -> defaultValue(m2);
                        }));
                    }
                    return out;
                }
                case "withRemovedHeaders": {
                    java.util.Set<String> names = new java.util.HashSet<>();
                    Object arg = a[0];
                    Iterable<?> it = arg instanceof Iterable<?> l ? l : Arrays.asList((Object[]) arg);
                    for (Object o : it) names.add(((burp.api.montoya.http.message.HttpHeader) o).name().trim().toLowerCase(Locale.ROOT));
                    StringBuilder out = new StringBuilder(lines[0]);
                    for (int i = 1; i < lines.length; i++) {
                        int c = lines[i].indexOf(':');
                        if (c > 0 && names.contains(lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT))) continue;
                        out.append("\r\n").append(lines[i]);
                    }
                    String body = text.contains("\r\n\r\n") ? text.substring(text.indexOf("\r\n\r\n")) : "\r\n\r\n";
                    return requestBytes((out + body).getBytes(StandardCharsets.UTF_8), host, port, secure, tool, ann, messageId, inScope);
                }
                case "toString": return text;
                case "hashCode": return System.identityHashCode(p);
                case "equals": return p == a[0];
                default: return defaultValue(m);
            }
        };
        return (HttpRequest) proxyMulti(h, HttpRequestToBeSent.class, InterceptedRequest.class);
    }

    public Object response(int status, int bodyLen, String location, HttpRequest initiating, ToolType tool, int messageId) {
        InvocationHandler h = (p, m, a) -> switch (m.getName()) {
            case "statusCode" -> (short) status;
            case "messageId" -> messageId;
            case "headerValue" -> "location".equalsIgnoreCase((String) a[0]) ? location
                    : "content-length".equalsIgnoreCase((String) a[0]) ? String.valueOf(bodyLen) : null;
            case "body" -> bytes(new byte[bodyLen]);
            case "initiatingRequest", "request" -> initiating;
            case "toolSource" -> toolSource(tool);
            case "annotations" -> new Ann().as();
            default -> defaultValue(m);
        };
        return proxyMulti(h, HttpResponseReceived.class, InterceptedResponse.class);
    }

    static ToolSource toolSource(ToolType t) {
        return proxy(ToolSource.class, (p, m, a) -> switch (m.getName()) {
            case "toolType" -> t;
            case "isFromTool" -> Arrays.asList((ToolType[]) a[0]).contains(t);
            default -> defaultValue(m);
        });
    }

    public int nextMessageId() { return msgIds.incrementAndGet(); }

    /** Adds an entry to the fake Proxy history, with the annotations returned by the handler. */
    public synchronized ProxyHttpRequestResponse addHistory(HttpRequest finalReq, Annotations ann) {
        return addHistory(finalReq, ann, null);
    }

    /** Same, with the response text of the entry (null = a generic JSON response). */
    public synchronized ProxyHttpRequestResponse addHistory(HttpRequest finalReq, Annotations ann, String responseText) {
        int id = ++historyId;
        Ann state = Ann.of(ann).copy();
        ProxyHttpRequestResponse item = proxy(ProxyHttpRequestResponse.class, (p, m, a) -> switch (m.getName()) {
            case "id" -> id;
            case "finalRequest", "request" -> finalReq;
            case "annotations" -> state.as();
            case "time" -> ZonedDateTime.now();
            case "hasResponse" -> true;
            case "response", "originalResponse" -> responseText != null ? httpResponse(responseText) : historyResponse(id);
            default -> defaultValue(m);
        });
        history.add(item);
        return item;
    }

    /** Fake HttpResponse with the given raw text ("\n" line breaks are sent as CRLF). */
    public static burp.api.montoya.http.message.responses.HttpResponse httpResponse(String text) {
        byte[] raw = text.replace("\r\n", "\n").replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8);
        return proxy(burp.api.montoya.http.message.responses.HttpResponse.class, (p, m, a) -> switch (m.getName()) {
            case "toByteArray" -> bytes(raw);
            case "toString" -> text;
            default -> defaultValue(m);
        });
    }

    /** Response of a fake Proxy history entry (JSON body naming the entry). */
    static burp.api.montoya.http.message.responses.HttpResponse historyResponse(int entryId) {
        String text = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"entry\":" + entryId + "}";
        byte[] raw = text.getBytes(StandardCharsets.UTF_8);
        return proxy(burp.api.montoya.http.message.responses.HttpResponse.class, (p, m, a) -> switch (m.getName()) {
            case "toByteArray" -> bytes(raw);
            case "statusCode" -> (short) 200;
            case "toString" -> text;
            default -> defaultValue(m);
        });
    }

    public Ann annOf(ProxyHttpRequestResponse item) { return Ann.of(item.annotations()); }

    // ---------- sub-APIs ----------

    /** Adds to scope like Burp (Add to scope) and notifies the handlers. */
    public void includeInScope(String prefix) {
        scopePrefixes.add(prefix);
        burp.api.montoya.scope.ScopeChange ev = proxy(burp.api.montoya.scope.ScopeChange.class, (p, m, a) -> defaultValue(m));
        for (var h : scopeHandlers) h.scopeChanged(ev);
    }

    private burp.api.montoya.scope.Scope scopeApi() {
        return proxy(burp.api.montoya.scope.Scope.class, (p, m, a) -> switch (m.getName()) {
            case "isInScope" -> scopePrefixes.stream().anyMatch(((String) a[0])::startsWith);
            case "includeInScope" -> { includeInScope((String) a[0]); yield null; }
            case "registerScopeChangeHandler" -> { scopeHandlers.add((burp.api.montoya.scope.ScopeChangeHandler) a[0]); yield defaultValue(m); }
            default -> defaultValue(m);
        });
    }

    private Proxy proxyApi() {
        return proxy(Proxy.class, (p, m, a) -> {
            switch (m.getName()) {
                case "history":
                    historyCalls.incrementAndGet();
                    if (a == null || a.length == 0) return new ArrayList<>(history);
                    ProxyHistoryFilter f = (ProxyHistoryFilter) a[0];
                    List<ProxyHttpRequestResponse> out = new ArrayList<>();
                    for (ProxyHttpRequestResponse h : history) if (f.matches(h)) out.add(h);
                    return out;
                case "registerRequestHandler": proxyReq.add((ProxyRequestHandler) a[0]); return defaultValue(m);
                case "registerResponseHandler": proxyResp.add((ProxyResponseHandler) a[0]); return defaultValue(m);
                default: return defaultValue(m);
            }
        });
    }

    private Http httpApi() {
        return proxy(Http.class, (p, m, a) -> {
            if (m.getName().equals("registerHttpHandler")) httpHandlers.add((HttpHandler) a[0]);
            return defaultValue(m);
        });
    }

    /** Fake Burp UI / editor fonts (different, to check the extension uses the UI font). */
    static final java.awt.Font DISPLAY_FONT = new java.awt.Font(java.awt.Font.SANS_SERIF, java.awt.Font.PLAIN, 13);
    static final java.awt.Font EDITOR_FONT = new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 13);

    private UserInterface uiApi() {
        return proxy(UserInterface.class, (p, m, a) -> switch (m.getName()) {
            case "registerSuiteTab" -> { suiteTab = (Component) a[1]; yield defaultValue(m); }
            case "registerContextMenuItemsProvider" -> { menus.add((ContextMenuItemsProvider) a[0]); yield defaultValue(m); }
            case "createHttpRequestEditor" -> editor();
            case "applyThemeToComponent" -> { applyTheme((Component) a[0]); yield null; }
            case "currentDisplayFont" -> DISPLAY_FONT;
            case "currentEditorFont" -> EDITOR_FONT;
            case "swingUtils" -> proxy(SwingUtils.class, (p2, m2, a2) -> switch (m2.getName()) {
                case "suiteFrame" -> suiteFrame;
                case "colorForHighLight" -> new Color(0xFFF2A8);
                default -> defaultValue(m2);
            });
            default -> defaultValue(m);
        });
    }

    /** Like real Burp: applying the theme replaces every JList renderer with the default one and updates the UI. */
    static void applyTheme(Component c) {
        if (c instanceof javax.swing.JList<?> l) {
            @SuppressWarnings("unchecked") javax.swing.JList<Object> lo = (javax.swing.JList<Object>) l;
            lo.setCellRenderer(new javax.swing.DefaultListCellRenderer());
        }
        if (c instanceof java.awt.Container ct) for (Component ch : ct.getComponents()) applyTheme(ch);
    }

    private HttpRequestEditor editor() {
        JTextArea area = new JTextArea(10, 60);
        HttpRequest[] cur = new HttpRequest[1];
        return proxy(HttpRequestEditor.class, (p, m, a) -> switch (m.getName()) {
            case "uiComponent" -> area;
            case "setRequest" -> { cur[0] = (HttpRequest) a[0]; area.setText(String.valueOf(cur[0])); yield null; }
            case "getRequest" -> cur[0];
            default -> defaultValue(m);
        });
    }

    private Persistence persistence() {
        return proxy(Persistence.class, (p, m, a) -> m.getName().equals("preferences")
                ? proxy(Preferences.class, mapBacked(prefs)) : proxy(PersistedObject.class, mapBacked(extData)));
    }

    private static InvocationHandler mapBacked(Map<String, Object> map) {
        return (p, m, a) -> {
            String n = m.getName();
            if (n.startsWith("get")) return map.get((String) a[0]);
            if (n.startsWith("set")) { map.put((String) a[0], a[1]); return null; }
            if (n.startsWith("delete")) { map.remove((String) a[0]); return null; }
            return defaultValue(m);
        };
    }

    private Extension extension() {
        return proxy(Extension.class, (p, m, a) -> {
            if (m.getName().equals("registerUnloadingHandler")) unloading.add((ExtensionUnloadingHandler) a[0]);
            return defaultValue(m);
        });
    }

    private Logging logging() {
        return proxy(Logging.class, (p, m, a) -> {
            if (m.getName().startsWith("logTo")) {
                String msg = String.valueOf(a[0]);
                logs.add(msg);
                System.out.println("  [burp " + m.getName() + "] " + msg);
                if (a.length > 1 && a[1] instanceof Throwable t) t.printStackTrace(System.out);
            }
            return null;
        });
    }

    // ---------- fake Montoya object factory ----------

    /** Action returned by a handler: factory method name + arguments. */
    public static final class Action implements InvocationHandler {
        public final String kind;
        public final Object[] args;
        Action(String kind, Object[] args) { this.kind = kind; this.args = args == null ? new Object[0] : args; }
        public HttpRequest request() { for (Object o : args) if (o instanceof HttpRequest r) return r; return null; }
        public Annotations annotations() { for (Object o : args) if (o instanceof Annotations x) return x; return null; }
        @Override public Object invoke(Object p, Method m, Object[] a) {
            return switch (m.getName()) {
                case "request" -> request();
                case "annotations" -> annotations();
                case "toString" -> kind;
                default -> defaultValue(m);
            };
        }
    }

    public static Action action(Object proxyAction) {
        return (Action) java.lang.reflect.Proxy.getInvocationHandler(proxyAction);
    }

    private static void installFactory() {
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory.class, (p, m, a) -> {
            String n = m.getName();
            Class<?> r = m.getReturnType();
            if (r.getSimpleName().endsWith("Action")) return proxy(r, new Action(n, a));
            switch (n) {
                case "httpService": return a.length == 3 ? service((String) a[0], (Integer) a[1], (Boolean) a[2]) : service(String.valueOf(a[0]), 443, true);
                case "byteArray": return a[0] instanceof byte[] b ? bytes(b) : bytes(String.valueOf(a[0]).getBytes(StandardCharsets.UTF_8));
                case "httpRequest": {
                    Object last = a == null || a.length == 0 ? "" : a[a.length - 1];
                    byte[] b = last instanceof ByteArray ba ? ba.getBytes() : String.valueOf(last).getBytes(StandardCharsets.UTF_8);
                    HttpService s = a != null && a.length == 2 ? (HttpService) a[0] : null;
                    String text = new String(b, StandardCharsets.UTF_8);
                    return proxy(HttpRequest.class, (p2, m2, a2) -> switch (m2.getName()) {
                        case "toString" -> text;
                        case "httpService" -> s;
                        case "toByteArray" -> bytes(b);
                        default -> defaultValue(m2);
                    });
                }
                case "hotkey": return proxy(burp.api.montoya.ui.hotkey.HotKey.class, (p2, m2, a2) -> m2.getName().equals("name") ? a[0] : a[1]);
                case "annotations": return new Ann().as();
                default: return defaultValue(m);
            }
        });
    }
}
