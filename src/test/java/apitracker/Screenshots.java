package apitracker;

import apitracker.FakeBurp.Action;
import apitracker.FakeBurp.Ann;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;

import javax.imageio.ImageIO;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Regenerates the README screenshots and the sample AI export from a demo dataset (fictional shop API), by running the
 * real extension on the fake Burp. Needs a display (xvfb-run on headless Linux). Argument: output directory.
 */
public final class Screenshots {
    static final String HOST = "shop-api.example.com";
    static final String TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.cDTq8vL0dCwVnF2kH";
    static final String LOGIN = "POST /api/v2/auth/login HTTP/1.1\nHost: " + HOST + "\nUser-Agent: ShopApp/5.2 (iOS 18.1)\n"
            + "X-Device-Id: 7f3c9a12e4b8\nContent-Type: application/json\n\n"
            + "{\"username\":\"alice\",\"password\":\"Winter2026!\",\"remember\":true}";
    static final String LOGIN_RESP = "HTTP/1.1 200 OK\nContent-Type: application/json\nSet-Cookie: sid=9d1f4c0e2b7a; Path=/; HttpOnly\n\n"
            + "{\"token\":\"" + TOKEN + "\",\"user\":{\"id\":1042,\"name\":\"alice\",\"role\":\"user\"}}";
    static final String ORDER = "GET /api/v2/orders/10452 HTTP/1.1\nHost: " + HOST + "\nAuthorization: Bearer " + TOKEN
            + "\nAccept: application/json\n\n";
    static final String ORDER_RESP = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
            + "{\"id\":10452,\"userId\":1042,\"items\":2,\"total\":59.90,\"status\":\"shipped\"}";
    static final String PROFILE = "PUT /api/v2/users/1042/profile HTTP/1.1\nHost: " + HOST + "\nAuthorization: Bearer " + TOKEN
            + "\nContent-Type: application/json\n\n{\"displayName\":\"Alice\",\"phone\":\"+84901234567\"}";
    static final String PROFILE_RESP = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1042,\"displayName\":\"Alice\",\"role\":\"user\"}";

    public static void main(String[] args) throws Exception {
        Path out = Path.of(args.length > 0 ? args[0] : "docs/images");
        Files.createDirectories(out);
        Path home = Files.createTempDirectory("api-logging-shots");
        FakeBurp fb = new FakeBurp();
        fb.projectName = "Shop API pentest";
        fb.scopePrefixes.clear();
        fb.scopePrefixes.add("https://" + HOST);
        fb.prefs.put("apitracker.storageDir", home.toString());
        fb.prefs.put("apitracker.sensitiveTokens", "password");
        SwingUtilities.invokeAndWait(() -> {
            JFrame f = new JFrame("Burp");
            f.add(new JPanel());
            fb.suiteFrame = f;
        });
        new ApiTrackerExtension().initialize(fb.api);
        BurpIntegrationTest.waitFor("DB opened", () -> fb.logs.stream().anyMatch(l -> l.contains("Opened")), 10_000);
        HttpHandler http = fb.httpHandlers.get(0);
        ProxyRequestHandler preq = fb.proxyReq.get(0);
        ProxyResponseHandler presp = fb.proxyResp.get(0);

        // Proxy history: browsing the app (in scope), plus a CDN request (out of scope)
        HttpRequest login = proxy(fb, preq, LOGIN, LOGIN_RESP);
        proxy(fb, preq, ORDER, ORDER_RESP);
        proxy(fb, preq, PROFILE, PROFILE_RESP);
        proxy(fb, preq, "GET /api/v2/cart HTTP/1.1\nHost: " + HOST + "\nAuthorization: Bearer " + TOKEN + "\n\n", "HTTP/1.1 200 OK\n\n{\"items\":[]}");
        proxy(fb, preq, "POST /api/v2/payments/checkout HTTP/1.1\nHost: " + HOST + "\nAuthorization: Bearer " + TOKEN
                + "\nContent-Type: application/json\n\n{\"cartId\":88,\"method\":\"card\"}", "HTTP/1.1 201 Created\n\n{\"paymentId\":\"p_77\"}");
        proxy(fb, preq, "GET /api/v2/admin/users?page=1 HTTP/1.1\nHost: " + HOST + "\nAuthorization: Bearer " + TOKEN + "\n\n", "HTTP/1.1 403 Forbidden\n\n");
        proxy(fb, preq, "GET /api/v2/products?category=shoes HTTP/1.1\nHost: " + HOST + "\n\n", "HTTP/1.1 200 OK\n\n[]");

        // login: Send to Repeater (tracked) with its response → original #1, then tests from Repeater, an AI agent, Intruder
        ContextMenuEvent ev = menuEvent(login, LOGIN_RESP);
        List<Component> items = fb.menus.get(0).provideMenuItems(ev);
        SwingUtilities.invokeAndWait(() -> ((JMenuItem) items.get(0)).doClick());
        Thread.sleep(300);
        repeater(fb, http, LOGIN.replace("Winter2026!", "wrong-pass"), 401, 61);
        repeater(fb, http, LOGIN.replace("\"alice\"", "\"alice'--\""), 500, 1_204);
        repeater(fb, http, LOGIN.replace("\"alice\"", "\"' OR '1'='1\""), 401, 61);
        ai(fb, preq, presp, LOGIN.replace("X-Device-Id: 7f3c9a12e4b8\n", ""), 200, 412);
        for (int i = 0; i < 10; i++) {
            int mid = fb.nextMessageId();
            HttpRequest ir = fb.request(LOGIN.replace("Winter2026!", "Spring202" + i + "!"), HOST, 443, true, ToolType.INTRUDER, new Ann(), mid, true);
            http.handleHttpRequestToBeSent((HttpRequestToBeSent) ir);
            http.handleHttpResponseReceived((HttpResponseReceived) fb.response(i == 6 ? 200 : 401, i == 6 ? 412 : 61, null, ir, ToolType.INTRUDER, mid));
        }
        // orders: plain Repeater (original found in Proxy history with its response), IDOR and auth tests
        repeater(fb, http, ORDER.replace("10452", "10453"), 200, 233);
        repeater(fb, http, ORDER.replace("Authorization: Bearer " + TOKEN + "\n", ""), 401, 38);
        ai(fb, preq, presp, ORDER.replace("10452", "1"), 403, 41);
        // profile: mass assignment
        repeater(fb, http, PROFILE.replace("\"phone\":\"+84901234567\"", "\"phone\":\"+84901234567\",\"role\":\"admin\""), 200, 74);

        Thread.sleep(11_000);                                                 // let the Intruder attack finish
        JFrame[] frame = new JFrame[1];
        SwingUtilities.invokeAndWait(() -> {
            frame[0] = new JFrame("API Logging");
            frame[0].add(fb.suiteTab);
            frame[0].setSize(new Dimension(1360, 540));
            frame[0].setVisible(true);
        });
        Thread.sleep(800);
        select(fb, "POST /api/v2/auth/login");
        Thread.sleep(1_200);
        shot(frame[0], out.resolve("log.png"));
        select(fb, "GET /api/v2/orders/{id}");
        Thread.sleep(1_200);
        shot(frame[0], out.resolve("log-orders.png"));
        SwingUtilities.invokeAndWait(() -> {
            for (Component c : all(fb.suiteTab)) if (c instanceof JCheckBox cb && cb.getText().startsWith("Untested APIs")) cb.doClick();
        });
        Thread.sleep(1_500);
        shot(frame[0], out.resolve("untested.png"));
        SwingUtilities.invokeAndWait(() -> {
            for (Component c : all(fb.suiteTab)) if (c instanceof JCheckBox cb && cb.getText().startsWith("Untested APIs")) cb.doClick();
        });
        SwingUtilities.invokeAndWait(() -> {
            frame[0].setSize(new Dimension(1360, 760));
            JTabbedPane t = BurpIntegrationTest.findTabs(fb.suiteTab);
            if (t != null) t.setSelectedIndex(1);
            // show the default location instead of the demo's temp folder (display only, not saved)
            String tmp = home.toString();
            for (Component c : all(fb.suiteTab)) {
                if (c instanceof javax.swing.JTextField tf && tf.getText().equals(tmp)) tf.setText("~/BurpTracker");
                if (c instanceof javax.swing.JLabel lb && lb.getText() != null && lb.getText().startsWith(tmp)) {
                    lb.setText("~/BurpTracker" + lb.getText().substring(tmp.length()));
                }
            }
        });
        Thread.sleep(800);
        shot(frame[0], out.resolve("settings.png"));
        SwingUtilities.invokeAndWait(() -> { JTabbedPane t = BurpIntegrationTest.findTabs(fb.suiteTab); if (t != null) t.setSelectedIndex(0); });

        // sample export for AI (the real "Export all logs for AI" action)
        Path md = out.getParent() == null ? Path.of("sample-ai-export.md") : out.getParent().resolve("sample-ai-export.md");
        Files.deleteIfExists(md);
        apitracker.ui.UiProbe.exportAllFromUi(fb.suiteTab, md.toFile());
        BurpIntegrationTest.waitFor("export written", () -> Files.exists(md), 10_000);
        Thread.sleep(300);
        System.out.println("wrote " + out + " and " + md);
        fb.unloading.get(0).extensionUnloaded();
        SwingUtilities.invokeAndWait(() -> { frame[0].dispose(); fb.suiteFrame.dispose(); });
        System.exit(0);
    }

    static HttpRequest proxy(FakeBurp fb, ProxyRequestHandler preq, String raw, String resp) {
        HttpRequest r = fb.request(raw, HOST, 443, true, ToolType.PROXY, new Ann(), fb.nextMessageId(), true);
        Action a = FakeBurp.action(preq.handleRequestToBeSent((InterceptedRequest) r));
        fb.addHistory(r, a.annotations() != null ? a.annotations() : new Ann().as(), resp);
        return r;
    }

    static void repeater(FakeBurp fb, HttpHandler http, String raw, int status, int len) throws InterruptedException {
        int id = fb.nextMessageId();
        HttpRequest r = fb.request(raw, HOST, 443, true, ToolType.REPEATER, new Ann(), id, true);
        http.handleHttpRequestToBeSent((HttpRequestToBeSent) r);
        Thread.sleep(150);
        http.handleHttpResponseReceived((HttpResponseReceived) fb.response(status, len, null, r, ToolType.REPEATER, id));
        Thread.sleep(250);
    }

    static void ai(FakeBurp fb, ProxyRequestHandler preq, ProxyResponseHandler presp, String raw, int status, int len)
            throws InterruptedException {
        int id = fb.nextMessageId();
        HttpRequest r = fb.request(raw.replace("Host: " + HOST + "\n", "Host: " + HOST + "\nx-burp: claude\n"), HOST, 443, true,
                ToolType.PROXY, new Ann(), id, true);
        Action a = FakeBurp.action(preq.handleRequestReceived((InterceptedRequest) r));
        Thread.sleep(150);
        presp.handleResponseReceived((InterceptedResponse) fb.response(status, len, null, a.request(), ToolType.PROXY, id));
        Thread.sleep(250);
    }

    static ContextMenuEvent menuEvent(HttpRequest req, String resp) {
        HttpRequestResponse rr = FakeBurp.proxy(HttpRequestResponse.class, (p, m, a) -> switch (m.getName()) {
            case "request" -> req;
            case "hasResponse" -> true;
            case "response" -> FakeBurp.httpResponse(resp);
            default -> FakeBurp.defaultValue(m);
        });
        return FakeBurp.proxy(ContextMenuEvent.class, (p, m, a) -> switch (m.getName()) {
            case "selectedRequestResponses" -> List.of(rr);
            case "messageEditorRequestResponse" -> Optional.empty();
            default -> FakeBurp.defaultValue(m);
        });
    }

    static void select(FakeBurp fb, String label) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            JList<?> l = BurpIntegrationTest.findList(fb.suiteTab, 0);
            for (int i = 0; i < l.getModel().getSize(); i++) {
                if (String.valueOf(l.getModel().getElementAt(i)).equals(label)) { l.setSelectedIndex(i); break; }
            }
        });
    }

    static List<Component> all(Component root) {
        List<Component> out = new java.util.ArrayList<>();
        BurpIntegrationTest.collect(root, out);
        return out;
    }

    static void shot(JFrame f, Path file) throws Exception {
        BufferedImage img = new BufferedImage(f.getContentPane().getWidth(), f.getContentPane().getHeight(), BufferedImage.TYPE_INT_RGB);
        SwingUtilities.invokeAndWait(() -> f.getContentPane().paint(img.getGraphics()));
        ImageIO.write(img, "png", file.toFile());
    }
}
