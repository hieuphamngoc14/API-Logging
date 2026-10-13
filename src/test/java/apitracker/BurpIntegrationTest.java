package apitracker;

import apitracker.FakeBurp.Action;
import apitracker.FakeBurp.Ann;
import apitracker.store.Repo;
import apitracker.store.Rows;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import org.sqlite.SQLiteDataSource;

import javax.imageio.ImageIO;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Runs the real extension on a fake Burp (needs a display; use xvfb-run on headless Linux).
 * Checks the flows Proxy → highlight yellow, Repeater → log + clear yellow, x-burp header, Send to Repeater (tracked),
 * tab hook, UI, unload.
 */
public final class BurpIntegrationTest {
    static int passed, failed;

    static final String ORIG = "POST /condition-orders/underlying-order/api/v1/so-order HTTP/1.1\n"
            + "Host: api.example.com\n"
            + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQSJ9.sig-aaaaaaaa\n"
            + "Content-Type: application/json\n"
            + "\n"
            + "{\"accountNo\":\"0001\",\"symbol\":\"VNM\",\"qty\":100,\"price\":65000}";

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("apitracker-it");
        Path shotDir = Path.of(args.length > 0 ? args[0] : home.toString());
        FakeBurp fb = new FakeBurp();
        fb.prefs.put("apitracker.storageDir", home.toString());
        fb.prefs.put("apitracker.sensitiveTokens", "authorization,accountNo");   // Settings → Masked fields

        JTabbedPane[] sub = new JTabbedPane[1];
        SwingUtilities.invokeAndWait(() -> {
            JFrame f = new JFrame("Fake Burp");
            JTabbedPane main = new JTabbedPane();
            main.addTab("Proxy", new JPanel());
            JPanel repRoot = new JPanel(new BorderLayout());
            sub[0] = new JTabbedPane();
            sub[0].addTab("1", editorTab("GET /old HTTP/1.1\nHost: api.example.com\n\n"));
            repRoot.add(sub[0]);
            main.addTab("Repeater", repRoot);
            f.add(main);
            f.setSize(600, 400);
            fb.suiteFrame = f;
        });

        long loadedAt = System.currentTimeMillis();
        new ApiTrackerExtension().initialize(fb.api);
        check("handlers registered", fb.httpHandlers.size() == 1 && fb.proxyReq.size() == 1 && fb.proxyResp.size() == 1);
        check("tab registered", fb.suiteTab != null);
        waitFor("DB opened", () -> fb.logs.stream().anyMatch(l -> l.contains("Opened")), 10_000);
        Path dbFile = home.resolve("KBSV_mobile.db");
        check("DB file named after the project", Files.exists(dbFile));
        check("dbFile saved to extensionData", "KBSV_mobile.db".equals(fb.extData.get("dbFile")));

        HttpHandler http = fb.httpHandlers.get(0);
        ProxyRequestHandler preq = fb.proxyReq.get(0);
        ProxyResponseHandler presp = fb.proxyResp.get(0);

        // 1. Proxy: untested API → yellow + note
        HttpRequest p1 = fb.request(ORIG, "api.example.com", 443, true, ToolType.PROXY, new Ann(), fb.nextMessageId(), true);
        Action r1 = FakeBurp.action(preq.handleRequestReceived((InterceptedRequest) p1));
        check("normal request follows Intercept rules", r1.kind.contains("FollowUserRules"));
        Action s1 = FakeBurp.action(preq.handleRequestToBeSent((InterceptedRequest) p1));
        check("untested API highlighted yellow", s1.annotations() != null && s1.annotations().highlightColor() == HighlightColor.YELLOW);
        check("untested note", s1.annotations() != null && "untested".equals(s1.annotations().notes()));
        ProxyHttpRequestResponse h1 = fb.addHistory(p1, s1.annotations());

        HttpRequest js = fb.request("GET /static/app.js HTTP/1.1\nHost: api.example.com\n\n", "api.example.com", 443, true,
                ToolType.PROXY, new Ann(), fb.nextMessageId(), true);
        Action sj = FakeBurp.action(preq.handleRequestToBeSent((InterceptedRequest) js));
        check("static file not highlighted", sj.annotations() == null);
        HttpRequest out = fb.request("GET /other HTTP/1.1\nHost: x.com\n\n", "x.com", 443, true, ToolType.PROXY, new Ann(), fb.nextMessageId(), false);
        check("out of scope not highlighted", FakeBurp.action(preq.handleRequestToBeSent((InterceptedRequest) out)).annotations() == null);
        Ann userColor = new Ann();
        userColor.color = HighlightColor.RED;
        HttpRequest red = fb.request(ORIG, "api.example.com", 443, true, ToolType.PROXY, userColor, fb.nextMessageId(), true);
        check("user color not overwritten", FakeBurp.action(preq.handleRequestToBeSent((InterceptedRequest) red)).annotations() == null);

        // 2. Repeater (plain Ctrl+R, no tracked original): send edit → look up Proxy as original → diff → tested → clear yellow
        int id = fb.nextMessageId();
        HttpRequest rep = fb.request(ORIG.replace("\"qty\":100", "\"qty\":-1"), "api.example.com", 443, true, ToolType.REPEATER, new Ann(), id, true);
        http.handleHttpRequestToBeSent((HttpRequestToBeSent) rep);
        http.handleHttpResponseReceived((HttpResponseReceived) fb.response(400, 50, null, rep, ToolType.REPEATER, id));
        waitFor("old Proxy entry yellow cleared", () -> fb.annOf(h1).color == HighlightColor.NONE, 15_000);
        check("untested note removed", fb.annOf(h1).notes == null || fb.annOf(h1).notes.isEmpty());
        HttpRequest p2 = fb.request(ORIG, "api.example.com", 443, true, ToolType.PROXY, new Ann(), fb.nextMessageId(), true);
        check("tested API no longer highlighted", FakeBurp.action(preq.handleRequestToBeSent((InterceptedRequest) p2)).annotations() == null);

        // 3. AI via curl with x-burp header
        Ann aiAnn = new Ann();
        int aiId = fb.nextMessageId();
        HttpRequest ai = fb.request(ORIG.replace("Host: api.example.com\n", "Host: api.example.com\nx-burp: claude\n").replace("0001", "0002"),
                "api.example.com", 443, true, ToolType.PROXY, aiAnn, aiId, true);
        Action ra = FakeBurp.action(preq.handleRequestReceived((InterceptedRequest) ai));
        check("AI request not intercepted", ra.kind.contains("DoNotIntercept"));
        check("x-burp header stripped", ra.request() != null && ra.request().headerValue("x-burp") == null);
        check("AI entry magenta + note", ra.annotations().highlightColor() == HighlightColor.MAGENTA
                && "[AI] claude".equals(ra.annotations().notes()));
        aiAnn.color = HighlightColor.MAGENTA;                                     // Burp applies the previous step's annotations
        aiAnn.notes = "[AI] claude";
        check("AI entry not highlighted yellow", FakeBurp.action(preq.handleRequestToBeSent((InterceptedRequest) ra.request())).annotations() == null);
        presp.handleResponseReceived((InterceptedResponse) fb.response(200, 20, null, ra.request(), ToolType.PROXY, aiId));

        // 4. Send to Repeater (tracked) via context menu
        ContextMenuEvent ev = FakeBurp.proxy(ContextMenuEvent.class, (p, m, a) -> switch (m.getName()) {
            case "selectedRequestResponses" -> List.of(FakeBurp.proxy(HttpRequestResponse.class, (px, m2, a2) ->
                    m2.getName().equals("request") ? p1 : FakeBurp.defaultValue(m2)));
            case "messageEditorRequestResponse" -> Optional.empty();
            default -> FakeBurp.defaultValue(m);
        });
        List<Component> items = fb.menus.get(0).provideMenuItems(ev);
        check("menu has Send to Repeater (tracked)", items.stream().anyMatch(c -> c instanceof JMenuItem mi && mi.getText().equals("Send to Repeater (tracked)")));
        SwingUtilities.invokeAndWait(() -> ((JMenuItem) items.get(0)).doClick());
        check("Repeater receives tab name", fb.repeaterSends.contains("POST /condition-orders/underlying-order/api/v1/so-order"));

        // 5. Tab hook: new tab "2" holding a request → renamed
        long wait = 10_500 - (System.currentTimeMillis() - loadedAt);
        if (wait > 0) Thread.sleep(wait);
        waitFor("hook attached to Repeater area", () -> fb.logs.stream().anyMatch(l -> l.contains("Attached to the Repeater tab area (")), 5_000);
        SwingUtilities.invokeAndWait(() -> sub[0].addTab("2", editorTab(
                "GET /condition-orders/underlying-order/api/v1/so-order/8831 HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer x\n\n")));
        waitFor("new tab renamed", () -> {
            AtomicReference<String> t = new AtomicReference<>();
            try { SwingUtilities.invokeAndWait(() -> t.set(sub[0].getTitleAt(1))); } catch (Exception e) { return false; }
            return t.get().equals("GET /condition-orders/underlying-order/api/v1/so-order/8831");
        }, 5_000);
        check("existing project tab not renamed", "1".equals(titleAt(sub[0], 0)));

        // send from hooked tab: original from the hook is matched (service taken from the send)
        int id3 = fb.nextMessageId();
        HttpRequest rep3 = fb.request("GET /condition-orders/underlying-order/api/v1/so-order/8832 HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer x\n\n",
                "api.example.com", 443, true, ToolType.REPEATER, new Ann(), id3, true);
        http.handleHttpRequestToBeSent((HttpRequestToBeSent) rep3);
        http.handleHttpResponseReceived((HttpResponseReceived) fb.response(200, 10, null, rep3, ToolType.REPEATER, id3));

        // x-burp header leaking into Repeater (resent AI request): still stripped; Proxy requests not rescanned
        HttpRequest repAi = fb.request("GET /strip-check HTTP/1.1\nHost: api.example.com\nX-Burp: 1\n\n", "api.example.com", 443, true,
                ToolType.REPEATER, new Ann(), fb.nextMessageId(), true);
        Action sa = FakeBurp.action(http.handleHttpRequestToBeSent((HttpRequestToBeSent) repAi));
        check("Repeater: x-burp header stripped", sa.request() != null && sa.request().headerValue("x-burp") == null);
        HttpRequest proxyAi = fb.request("GET /strip-check HTTP/1.1\nHost: api.example.com\nX-Burp: 1\n\n", "api.example.com", 443, true,
                ToolType.PROXY, new Ann(), fb.nextMessageId(), true);
        Action sp = FakeBurp.action(http.handleHttpRequestToBeSent((HttpRequestToBeSent) proxyAi));
        check("HttpHandler does not reprocess Proxy requests", sp.request() == proxyAi);

        // Intruder: 15 requests fuzzing $.orderId → one summary row, not 15 rows
        String cancel = "POST /condition-orders/underlying-order/api/v1/cancel-order HTTP/1.1\nHost: api.example.com\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQSJ9.sig-aaaaaaaa\nContent-Type: application/json\n\n";
        for (int i = 0; i < 15; i++) {
            int mid = fb.nextMessageId();
            HttpRequest ir = fb.request(cancel + "{\"orderId\":\"" + (i == 7 ? "1' OR '1'='1" : "A" + i) + "\",\"reason\":\"x\"}",
                    "api.example.com", 443, true, ToolType.INTRUDER, new Ann(), mid, true);
            http.handleHttpRequestToBeSent((HttpRequestToBeSent) ir);
            http.handleHttpResponseReceived((HttpResponseReceived) fb.response(i == 7 ? 500 : 200, 40 + i, null, ir, ToolType.INTRUDER, mid));
        }

        // 6. check the DB through a separate read connection
        Thread.sleep(2_500);
        int[] intruderApi = {-1};
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + dbFile);
        try (Repo repo = new Repo(ds.getConnection())) {
            List<Rows.SendRow> all = repo.page(1, Long.MAX_VALUE, 100, Repo.Filter.ALL);
            check("so-order API has 2 sends (Repeater + AI)", all.size() == 2);
            Rows.SendRow aiRow = all.stream().filter(r -> !r.source().equals("repeater")).findFirst().orElse(null);
            check("AI send has source ai:claude", aiRow != null && aiRow.source().equals("ai:claude"));
            check("AI diff vs original", aiRow != null && aiRow.changes().contains("$.accountNo"));
            check("no x-burp header left in log", aiRow != null && !aiRow.changes().toLowerCase().contains("x-burp"));
            Rows.SendRow repRow = all.stream().filter(r -> r.source().equals("repeater")).findFirst().orElse(null);
            check("diff Repeater qty", repRow != null && repRow.changes().contains("$.qty   100 → -1"));
            check("token not leaked in log", all.stream().noneMatch(r -> r.changes().contains("eyJ") || r.firstLine().contains("eyJ")));
            check("masked field from Settings shows a fingerprint, other fields cleartext",
                    aiRow != null && aiRow.changes().contains("$.accountNo   <#") && !aiRow.changes().contains("0001")
                    && repRow != null && repRow.changes().contains("$.qty   100 → -1"));
            List<Rows.SendRow> idApi = repo.page(2, Long.MAX_VALUE, 100, Repo.Filter.ALL);
            check("so-order/{id} API: send vs original from hook", idApi.size() == 1 && idApi.get(0).changes().contains("[5]   8831 → 8832"));
            List<Rows.OriginalRow> og = repo.originals(1);
            check("original from Proxy history", og.stream().anyMatch(o -> o.source() == Rows.SRC_PROXY));
            Map<Integer, Integer> intr = repo.searchAll("intruder", List.of());
            check("Intruder: summary row exists", intr.size() == 1);
            int iApi = intr.isEmpty() ? -1 : intr.keySet().iterator().next();
            List<Rows.SendRow> irows = repo.page(iApi, Long.MAX_VALUE, 50, Repo.Filter.ALL);
            check("Intruder: one row for the whole 15-request attack", irows.size() == 1 && (irows.get(0).flags() & Rows.FLAG_INTRUDER) != 0);
            check("Intruder: correct payload position", !irows.isEmpty() && irows.get(0).changes().contains("§ body    $.orderId")
                    && !irows.get(0).changes().contains("reason"));
            check("Intruder: payloads not logged", irows.stream().noneMatch(r -> r.changes().contains("OR '1'")));
            intruderApi[0] = iApi;
        }

        // 7. UI: screenshot the extension tab (first API in the list is the one just hit by Intruder)
        JFrame[] frame = new JFrame[1];
        SwingUtilities.invokeAndWait(() -> {
            frame[0] = new JFrame("API Logging");
            frame[0].add(fb.suiteTab);
            frame[0].setSize(new Dimension(1400, 820));
            frame[0].setVisible(true);
        });
        Thread.sleep(800);
        // Burp reapplies the theme (light / dark switch) after the tab is shown: extension renderers must survive
        SwingUtilities.invokeAndWait(() -> FakeBurp.applyTheme(fb.suiteTab));
        SwingUtilities.invokeAndWait(() -> {
            JList<?> apiList = findList(fb.suiteTab, 0);
            if (apiList != null) apiList.setSelectedIndex(1);
        });
        Thread.sleep(500);
        String[] cells = new String[2];
        SwingUtilities.invokeAndWait(() -> {
            for (int k = 0; k < 2; k++) {
                @SuppressWarnings("unchecked") JList<Object> l = (JList<Object>) findList(fb.suiteTab, k);
                if (l == null || l.getModel().getSize() == 0) continue;
                int idx = l.getModel().getSize() > 1 ? 1 : 0;
                Component c = l.getCellRenderer().getListCellRendererComponent(l, l.getModel().getElementAt(idx), idx, false, false);
                cells[k] = c.getClass().getName() + (c instanceof javax.swing.JLabel lb ? ":" + lb.getText() : "");
            }
        });
        check("API list uses the extension renderer after Burp applies the theme",
                cells[0] != null && !cells[0].contains("DefaultListCellRenderer") && !cells[0].contains("@"));
        check("log list uses the extension renderer after Burp applies the theme",
                cells[1] != null && !cells[1].contains("DefaultListCellRenderer") && !cells[1].contains("@"));
        // API list: one line per item = method + full path (no query), cell wide enough not to cut the path
        List<String> apiTexts = new java.util.ArrayList<>();
        boolean[] fits = {true};
        SwingUtilities.invokeAndWait(() -> {
            @SuppressWarnings("unchecked") JList<Object> l = (JList<Object>) findList(fb.suiteTab, 0);
            if (l == null) return;
            for (int i = 0; i < l.getModel().getSize(); i++) {
                Object v = l.getModel().getElementAt(i);
                Component c = l.getCellRenderer().getListCellRendererComponent(l, v, i, false, false);
                List<Component> parts = new java.util.ArrayList<>();
                collect(c, parts);
                for (Component pc : parts) {
                    if (pc instanceof javax.swing.JLabel lb && lb.getText() != null && lb.getText().contains(" /")) {
                        apiTexts.add(lb.getText());
                        if (lb.getFontMetrics(lb.getFont()).stringWidth(lb.getText()) > l.getFixedCellWidth()) fits[0] = false;
                    }
                }
            }
        });
        System.out.println("  API list items: " + apiTexts);
        check("API list shows method + full path, one line, not cut",
                apiTexts.contains("POST /condition-orders/underlying-order/api/v1/so-order")
                && apiTexts.contains("GET /condition-orders/underlying-order/api/v1/so-order/{id}")
                && apiTexts.stream().noneMatch(t -> t.contains("?") || t.contains("…")) && fits[0]);
        Thread.sleep(1_500);
        BufferedImage img = new BufferedImage(1400, 820, BufferedImage.TYPE_INT_RGB);
        SwingUtilities.invokeAndWait(() -> frame[0].getContentPane().paint(img.getGraphics()));
        File shot = shotDir.resolve("ui-apis.png").toFile();
        ImageIO.write(img, "png", shot);
        check("UI screenshot", shot.length() > 1000);
        System.out.println("  UI screenshot: " + shot);
        SwingUtilities.invokeAndWait(() -> {
            JList<?> apiList = findList(fb.suiteTab, 0);
            if (apiList != null) apiList.setSelectedIndex(2);
        });
        Thread.sleep(1_000);
        SwingUtilities.invokeAndWait(() -> {
            JList<?> logList = findList(fb.suiteTab, 1);
            if (logList != null) logList.setSelectedIndex(logList.getModel().getSize() - 1);
        });
        Thread.sleep(1_000);
        // double-click a log row → send to Repeater: tab name = method + real path (no query, no {id})
        int sendsBefore = fb.repeaterSends.size();
        SwingUtilities.invokeAndWait(() -> {
            JList<?> logList = findList(fb.suiteTab, 1);
            if (logList == null || logList.getSelectedIndex() < 0) return;
            java.awt.Rectangle r = logList.getCellBounds(logList.getSelectedIndex(), logList.getSelectedIndex());
            java.awt.event.MouseEvent me = new java.awt.event.MouseEvent(logList, java.awt.event.MouseEvent.MOUSE_CLICKED,
                    System.currentTimeMillis(), 0, r.x + 5, r.y + 5, 2, false);
            for (java.awt.event.MouseListener ml : logList.getMouseListeners()) ml.mouseClicked(me);
        });
        waitFor("UI sends log row to Repeater", () -> fb.repeaterSends.size() > sendsBefore, 5_000);
        String uiSent = fb.repeaterSends.isEmpty() ? "" : fb.repeaterSends.get(fb.repeaterSends.size() - 1);
        System.out.println("  tab name from UI: " + uiSent);
        // log numbered per API: the original is #1 (no "ORIGINAL" word), the send #2 compared against #1
        String[] heads = new String[2];
        SwingUtilities.invokeAndWait(() -> {
            JList<?> ll = findList(fb.suiteTab, 1);
            if (ll != null && ll.getModel().getSize() >= 2) {
                heads[0] = String.valueOf(ll.getModel().getElementAt(0));
                heads[1] = String.valueOf(ll.getModel().getElementAt(1));
            }
        });
        System.out.println("  log heads: " + heads[0] + " | " + heads[1]);
        check("log numbered per API: original #1, send #2 vs original #1, tab name #2",
                heads[0] != null && heads[0].startsWith("#1  ") && !heads[0].contains("ORIGINAL")
                && heads[1] != null && heads[1].startsWith("#2  ") && heads[1].endsWith("(vs original #1)")
                && uiSent.endsWith(" #2"));
        // Burp context menu → "API Logging: copy this API's log for AI": Markdown with the original's request + response
        List<Component> menu2 = fb.menus.get(0).provideMenuItems(ev);
        JMenuItem copyAi = null;
        for (Component c : menu2) if (c instanceof JMenuItem mi && mi.getText().equals("API Logging: copy this API's log for AI")) copyAi = mi;
        check("Burp context menu has \"copy this API's log for AI\"", copyAi != null);
        java.awt.datatransfer.Clipboard sysClip = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
        SwingUtilities.invokeAndWait(() -> sysClip.setContents(new java.awt.datatransfer.StringSelection(""), null));
        if (copyAi != null) { JMenuItem ca = copyAi; SwingUtilities.invokeAndWait(ca::doClick); }
        String[] clip = {""};
        waitFor("log for AI on the clipboard", () -> {
            try {
                SwingUtilities.invokeAndWait(() -> {
                    try { clip[0] = String.valueOf(sysClip.getData(java.awt.datatransfer.DataFlavor.stringFlavor)); } catch (Exception ignored) { }
                });
            } catch (Exception e) { return false; }
            return clip[0].contains("## POST /condition-orders/underlying-order/api/v1/so-order");
        }, 5_000);
        check("AI log: guide, coverage, original request + response, tests",
                clip[0].contains("How to read this log") && clip[0].contains("### What was tested")
                && clip[0].contains("### Original request #1") && clip[0].contains("Response:\n```http\nHTTP/1.1 200 OK")
                && clip[0].contains("### Tests (oldest first)") && clip[0].contains("[AI:claude]"));
        // right-click in the API list → "Copy log for AI (this API)" / "Export all logs for AI…"
        javax.swing.JPopupMenu[] pop = new javax.swing.JPopupMenu[1];
        SwingUtilities.invokeAndWait(() -> {
            JList<?> al = findList(fb.suiteTab, 0);
            java.awt.Rectangle rb = al.getCellBounds(2, 2);
            java.awt.event.MouseEvent pe = new java.awt.event.MouseEvent(al, java.awt.event.MouseEvent.MOUSE_PRESSED,
                    System.currentTimeMillis(), java.awt.event.InputEvent.BUTTON3_DOWN_MASK, rb.x + 5, rb.y + 5, 1, true,
                    java.awt.event.MouseEvent.BUTTON3);
            for (java.awt.event.MouseListener ml : al.getMouseListeners()) ml.mousePressed(pe);
            for (java.awt.Window w : java.awt.Window.getWindows()) {
                List<Component> parts = new java.util.ArrayList<>();
                collect(w, parts);
                for (Component c : parts) if (c instanceof javax.swing.JPopupMenu pm && pm.isVisible()) pop[0] = pm;
            }
        });
        List<String> popItems = new java.util.ArrayList<>();
        JMenuItem copyOne = null;
        if (pop[0] != null) for (Component c : pop[0].getComponents()) {
            if (c instanceof JMenuItem mi) { popItems.add(mi.getText()); if (mi.getText().startsWith("Copy log for AI")) copyOne = mi; }
        }
        check("API list right-click menu: copy log / export all for AI",
                popItems.contains("Copy log for AI (this API)") && popItems.contains("Export all logs for AI…"));
        SwingUtilities.invokeAndWait(() -> sysClip.setContents(new java.awt.datatransfer.StringSelection(""), null));
        if (copyOne != null) { JMenuItem co = copyOne; SwingUtilities.invokeAndWait(() -> { co.doClick(); pop[0].setVisible(false); }); }
        waitFor("API list copy for AI", () -> {
            try {
                SwingUtilities.invokeAndWait(() -> {
                    try { clip[0] = String.valueOf(sysClip.getData(java.awt.datatransfer.DataFlavor.stringFlavor)); } catch (Exception ignored) { }
                });
            } catch (Exception e) { return false; }
            return clip[0].contains("## GET /condition-orders/underlying-order/api/v1/so-order/{id}");
        }, 5_000);
        check("copied log of the right-clicked API (hook original + its test)",
                clip[0].contains("## GET /condition-orders/underlying-order/api/v1/so-order/{id}") && clip[0].contains("path `[5]`: modified 1×"));
        check("UI → Repeater: tab name is the full path, no query/{id}",
                uiSent.matches("^[A-Z]+ /[^?{ ]+ (#\\d+|original)$") && uiSent.contains("/condition-orders/"));
        // log panel keeps only the "Send to Repeater" button: no log search box, filter chips, Follow, Copy Markdown
        List<Component> apiTabParts = new java.util.ArrayList<>();
        javax.swing.JButton[] repBtn = new javax.swing.JButton[1];
        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane tabs = findTabs(fb.suiteTab);
            if (tabs != null) collect(tabs.getComponentAt(0), apiTabParts);
            for (Component c : apiTabParts) if (c instanceof javax.swing.JButton b && "Send to Repeater".equals(b.getText())) repBtn[0] = b;
        });
        long textFields = apiTabParts.stream().filter(c -> c instanceof javax.swing.JTextField).count();
        boolean removed = apiTabParts.stream().noneMatch(c ->
                c instanceof javax.swing.JToggleButton t && List.of("2xx", "header", "Repeater", "AI", "Intruder").contains(t.getText())
                || c instanceof javax.swing.AbstractButton b && List.of("Follow", "Copy Markdown").contains(b.getText()));
        check("log panel: search box + Send to Repeater button (no chips/Follow/Copy Markdown)",
                textFields == 2 && removed && repBtn[0] != null);
        check("search boxes only say \"Search\"", apiTabParts.stream().filter(c -> c instanceof javax.swing.JTextField)
                .allMatch(c -> "Search".equals(((javax.swing.JTextField) c).getClientProperty("JTextField.placeholderText"))));
        check("no Request / Changes panel: log fills the whole right side",
                apiTabParts.stream().noneMatch(c -> c instanceof JTabbedPane)
                && apiTabParts.stream().noneMatch(c -> c instanceof javax.swing.JSplitPane vsp && vsp.getOrientation() == javax.swing.JSplitPane.VERTICAL_SPLIT));
        int sendsBefore2 = fb.repeaterSends.size();
        if (repBtn[0] != null) SwingUtilities.invokeAndWait(repBtn[0]::doClick);
        waitFor("Send to Repeater button works", () -> fb.repeaterSends.size() > sendsBefore2, 5_000);
        check("Send to Repeater button sends the selected row", uiSent.equals(fb.repeaterSends.get(fb.repeaterSends.size() - 1)));

        // search box in the log header: filters the selected API's log
        javax.swing.JTextField[] logSearchF = new javax.swing.JTextField[1];
        SwingUtilities.invokeAndWait(() -> {
            for (Component c : apiTabParts) {
                if (c instanceof javax.swing.JTextField tf && SwingUtilities.isDescendingFrom(tf, repBtn[0].getParent())) logSearchF[0] = tf;
            }
        });
        check("search box sits next to the Send to Repeater button", logSearchF[0] != null);
        if (logSearchF[0] != null) {
            JList<?> ll = findList(fb.suiteTab, 1);
            SwingUtilities.invokeAndWait(() -> logSearchF[0].setText("8832"));
            waitFor("search 8832 in log", () -> footerText(apiTabParts).contains("matching") && ll.getModel().getSize() == 2, 5_000);
            check("log search: 1 matching send (original still shown)", footerText(apiTabParts).startsWith("1 matching send"));
            SwingUtilities.invokeAndWait(() -> logSearchF[0].setText("nosuchtext"));
            waitFor("search for a missing string", () -> footerText(apiTabParts).startsWith("0 matching sends"), 5_000);
            SwingUtilities.invokeAndWait(() -> logSearchF[0].setText("8832"));
            waitFor("search 8832 again", () -> footerText(apiTabParts).startsWith("1 matching send"), 5_000);
        }
        // font: uses Burp's UI font (currentDisplayFont), not the editor font
        String[] fonts = new String[2];
        SwingUtilities.invokeAndWait(() -> {
            for (Component c : apiTabParts) {
                if (c instanceof javax.swing.JLabel lb && lb.getText() != null && lb.getText().startsWith("GET /condition-orders")) fonts[0] = lb.getFont().getFamily();
            }
            @SuppressWarnings("unchecked") JList<Object> al = (JList<Object>) findList(fb.suiteTab, 0);
            for (int i = 0; i < al.getModel().getSize(); i++) {
                Component c = al.getCellRenderer().getListCellRendererComponent(al, al.getModel().getElementAt(i), i, false, false);
                List<Component> parts = new java.util.ArrayList<>();
                collect(c, parts);
                for (Component pc : parts) if (pc instanceof javax.swing.JLabel lb && lb.getText() != null && lb.getText().contains(" /")) fonts[1] = lb.getFont().getFamily();
            }
        });
        System.out.println("  title / list font: " + fonts[0] + " / " + fonts[1]);
        check("UI uses Burp's UI font", FakeBurp.DISPLAY_FONT.getFamily().equals(fonts[0])
                && FakeBurp.DISPLAY_FONT.getFamily().equals(fonts[1]));
        BufferedImage img2 = new BufferedImage(1400, 820, BufferedImage.TYPE_INT_RGB);
        SwingUtilities.invokeAndWait(() -> frame[0].getContentPane().paint(img2.getGraphics()));
        ImageIO.write(img2, "png", shotDir.resolve("ui-log.png").toFile());

        // "Untested APIs in scope (Proxy history)": replaces "Search the log" + "Untested (Proxy)"
        check("no \"Search the log\" box anymore", apiTabParts.stream().noneMatch(c ->
                c instanceof javax.swing.AbstractButton b && "Search the log".equals(b.getText())));
        javax.swing.JCheckBox[] untested = new javax.swing.JCheckBox[1];
        for (Component c : apiTabParts) {
            if (c instanceof javax.swing.JCheckBox cb && cb.getText() != null && cb.getText().startsWith("Untested APIs in scope")) untested[0] = cb;
        }
        check("has the untested-APIs-in-scope checkbox", untested[0] != null);
        fb.addHistory(fb.request("GET /open-api/inq/accounts/0009003785/availableTrade?x=1 HTTP/1.1\nHost: api.example.com\n\n",
                "api.example.com", 443, true, ToolType.PROXY, new Ann(), fb.nextMessageId(), true), new Ann().as());
        fb.addHistory(fb.request("GET /v1/profile HTTP/1.1\nHost: other.example.net\n\n",
                "other.example.net", 443, true, ToolType.PROXY, new Ann(), fb.nextMessageId(), false), new Ann().as());
        JList<?> apiL = findList(fb.suiteTab, 0);
        java.util.function.Supplier<String> apiItems = () -> {
            StringBuilder b = new StringBuilder();
            try {
                SwingUtilities.invokeAndWait(() -> {
                    for (int i = 0; i < apiL.getModel().getSize(); i++) b.append(apiL.getModel().getElementAt(i)).append(" | ");
                });
            } catch (Exception ignored) { }
            return b.toString();
        };
        if (untested[0] != null) {
            SwingUtilities.invokeAndWait(untested[0]::doClick);
            waitFor("untested-in-scope list", () -> apiItems.get().contains("availableTrade"), 5_000);
            String l1 = apiItems.get();
            System.out.println("  untested in scope: " + l1);
            check("untested in scope: has in-scope API, no out-of-scope API, no tested API",
                    l1.contains("GET /open-api/inq/accounts/{id}/availableTrade") && !l1.contains("/v1/profile")
                    && !l1.contains("POST /condition-orders/underlying-order/api/v1/so-order |"));
            fb.includeInScope("https://other.example.net");                   // Add to scope in Burp
            waitFor("scope added: list updates itself", () -> apiItems.get().contains("GET /v1/profile"), 5_000);
            BufferedImage imgU = new BufferedImage(1400, 820, BufferedImage.TYPE_INT_RGB);
            SwingUtilities.invokeAndWait(() -> frame[0].getContentPane().paint(imgU.getGraphics()));
            ImageIO.write(imgU, "png", shotDir.resolve("ui-untested.png").toFile());
            // select untested API → Send to Repeater: takes the latest request from Proxy history
            int before3 = fb.repeaterSends.size();
            SwingUtilities.invokeAndWait(() -> {
                for (int i = 0; i < apiL.getModel().getSize(); i++) {
                    if (String.valueOf(apiL.getModel().getElementAt(i)).contains("availableTrade")) { apiL.setSelectedIndex(i); break; }
                }
                repBtn[0].doClick();
            });
            waitFor("send untested API to Repeater", () -> fb.repeaterSends.size() > before3, 5_000);
            String sentU = fb.repeaterSends.isEmpty() ? "" : fb.repeaterSends.get(fb.repeaterSends.size() - 1);
            check("untested API → Repeater with real path name: " + sentU, "GET /open-api/inq/accounts/0009003785/availableTrade".equals(sentU));
            SwingUtilities.invokeAndWait(untested[0]::doClick);                // back to the API list
        }
        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane tabs = findTabs(fb.suiteTab);
            if (tabs != null) tabs.setSelectedIndex(1);
        });
        Thread.sleep(500);
        BufferedImage img3 = new BufferedImage(1400, 820, BufferedImage.TYPE_INT_RGB);
        SwingUtilities.invokeAndWait(() -> frame[0].getContentPane().paint(img3.getGraphics()));
        ImageIO.write(img3, "png", shotDir.resolve("ui-settings.png").toFile());

        // 8. unload
        fb.unloading.get(0).extensionUnloaded();
        try (FileChannel ch = FileChannel.open(home.resolve("KBSV_mobile.db.lock"), StandardOpenOption.WRITE)) {
            FileLock l = ch.tryLock();
            check("unload releases the DB lock", l != null);
            if (l != null) l.release();
        }
        check("no errors in Output", fb.logs.stream().noneMatch(l -> l.toLowerCase(java.util.Locale.ROOT).contains("error") || l.contains("Exception")));
        try (Repo repo = new Repo(ds.getConnection())) {
            List<Rows.SendRow> irows = repo.page(intruderApi[0], Long.MAX_VALUE, 50, Repo.Filter.ALL);
            if (System.getenv("IT_DEBUG") != null) irows.forEach(r -> System.out.println("  DEBUG " + r));
            check("Intruder: unload writes the final row (15 requests, finished)", irows.size() == 1
                    && (irows.get(0).flags() & Rows.FLAG_RUNNING) == 0 && irows.get(0).changes().contains("15 requests"));
        }
        // originals keep a readable request + response (AI context): the Proxy response is found for a tracked send
        // made without one, and comes along when an untested API is sent from the list
        List<String[]> ctx = new java.util.ArrayList<>();
        try (var c = ds.getConnection(); var st = c.createStatement();
             var rs = st.executeQuery("SELECT first_line, request_text, response_text FROM originals ORDER BY id")) {
            while (rs.next()) ctx.add(new String[]{rs.getString(1), rs.getString(2), rs.getString(3)});
        }
        if (System.getenv("IT_DEBUG") != null) ctx.forEach(r -> System.out.println("  DEBUG original " + String.join(" | ", r)));
        check("tracked original: request + Proxy response stored as text", ctx.stream().anyMatch(r ->
                r[0].startsWith("POST /condition-orders/underlying-order/api/v1/so-order") && r[1] != null
                && r[1].startsWith("POST /condition-orders/underlying-order/api/v1/so-order") && r[2] != null
                && r[2].startsWith("HTTP/1.1 200 OK") && r[2].contains("\"entry\":")));
        check("untested API sent from the list: request + response stored", ctx.stream().anyMatch(r ->
                r[0].contains("availableTrade") && r[1] != null && r[2] != null && r[2].contains("\"ok\":true")));
        SwingUtilities.invokeAndWait(() -> { frame[0].dispose(); fb.suiteFrame.dispose(); });

        System.out.println();
        System.out.println("INTEGRATION PASSED " + passed + "  FAILED " + failed);
        System.exit(failed == 0 ? 0 : 1);
    }

    static Component editorTab(String text) {
        JTextArea req = new JTextArea(text);
        JTextArea resp = new JTextArea("HTTP/1.1 200 OK\n\n");
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(req), BorderLayout.WEST);
        p.add(new JScrollPane(resp), BorderLayout.EAST);
        return p;
    }

    static String titleAt(JTabbedPane tp, int i) {
        AtomicReference<String> t = new AtomicReference<>();
        try { SwingUtilities.invokeAndWait(() -> t.set(tp.getTitleAt(i))); } catch (Exception e) { return null; }
        return t.get();
    }

    static String footerText(List<Component> parts) {
        String[] t = {""};
        try {
            SwingUtilities.invokeAndWait(() -> {
                for (Component c : parts) {
                    if (c instanceof javax.swing.JLabel lb && lb.getText() != null && lb.getText().contains("send")
                            && !lb.getText().matches(".*originals?  ·.*") && lb.getText().matches("^\\d.*")) t[0] = lb.getText();
                }
            });
        } catch (Exception ignored) { }
        return t[0];
    }

    static void collect(Component c, List<Component> out) {
        out.add(c);
        if (c instanceof Container ct) for (Component ch : ct.getComponents()) collect(ch, out);
    }

    static JTabbedPane findTabs(Component c) {
        if (c instanceof JTabbedPane t) return t;
        if (c instanceof Container ct) for (Component ch : ct.getComponents()) {
            JTabbedPane r = findTabs(ch);
            if (r != null) return r;
        }
        return null;
    }

    static JList<?> findList(Component c, int nth) {
        int[] n = {nth};
        return find(c, n);
    }

    private static JList<?> find(Component c, int[] n) {
        if (c instanceof JList<?> l) { if (n[0]-- == 0) return l; }
        if (c instanceof Container ct) for (Component ch : ct.getComponents()) {
            JList<?> r = find(ch, n);
            if (r != null) return r;
        }
        return null;
    }

    static void check(String what, boolean ok) {
        if (ok) { passed++; System.out.println("ok   " + what); }
        else { failed++; System.out.println("FAIL " + what); }
    }

    static void waitFor(String what, BooleanSupplier cond, long timeoutMs) throws InterruptedException {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (cond.getAsBoolean()) { check(what, true); return; }
            Thread.sleep(50);
        }
        check(what + " (timed out)", false);
    }
}
