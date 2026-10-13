package apitracker.burp;

import apitracker.core.ApiKeys;
import apitracker.core.Events;
import apitracker.core.TabNames;
import apitracker.core.Tracker;
import apitracker.store.DbWriter;
import apitracker.store.Rows;
import apitracker.ui.Labels;
import apitracker.util.Log;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyEvent;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Tier 1 of tab renaming (main path): the "Send to Repeater (tracked)" context menu and hotkey name the tab via
 * Montoya, so Burp saves the name in the Burp project, and the original request is exactly the selected one.
 * Also: label the selected value (userA token...), open the API's log in the extension tab.
 */
public final class TrackedSend implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final Supplier<Tracker> tracker;
    private final Supplier<DbWriter> writer;
    private final Labels labels;
    private final ApiKeys keys;
    private final Consumer<String> openApi;                  // apiKey → open in the extension tab
    private final Consumer<String> copyForAi;                // apiKey → copy its log for AI
    private final Set<String> usedNames = Collections.synchronizedSet(new HashSet<>());
    private final List<Registration> hotkeys = new ArrayList<>();

    public TrackedSend(MontoyaApi api, Supplier<Tracker> tracker, Supplier<DbWriter> writer, Labels labels, ApiKeys keys,
                       Consumer<String> openApi, Consumer<String> copyForAi) {
        this.api = api;
        this.tracker = tracker;
        this.writer = writer;
        this.labels = labels;
        this.keys = keys;
        this.openApi = openApi;
        this.copyForAi = copyForAi;
    }

    public void registerHotkeys(String hotkey) {
        if (hotkey == null || hotkey.isBlank()) return;
        for (HotKeyContext ctx : new HotKeyContext[]{HotKeyContext.PROXY_HTTP_HISTORY, HotKeyContext.SITE_MAP_CONTENTS_TABLE,
                HotKeyContext.HTTP_MESSAGE_EDITOR}) {
            try {
                hotkeys.add(api.userInterface().registerHotKeyHandler(ctx,
                        HotKey.hotKey("Send to Repeater (tracked)", hotkey), this::onHotKey));
            } catch (Throwable t) {
                Log.warn("Could not register hotkey " + hotkey + " for " + ctx + ": " + t.getMessage());
            }
        }
    }

    /** Selected request with its response (if any): the response is stored with the original as AI context. */
    private record Msg(HttpRequest req, HttpResponse resp) {
        static Msg of(HttpRequestResponse rr) {
            HttpResponse resp;
            try { resp = rr.hasResponse() ? rr.response() : null; } catch (Throwable t) { resp = null; }
            return new Msg(rr.request(), resp);
        }
    }

    private void onHotKey(HotKeyEvent e) {
        List<Msg> msgs = new ArrayList<>();
        for (HttpRequestResponse rr : e.selectedRequestResponses()) if (rr.request() != null) msgs.add(Msg.of(rr));
        if (msgs.isEmpty()) e.messageEditorRequestResponse().ifPresent(m -> msgs.add(Msg.of(m.requestResponse())));
        SwingUtilities.invokeLater(() -> msgs.forEach(m -> send(m.req(), m.resp())));
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        List<Msg> msgs = new ArrayList<>();
        for (HttpRequestResponse rr : event.selectedRequestResponses()) if (rr.request() != null) msgs.add(Msg.of(rr));
        Optional<MessageEditorHttpRequestResponse> ed = event.messageEditorRequestResponse();
        if (msgs.isEmpty()) ed.ifPresent(m -> { if (m.requestResponse().request() != null) msgs.add(Msg.of(m.requestResponse())); });
        if (!msgs.isEmpty()) {
            JMenuItem send = new JMenuItem(msgs.size() == 1 ? "Send to Repeater (tracked)" : "Send " + msgs.size() + " to Repeater (tracked)");
            send.addActionListener(a -> msgs.forEach(m -> send(m.req(), m.resp())));
            items.add(send);
            JMenuItem open = new JMenuItem("API Logging: open this API's log");
            HttpRequest first = msgs.get(0).req();
            open.addActionListener(a -> {
                try {
                    var s = first.httpService();
                    openApi.accept(ApiKeys.hostKey(s.host(), s.port(), s.secure()) + keys.pathKey(first.pathWithoutQuery()));
                } catch (Throwable t) { Log.rateLimited(t); }
            });
            items.add(open);
            JMenuItem copy = new JMenuItem("API Logging: copy this API's log for AI");
            copy.addActionListener(a -> {
                try {
                    var s = first.httpService();
                    copyForAi.accept(ApiKeys.hostKey(s.host(), s.port(), s.secure()) + keys.pathKey(first.pathWithoutQuery()));
                } catch (Throwable t) { Log.rateLimited(t); }
            });
            items.add(copy);
        }
        ed.ifPresent(m -> {
            if (m.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST && m.selectionOffsets().isPresent()) {
                JMenuItem label = new JMenuItem("API Logging: label the selected value…");
                label.addActionListener(a -> labelSelection(m));
                items.add(label);
            }
        });
        return items;
    }

    /** Sends to Repeater with a preset name and marks this request as the original request. Runs on the EDT. */
    public void send(HttpRequest req) { send(req, null); }

    /** Same, with the response of that request (may be null), stored with the original. */
    public void send(HttpRequest req, HttpResponse resp) {
        try {
            var s = req.httpService();
            String hostKey = ApiKeys.hostKey(s.host(), s.port(), s.secure());
            String name = TabNames.tabName(req.method(), req.pathWithoutQuery(), usedNames);
            usedNames.add(name);
            api.repeater().sendToRepeater(req, name);
            Tracker t = tracker.get();
            if (t != null) t.submitInternal(new Events.OriginalEvent(Rows.SRC_TRACKED, System.currentTimeMillis(),
                    BurpRequest.snapshot(req), BurpResponse.of(resp)));
            Log.info("Send to Repeater (tracked): " + name + " (" + hostKey + ")");
        } catch (Throwable e) {
            Log.error("Send to Repeater (tracked)", e);
        }
    }

    private void labelSelection(MessageEditorHttpRequestResponse m) {
        try {
            Range r = m.selectionOffsets().orElse(null);
            if (r == null) return;
            byte[] all = m.requestResponse().request().toByteArray().getBytes();
            int a = Math.max(0, r.startIndexInclusive()), b = Math.min(all.length, r.endIndexExclusive());
            if (b <= a) return;
            String value = new String(all, a, b - a, StandardCharsets.UTF_8).trim();
            // the Authorization header is matched verbatim as "Bearer xxx": label both with and without the prefix
            if (value.toLowerCase(java.util.Locale.ROOT).startsWith("bearer ")) {
                promptAndSave(value, value.substring(value.indexOf(' ') + 1).trim());
            } else {
                promptAndSave(value, "Bearer " + value);
            }
        } catch (Throwable t) {
            Log.error("labeling", t);
        }
    }

    private void promptAndSave(String value, String alt) {
        Tracker t = tracker.get();
        DbWriter w = writer.get();
        if (t == null || w == null) return;
        String shown = value.length() > 40 ? value.substring(0, 18) + "…" + value.substring(value.length() - 18) : value;
        String label = JOptionPane.showInputDialog(api.userInterface().swingUtils().suiteFrame(),
                "Label for value " + shown + "\n(e.g. userA, userB, admin):", "API Logging", JOptionPane.PLAIN_MESSAGE);
        if (label == null || label.isBlank()) return;
        String clean = label.trim().replaceAll("[<>\\s]+", "_");
        for (String v : alt == null ? List.of(value) : List.of(value, alt)) {
            String h = t.redactor().fullHmac(v);
            labels.put(h, clean);
            w.submit(DbWriter.putLabel(h, clean));
        }
    }

    public void unregister() {
        for (Registration r : hotkeys) { try { r.deregister(); } catch (Throwable ignored) { } }
        hotkeys.clear();
    }
}
