package proxyscanner.burpext;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;

import javax.swing.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Entry point (spec: Burp Browser 연동 §3). Observes completed Burp Proxy
 * History exchanges via Montoya's HttpHandler and forwards the ones that
 * came from the PROXY tool to Proxy Scanner's local receiver -- never
 * intercepts or modifies live traffic (both handler methods always
 * continueWith(...) unchanged).
 *
 * Known Montoya API limitation (documented here rather than worked around
 * with a guess): handleHttpResponseReceived only fires once a response
 * actually arrives -- there is no equivalent of proxy_scanner's own
 * mitmproxy addon.py error() hook, so a request that times out or gets a
 * connection refused is invisible to this extension and never forwarded.
 * Proxy Scanner's own independent proxy mode (mitmproxy-based) still
 * captures those as "응답 없음" rows; the Burp-sourced path just can't.
 */
public class BurpScannerExtension implements BurpExtension {
    private MontoyaApi api;
    private BridgeSettings settings;
    private HistorySender sender;
    private SettingsPanel panel;
    private SecurityToolkitSettings toolkitSettings;
    private SecurityToolkitPanel toolkitPanel;
    private DecoderPanel decoderPanel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Proxy Scanner History Bridge");

        settings = new BridgeSettings();
        sender = new HistorySender(settings, (success, message) -> {
            if (panel != null) {
                panel.setStatus(success, success ? "연결됨 -- History 수신 중" : "연동 오류 -- " + message);
            }
        });

        toolkitSettings = new SecurityToolkitSettings();
        BurpIssueReporter issueReporter = new BurpIssueReporter(api);

        // Swing components must be built on the EDT -- initialize() runs on
        // whatever thread Burp calls it from (not guaranteed to be the EDT),
        // and constructing/laying out JTextFields off the EDT is why the
        // 로컬 포트/세션 토큰 fields could render as blank, near-zero-size
        // boxes: the initial layout pass that sizes them to their preferred
        // width never ran correctly. invokeAndWait blocks until the panel is
        // fully built and laid out on the EDT before registerSuiteTab hands
        // it to Burp.
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                panel = new SettingsPanel(settings);
                toolkitPanel = new SecurityToolkitPanel(toolkitSettings, issueReporter);
                decoderPanel = new DecoderPanel(toolkitSettings);
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            api.logging().logToError("Proxy Scanner bridge: interrupted while building settings panel", e);
            return;
        } catch (java.lang.reflect.InvocationTargetException e) {
            api.logging().logToError("Proxy Scanner bridge: failed to build settings panel", e.getCause());
            return;
        }
        api.userInterface().registerSuiteTab("Proxy Scanner", panel);
        api.userInterface().registerSuiteTab("Security Toolkit", toolkitPanel);
        api.userInterface().registerSuiteTab("Security Toolkit Decoder", decoderPanel);

        // spec §66 item 32: Proxy History 우클릭 -> Security Toolkit로 전송.
        // ContextMenuItemsProvider's methods are all `default` (confirmed via
        // javap against the real montoya-api jar) -- it has no single
        // abstract method, so it isn't lambda-compatible; an anonymous class
        // overriding just the one method we need is the correct shape.
        api.userInterface().registerContextMenuItemsProvider(
                new burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider() {
                    @Override
                    public List<java.awt.Component> provideMenuItems(ContextMenuEvent event) {
                        JMenuItem sendItem = new JMenuItem("Send to Security Toolkit");
                        sendItem.addActionListener(e -> onSendToSecurityToolkit(event));
                        return List.of(sendItem);
                    }
                }
        );

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                try {
                    onResponse(responseReceived);
                } catch (Exception e) {
                    api.logging().logToError("Proxy Scanner bridge failed to process one exchange", e);
                }
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        api.extension().registerUnloadingHandler(() -> {
            sender.shutdown();
            if (toolkitPanel != null) {
                toolkitPanel.shutdown();
            }
            if (decoderPanel != null) {
                decoderPanel.shutdown();
            }
        });
        api.logging().logToOutput("Proxy Scanner History Bridge loaded.");
    }

    /** spec §66 item 32 -- takes the first selected Proxy History request
     * (right-click can multi-select, but a scan target is one host) and
     * hands it to the Security Toolkit tab. */
    private void onSendToSecurityToolkit(ContextMenuEvent event) {
        List<burp.api.montoya.http.message.HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected.isEmpty() || toolkitPanel == null) {
            return;
        }
        HttpRequest request = selected.get(0).request();
        toolkitPanel.sendTarget(request.url(), request.httpService().host());
    }

    private void onResponse(HttpResponseReceived response) {
        // spec 3.5: Burp Repeater/Scanner 등 다른 도구의 요청은 기본적으로 제외 --
        // Montoya doesn't expose a finer "was this specifically the embedded
        // Burp Browser vs. some other client proxied through Burp" distinction,
        // so PROXY tool-source is the closest available filter (spec's own
        // acknowledged fallback: "출처를 완전히 구분할 수 없는 Burp 버전에서는
        // 'Proxy 도구 트래픽'으로 표시"). sourceLabel below reflects that.
        if (!response.toolSource().isFromTool(ToolType.PROXY)) {
            return;
        }

        HttpRequest request = response.initiatingRequest();
        String reqHeaders = request.headers().stream()
                .map(h -> h.name() + ": " + h.value())
                .collect(Collectors.joining("\n"));
        String respHeaders = response.headers().stream()
                .map(h -> h.name() + ": " + h.value())
                .collect(Collectors.joining("\n"));
        String mime = response.statedMimeType() != null ? response.statedMimeType().toString() : "";
        int contentLength;
        try {
            contentLength = response.body().length();
        } catch (Exception e) {
            contentLength = 0;
        }

        // Message id + method + URL -- stable per Burp session, good enough
        // for the receiver's own duplicate-suppression key (spec 3.5).
        String dedupKey = "burp:" + response.messageId() + ":" + request.method() + ":" + request.url();

        CapturedExchange exchange = new CapturedExchange(
                request.method(), request.url(),
                request.httpService().host(), request.httpService().port(),
                reqHeaders, request.bodyToString(),
                (int) response.statusCode(), respHeaders, response.bodyToString(),
                mime, contentLength, null,
                System.currentTimeMillis() / 1000.0, dedupKey, "PROXY"
        );
        sender.sendAsync(exchange);
    }
}
