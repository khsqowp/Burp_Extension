package proxyscanner.burpext;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Sends captured exchanges to Proxy Scanner's local receiver -- always
 * 127.0.0.1, never any other host (spec 3.2: "외부 인터페이스에 바인딩하지
 * 않는다" on the receiver side; this is the send side's matching half: only
 * ever talk to loopback). Runs on a small background thread pool so a slow
 * or unreachable receiver never blocks Burp's own proxy pipeline.
 */
final class HistorySender {
    interface StatusListener {
        void onSendResult(boolean success, String message);
    }

    private final BridgeSettings settings;
    private final StatusListener statusListener;
    private final ExecutorService executor;

    HistorySender(BridgeSettings settings, StatusListener statusListener) {
        this.settings = settings;
        this.statusListener = statusListener;
        ThreadFactory tf = r -> {
            Thread t = new Thread(r, "proxyscanner-history-sender");
            t.setDaemon(true);
            return t;
        };
        this.executor = new java.util.concurrent.ThreadPoolExecutor(
                1, 2, 30, TimeUnit.SECONDS, new LinkedBlockingQueue<>(500), tf
        );
    }

    void sendAsync(CapturedExchange exchange) {
        if (!settings.isConnected()) {
            return;
        }
        try {
            executor.submit(() -> send(exchange));
        } catch (java.util.concurrent.RejectedExecutionException e) {
            // queue full -- receiver is unreachable/stuck; drop this one rather than pile up unbounded memory
            if (statusListener != null) {
                statusListener.onSendResult(false, "전송 대기열 초과 -- Proxy Scanner가 응답하지 않음");
            }
        }
    }

    private void send(CapturedExchange exchange) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("http://127.0.0.1:" + settings.getPort() + "/ingest");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(3000);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("X-Session-Token", settings.getToken());
            byte[] body = exchange.toJson().getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(body.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
            int code = conn.getResponseCode();
            if (statusListener != null) {
                statusListener.onSendResult(code == 200, "HTTP " + code);
            }
        } catch (Exception e) {
            if (statusListener != null) {
                statusListener.onSendResult(false, e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    void shutdown() {
        executor.shutdown();
    }
}
