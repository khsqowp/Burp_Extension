package proxyscanner.burpext;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityToolkitPanelFlowTest {
    @Test
    void rendersNonApplicableTaskAsSkippedWithoutClaimingClean() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> respondWithStatus(exchange, "skipped",
                "TLS 진단은 HTTPS 대상에만 적용됩니다. HTTP 대상이므로 건너뜁니다."));
        server.start();
        SecurityToolkitSettings settings = new SecurityToolkitSettings();
        settings.setBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
        SecurityToolkitPanel panel = new SecurityToolkitPanel(settings, null);
        try {
            JTextField target = field(panel, "targetField", JTextField.class);
            JButton run = field(panel, "runButton", JButton.class);
            JTextArea processed = field(panel, "log", JTextArea.class);
            JLabel statusLabel = field(panel, "statusLabel", JLabel.class);
            @SuppressWarnings("unchecked")
            Map<String, JCheckBox> checks = (Map<String, JCheckBox>) fieldValue(panel, "moduleChecks");
            SwingUtilities.invokeAndWait(() -> {
                target.setText("http://192.168.0.12:3000");
                checks.values().forEach(box -> box.setSelected(false));
                checks.get("ssl_tls").setSelected(true);
                run.doClick();
            });
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
            while ((!processed.getText().contains("전체 요약") || !run.isEnabled())
                    && System.nanoTime() < deadline) Thread.sleep(50);
            SwingUtilities.invokeAndWait(() -> {});
            assertTrue(processed.getText().contains("비적용"));
            assertTrue(processed.getText().contains("전부 비적용"));
            assertTrue(!processed.getText().contains("전체 양호 -- 발견된 이슈 없음"));
            assertTrue(statusLabel.getText().contains("적용 가능한 모듈 없음"));
        } finally {
            panel.shutdown();
            server.stop(0);
        }
    }

    @Test
    void rendersProcessedFindingAndTaskRawThroughTheRealClientFlow() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::respond);
        server.start();
        SecurityToolkitSettings settings = new SecurityToolkitSettings();
        settings.setBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
        SecurityToolkitPanel panel = new SecurityToolkitPanel(settings, null);
        try {
            JTextField target = field(panel, "targetField", JTextField.class);
            JButton run = field(panel, "runButton", JButton.class);
            JTextArea processed = field(panel, "log", JTextArea.class);
            JTextArea raw = field(panel, "rawLog", JTextArea.class);
            @SuppressWarnings("unchecked")
            Map<String, JCheckBox> checks = (Map<String, JCheckBox>) fieldValue(panel, "moduleChecks");

            SwingUtilities.invokeAndWait(() -> {
                target.setText("http://192.168.0.12:3000");
                checks.values().forEach(box -> box.setSelected(false));
                checks.get("server_header").setSelected(true);
                run.doClick();
            });

            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
            while ((!processed.getText().contains("전체 요약") || !run.isEnabled())
                    && System.nanoTime() < deadline) Thread.sleep(50);
            SwingUtilities.invokeAndWait(() -> {});

            assertTrue(run.isEnabled(), "scan did not finish");
            assertTrue(processed.getText().contains("제품 정보 노출"));
            assertTrue(processed.getText().contains("예상 피해: 공격 표면 식별"));
            assertTrue(processed.getText().contains("참고 관찰 1건"));
            assertTrue(raw.getText().contains("x-powered-by"));
            assertTrue(raw.getText().contains("task-meta"));
        } finally {
            panel.shutdown();
            server.stop(0);
        }
    }

    private void respond(HttpExchange exchange) throws java.io.IOException {
        String path = exchange.getRequestURI().getPath();
        String body;
        if ("POST".equals(exchange.getRequestMethod()) && "/scans".equals(path)) {
            body = "{\"id\":\"scan-test\"}";
        } else if ("POST".equals(exchange.getRequestMethod()) && path.endsWith("/tasks")) {
            body = "{\"id\":\"task-test\"}";
        } else if ("/tasks/task-test".equals(path)) {
            body = "{\"id\":\"task-test\",\"status\":\"completed\",\"error\":\"\"}";
        } else if ("/tasks/task-test/raw".equals(path)) {
            String result = "{\"observations\":[{\"message\":\"동일 IP 참고\"}],\"raw\":[{\"headers\":{\"x-powered-by\":\"Next.js\"}}]}";
            body = "{\"result\":" + Json.quote(result) + ",\"meta\":\"task-meta\"}";
        } else if ("/issues".equals(path)) {
            body = "[{\"task_id\":\"task-test\",\"severity\":\"info\",\"finding\":\"제품 정보 노출\",\"description\":\"공격 표면 식별\"}]";
        } else {
            body = "{}";
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private void respondWithStatus(HttpExchange exchange, String status, String error) throws java.io.IOException {
        String path = exchange.getRequestURI().getPath();
        String body;
        if ("POST".equals(exchange.getRequestMethod()) && "/scans".equals(path)) {
            body = "{\"id\":\"scan-test\"}";
        } else if ("POST".equals(exchange.getRequestMethod()) && path.endsWith("/tasks")) {
            body = "{\"id\":\"task-test\"}";
        } else if ("/tasks/task-test".equals(path)) {
            body = "{\"id\":\"task-test\",\"status\":" + Json.quote(status)
                    + ",\"error\":" + Json.quote(error) + "}";
        } else if ("/tasks/task-test/raw".equals(path)) {
            String result = "{\"status\":\"skipped\",\"observations\":[{\"type\":\"not_applicable\",\"message\":"
                    + Json.quote(error) + "}]}";
            body = "{\"result\":" + Json.quote(result) + "}";
        } else if ("/issues".equals(path)) {
            body = "[]";
        } else {
            body = "{}";
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static Object fieldValue(Object object, String name) throws Exception {
        Field field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(object);
    }

    private static <T> T field(Object object, String name, Class<T> type) throws Exception {
        return type.cast(fieldValue(object, name));
    }
}
