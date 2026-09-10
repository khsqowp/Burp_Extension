package proxyscanner.burpext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Java client for the Security Toolkit Scanner API (spec §50-§51). Pure
 * java.net stdlib, no extra dependency (same rationale as HistorySender) --
 * this is the *only* thing in the extension allowed to talk to the Docker
 * Scanner Core, matching spec §50's "Burp Extension이 Scanner Core에 직접
 * 종속되지 않도록 API 계층을 둔다" (i.e. via HTTP, never Orchestrator
 * internals or a shared process).
 */
final class SecurityToolkitClient {
    static final class ApiException extends IOException {
        final int statusCode;

        ApiException(int statusCode, String body) {
            super("Scanner API returned HTTP " + statusCode + ": " + body);
            this.statusCode = statusCode;
        }
    }

    private final SecurityToolkitSettings settings;

    SecurityToolkitClient(SecurityToolkitSettings settings) {
        this.settings = settings;
    }

    Map<String, Object> createScan(String target, String scopeHost) throws IOException {
        String body = "{\"target\":" + Json.quote(target) + ",\"scope_host\":" + Json.quote(scopeHost) + "}";
        return SimpleJson.parseObject(request("POST", "/scans", body));
    }

    Map<String, Object> runModule(String scanId, String module, String argsJson) throws IOException {
        String body = "{\"module\":" + Json.quote(module) + ",\"args\":" + (argsJson == null ? "{}" : argsJson) + "}";
        return SimpleJson.parseObject(request("POST", "/scans/" + urlPathSegment(scanId) + "/tasks", body));
    }

    Map<String, Object> getTask(String taskId) throws IOException {
        return SimpleJson.parseObject(request("GET", "/tasks/" + urlPathSegment(taskId), null));
    }

    Map<String, Object> getTaskRaw(String taskId) throws IOException {
        return SimpleJson.parseObject(request("GET", "/tasks/" + urlPathSegment(taskId) + "/raw", null));
    }

    Map<String, Object> getScan(String scanId) throws IOException {
        return SimpleJson.parseObject(request("GET", "/scans/" + urlPathSegment(scanId), null));
    }

    Map<String, Object> getScanResults(String scanId) throws IOException {
        return SimpleJson.parseObject(request("GET", "/scans/" + urlPathSegment(scanId) + "/results", null));
    }

    List<Object> listIssues(String scanId) throws IOException {
        return SimpleJson.parseArray(request("GET", "/issues?scan_id=" + urlPathSegment(scanId), null));
    }

    /** spec §60 Process Termination -- cancels still-PENDING Tasks and kills
     * the subprocess behind any currently-RUNNING Task on this scan. */
    Map<String, Object> stopScan(String scanId) throws IOException {
        return SimpleJson.parseObject(request("POST", "/scans/" + urlPathSegment(scanId) + "/stop", "{}"));
    }

    boolean healthCheck() {
        try {
            request("GET", "/health", null);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private String request(String method, String path, String jsonBody) throws IOException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(settings.getBaseUrl() + path);
            conn = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            conn.setRequestMethod(method);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(120_000); // a running scan module can legitimately take a while
            if (jsonBody != null) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
                conn.setFixedLengthStreamingMode(bytes.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bytes);
                }
            }
            int code = conn.getResponseCode();
            InputStream stream = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream();
            String responseBody = readAll(stream);
            if (code < 200 || code >= 300) {
                throw new ApiException(code, responseBody);
            }
            return responseBody;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static String readAll(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = stream.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    /** Scan/task ids are our own uuid-hex-suffixed strings (spec §24), never
     * user-controlled arbitrary text, but this still guards against a stray
     * '/' or '?' turning into a path-traversal-shaped request. */
    private static String urlPathSegment(String raw) {
        try {
            return java.net.URLEncoder.encode(raw, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new AssertionError("UTF-8 must always be supported", e);
        }
    }
}
