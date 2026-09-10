package proxyscanner.burpext;

/**
 * Mutable connection settings for the Security Toolkit Scanner API client
 * (spec §50: Burp Extension talks to Scanner API only, never Orchestrator
 * internals directly). Default matches api/main.py's own direct-run default
 * (127.0.0.1:8000) and the Docker Compose port mapping, both loopback-only.
 */
public final class SecurityToolkitSettings {
    private volatile String baseUrl = "http://127.0.0.1:8000";

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return;
        }
        String trimmed = baseUrl.trim();
        String normalized = trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
        try {
            java.net.URI uri = new java.net.URI(normalized);
            String host = uri.getHost();
            boolean loopback = "127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host)
                    || "::1".equals(host) || "[::1]".equals(host);
            if (!"http".equalsIgnoreCase(uri.getScheme()) || !loopback || uri.getPort() < 1
                    || uri.getUserInfo() != null || uri.getPath() != null && !uri.getPath().isEmpty()) {
                throw new IllegalArgumentException("Scanner API 주소는 로컬 http://127.0.0.1:<port>만 허용됩니다.");
            }
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException("Scanner API 주소 형식이 올바르지 않습니다.", e);
        }
        this.baseUrl = normalized;
    }
}
