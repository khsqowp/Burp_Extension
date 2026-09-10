package proxyscanner.burpext;

/**
 * One HTTP exchange captured from Burp Proxy History, ready to send to
 * Proxy Scanner's local receiver. Mirrors the fields proxy_scanner's own
 * FlowRecord already tracks (models.py) so the receiver can slot these in
 * next to its own mitmproxy-sourced records with no format translation
 * beyond the dedup key.
 */
final class CapturedExchange {
    final String method;
    final String url;
    final String host;
    final int port;
    final String reqHeaders;
    final String reqBody;
    final Integer status; // null when there was no response (spec 3.5: "응답 없는 요청과 네트워크 오류도 상태를 구분해 기록")
    final String respHeaders;
    final String respBody;
    final String mime;
    final int contentLength;
    final String error; // non-null only when status is null
    final double timestamp; // epoch seconds
    final String dedupKey; // spec 3.5: "Burp 메시지 식별자 또는 요청 시각·해시 기반 중복 키"
    final String sourceLabel; // "PROXY" (Burp Browser guarantee unavailable in this Burp version -- spec 3.5's
    // acknowledged fallback) or "PROXY_BROWSER" if a future Montoya API version lets us tell them apart

    CapturedExchange(
            String method, String url, String host, int port,
            String reqHeaders, String reqBody,
            Integer status, String respHeaders, String respBody, String mime, int contentLength, String error,
            double timestamp, String dedupKey, String sourceLabel
    ) {
        this.method = method;
        this.url = url;
        this.host = host;
        this.port = port;
        this.reqHeaders = reqHeaders;
        this.reqBody = reqBody;
        this.status = status;
        this.respHeaders = respHeaders;
        this.respBody = respBody;
        this.mime = mime;
        this.contentLength = contentLength;
        this.error = error;
        this.timestamp = timestamp;
        this.dedupKey = dedupKey;
        this.sourceLabel = sourceLabel;
    }

    String toJson() {
        StringBuilder sb = new StringBuilder(256 + reqBody.length() + respBody.length());
        sb.append('{');
        sb.append("\"method\":").append(Json.quote(method)).append(',');
        sb.append("\"url\":").append(Json.quote(url)).append(',');
        sb.append("\"host\":").append(Json.quote(host)).append(',');
        sb.append("\"port\":").append(port).append(',');
        sb.append("\"req_headers\":").append(Json.quote(reqHeaders)).append(',');
        sb.append("\"req_body\":").append(Json.quote(reqBody)).append(',');
        sb.append("\"status\":").append(status == null ? "null" : status).append(',');
        sb.append("\"resp_headers\":").append(Json.quote(respHeaders)).append(',');
        sb.append("\"resp_body\":").append(Json.quote(respBody)).append(',');
        sb.append("\"mime\":").append(Json.quote(mime)).append(',');
        sb.append("\"content_length\":").append(contentLength).append(',');
        sb.append("\"error\":").append(error == null ? "null" : Json.quote(error)).append(',');
        sb.append("\"timestamp\":").append(timestamp).append(',');
        sb.append("\"dedup_key\":").append(Json.quote(dedupKey)).append(',');
        sb.append("\"source_label\":").append(Json.quote(sourceLabel));
        sb.append('}');
        return sb.toString();
    }
}
