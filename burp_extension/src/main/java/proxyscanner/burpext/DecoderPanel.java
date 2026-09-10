package proxyscanner.burpext;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * Burp Suite tab (spec §18) -- Decoder. Base64/URL Encoding/Hex, JWT Parsing
 * and hash-format identification run entirely inside this panel (no
 * Scanner Core round trip, per spec §18: "다음과 같은 단순 변환은 Burp
 * Extension에서 직접 수행할 수 있다"). Only the two CPU-heavy operations --
 * brute-forcing a JWT's HMAC secret and dictionary-cracking a hash -- are
 * delegated to the Scanner Core's jwt_analyzer/crypto_identifier modules via
 * the same Scanner API every other tab uses (spec §18: "CPU 사용량이 높은
 * 작업은 Scanner Core에서 처리할 수 있도록 분리한다").
 */
final class DecoderPanel extends JPanel {
    private final SecurityToolkitClient client;
    private final ExecutorService executor;

    private final JTextArea inputArea;
    private final JTextArea outputArea;
    // spec review finding (2026-09-05): these used to be one shared field --
    // set a JWT-secret wordlist, forget to clear it, then click "Crack Hash"
    // and it silently runs against the wrong dictionary. Separate fields per
    // crack target make that mistake structurally impossible.
    private final JTextField jwtWordlistField;
    private final JTextField hashWordlistField;
    private final JLabel statusLabel;

    // spec: bcrypt/md5crypt/sha256crypt/sha512crypt/argon2/phpass/Django
    // PBKDF2/apr1/SSHA prefix rules, mirrored from crypto_identifier.py's
    // _PREFIX_RULES so a quick local guess needs no Scanner Core round trip.
    private static final Object[][] HASH_PREFIX_RULES = {
            {Pattern.compile("^\\$2[aby]\\$"), "bcrypt"},
            {Pattern.compile("^\\$1\\$"), "md5crypt"},
            {Pattern.compile("^\\$5\\$"), "sha256crypt"},
            {Pattern.compile("^\\$6\\$"), "sha512crypt"},
            {Pattern.compile("^\\$argon2(i|d|id)\\$"), "argon2"},
            {Pattern.compile("^\\$P\\$"), "phpass (WordPress/phpBB)"},
            {Pattern.compile("^\\$H\\$"), "phpass (phpBB3 old)"},
            {Pattern.compile("^pbkdf2_sha256\\$"), "Django PBKDF2-SHA256"},
            {Pattern.compile("^\\$apr1\\$"), "Apache apr1-md5"},
            {Pattern.compile("^\\{SSHA\\}"), "Salted SHA1 (LDAP SSHA)"},
    };
    private static final int[] HASH_HEX_LENGTHS = {32, 40, 56, 64, 96, 128};
    private static final String[] HASH_HEX_NAMES = {
            "MD5 (or NTLM -- same length/charset)", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
    };

    DecoderPanel(SecurityToolkitSettings settings) {
        this.client = new SecurityToolkitClient(settings);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "security-toolkit-decoder");
            t.setDaemon(true);
            return t;
        });

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JLabel title = new JLabel("Decoder");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));

        inputArea = new JTextArea(4, 60);
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        JPanel north = new JPanel(new BorderLayout(4, 4));
        north.add(title, BorderLayout.NORTH);
        north.add(new JScrollPane(inputArea), BorderLayout.CENTER);
        add(north, BorderLayout.NORTH);

        JPanel buttons = new JPanel();
        buttons.setLayout(new BoxLayout(buttons, BoxLayout.Y_AXIS));

        JPanel localRow1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        localRow1.add(new JLabel("로컬 변환:"));
        addButton(localRow1, "Base64 Encode", this::onBase64Encode);
        addButton(localRow1, "Base64 Decode", this::onBase64Decode);
        addButton(localRow1, "URL Encode", this::onUrlEncode);
        addButton(localRow1, "URL Decode", this::onUrlDecode);
        addButton(localRow1, "Hex Encode", this::onHexEncode);
        addButton(localRow1, "Hex Decode", this::onHexDecode);
        buttons.add(localRow1);

        JPanel localRow2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        localRow2.add(new JLabel("로컬 분석:"));
        addButton(localRow2, "Parse JWT", this::onParseJwt);
        addButton(localRow2, "Identify Hash", this::onIdentifyHash);
        buttons.add(localRow2);

        JPanel scannerCoreRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        scannerCoreRow.add(new JLabel("Scanner Core (CPU-heavy):"));
        addButton(scannerCoreRow, "Crack JWT Secret", this::onCrackJwtSecret);
        scannerCoreRow.add(new JLabel("wordlist(선택)"));
        jwtWordlistField = new JTextField(16);
        scannerCoreRow.add(jwtWordlistField);
        addButton(scannerCoreRow, "Crack Hash", this::onCrackHash);
        scannerCoreRow.add(new JLabel("wordlist(선택)"));
        hashWordlistField = new JTextField(16);
        scannerCoreRow.add(hashWordlistField);
        buttons.add(scannerCoreRow);

        add(buttons, BorderLayout.CENTER);

        statusLabel = new JLabel("● 대기 중");
        outputArea = new JTextArea(16, 60);
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel south = new JPanel(new BorderLayout(4, 4));
        south.add(statusLabel, BorderLayout.NORTH);
        south.add(new JScrollPane(outputArea), BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);
    }

    private void addButton(JPanel panel, String label, Runnable action) {
        JButton b = new JButton(label);
        b.addActionListener(e -> action.run());
        panel.add(b);
    }

    // -- local transforms (spec §18: Base64/URL/Hex, no Scanner Core call) ---
    private void onBase64Encode() {
        withInput(input -> setOutput(Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8))));
    }

    private void onBase64Decode() {
        withInput(input -> {
            String cleaned = input.trim();
            try {
                byte[] decoded = cleaned.indexOf('-') >= 0 || cleaned.indexOf('_') >= 0
                        ? Base64.getUrlDecoder().decode(pad(cleaned))
                        : Base64.getDecoder().decode(pad(cleaned));
                setOutput(new String(decoded, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                setOutput("Base64 디코딩 실패: " + e.getMessage());
            }
        });
    }

    private static String pad(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "====".substring(rem);
    }

    private void onUrlEncode() {
        withInput(input -> {
            try {
                setOutput(URLEncoder.encode(input, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw new AssertionError("UTF-8 must always be supported", e);
            }
        });
    }

    private void onUrlDecode() {
        withInput(input -> {
            try {
                setOutput(URLDecoder.decode(input, "UTF-8"));
            } catch (IllegalArgumentException | UnsupportedEncodingException e) {
                setOutput("URL 디코딩 실패: " + e.getMessage());
            }
        });
    }

    private void onHexEncode() {
        withInput(input -> {
            byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            setOutput(sb.toString());
        });
    }

    private void onHexDecode() {
        withInput(input -> {
            String cleaned = input.trim().replaceAll("\\s+", "");
            if (cleaned.length() % 2 != 0 || !cleaned.matches("[0-9a-fA-F]+")) {
                setOutput("Hex 디코딩 실패: 유효한 hex 문자열이 아님");
                return;
            }
            byte[] bytes = new byte[cleaned.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
            }
            setOutput(new String(bytes, StandardCharsets.UTF_8));
        });
    }

    // -- local JWT parsing + structural checks (spec §18: "JWT Parsing"은 --
    // 단순 변환으로 분류되어 로컬에서 처리; secret brute force만 Scanner
    // Core로 위임한다, 아래 onCrackJwtSecret 참고) -----------------------------
    private void onParseJwt() {
        withInput(input -> {
            String token = input.trim();
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) {
                setOutput("JWT 파싱 실패: header.payload.signature 3파트 구조가 아님 (" + parts.length + "개 segment)");
                return;
            }
            String headerJson, payloadJson;
            try {
                headerJson = new String(Base64.getUrlDecoder().decode(pad(parts[0])), StandardCharsets.UTF_8);
                payloadJson = new String(Base64.getUrlDecoder().decode(pad(parts[1])), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                setOutput("JWT 파싱 실패: base64url 디코딩 오류 -- " + e.getMessage());
                return;
            }

            Map<String, Object> header;
            Map<String, Object> payload;
            try {
                header = SimpleJson.parseObject(headerJson);
                payload = SimpleJson.parseObject(payloadJson);
            } catch (RuntimeException e) {
                setOutput("JWT 파싱 실패: JSON 파싱 오류 -- " + e.getMessage() + "\n\n[Header raw]\n" + headerJson + "\n\n[Payload raw]\n" + payloadJson);
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("[Header]\n").append(headerJson).append("\n\n[Payload]\n").append(payloadJson).append("\n\n");
            sb.append("[Findings]\n");
            for (String line : analyzeJwtStructure(header, payload)) {
                sb.append("  ").append(line).append('\n');
            }
            setOutput(sb.toString());
        });
    }

    /** Mirrors jwt_analyzer.py's analyze_structure() (spec §38) closely
     * enough for immediate local feedback -- alg=none, missing exp/iat,
     * kid/jku/x5u injection surface. The heavier pieces (secret brute
     * force, algorithm-confusion PoC generation) stay on the Scanner Core
     * side and aren't duplicated here. */
    private static List<String> analyzeJwtStructure(Map<String, Object> header, Map<String, Object> payload) {
        java.util.List<String> out = new java.util.ArrayList<>();
        Object algObj = header.get("alg");
        String alg = algObj == null ? "" : String.valueOf(algObj);

        if (alg.equalsIgnoreCase("none")) {
            out.add("VULNERABLE  alg=none: 서버가 이를 받아들이면 서명 검증 없이 payload 위조 가능.");
        }
        if (!payload.containsKey("exp")) {
            out.add("WARNING     exp(만료시간) claim 없음 -- 토큰이 영구적으로 유효할 수 있음.");
        }
        if (!payload.containsKey("iat")) {
            out.add("INFO        iat(발급시간) claim 없음.");
        }
        if (header.containsKey("kid")) {
            out.add("WARNING     kid 헤더 존재 (" + header.get("kid") + ") -- 서버가 이 값으로 키 파일/DB를 직접 조회한다면 경로 조작/SQL 인젝션 벡터.");
        }
        if (header.containsKey("jku")) {
            out.add("WARNING     jku 헤더 존재 (" + header.get("jku") + ") -- 서버가 이 URL에서 공개키를 fetch한다면 SSRF/키 위조 벡터.");
        }
        if (header.containsKey("x5u")) {
            out.add("WARNING     x5u 헤더 존재 -- 서버가 이 URL의 인증서를 신뢰한다면 위조 인증서 주입 벡터.");
        }
        String algUpper = alg.toUpperCase(java.util.Locale.ROOT);
        if (algUpper.equals("HS256") || algUpper.equals("HS384") || algUpper.equals("HS512")) {
            out.add("INFO        " + alg + ": 대칭키(HMAC) 서명 -- 시크릿이 약하면 아래 'Crack JWT Secret'으로 무차별 대입 가능.");
        } else if (algUpper.matches("RS(256|384|512)|ES(256|384|512)|PS(256|384|512)")) {
            out.add("INFO        " + alg + ": 비대칭키 서명 -- 서버 검증 로직이 공개키를 HMAC 시크릿으로 오인하면 algorithm confusion 공격 가능.");
        } else if (!algUpper.isEmpty()) {
            out.add("INFO        알 수 없거나 드문 alg 값: " + alg);
        }
        if (out.isEmpty()) {
            out.add("(특이사항 없음)");
        }
        return out;
    }

    // -- local hash-format identification (spec §18: "Hash 형태 식별") --------
    private void onIdentifyHash() {
        withInput(input -> {
            String value = input.trim();
            java.util.List<String> guesses = new java.util.ArrayList<>();
            for (Object[] rule : HASH_PREFIX_RULES) {
                Pattern p = (Pattern) rule[0];
                if (p.matcher(value).find()) {
                    guesses.add((String) rule[1]);
                }
            }
            if (guesses.isEmpty()) {
                String body = value.startsWith("*") ? value.substring(1) : value;
                if (body.matches("[0-9a-fA-F]+")) {
                    for (int i = 0; i < HASH_HEX_LENGTHS.length; i++) {
                        if (body.length() == HASH_HEX_LENGTHS[i]) {
                            guesses.add(HASH_HEX_NAMES[i]);
                        }
                    }
                }
            }
            if (guesses.isEmpty()) {
                setOutput("알려진 해시/crypt 포맷과 일치하지 않음 (원문이거나 인코딩된 값일 수 있음 -- Base64/Hex Decode도 시도해보세요)");
            } else {
                setOutput("가능한 해시 포맷:\n" + String.join("\n", guesses.stream().map(g -> "  - " + g).toArray(String[]::new)));
            }
        });
    }

    // -- Scanner Core delegation (spec §18: CPU-heavy work only) --------------
    private void onCrackJwtSecret() {
        String token = inputArea.getText().trim();
        if (token.split("\\.", -1).length != 3) {
            JOptionPane.showMessageDialog(this, "유효한 JWT(header.payload.signature)를 입력하세요.", "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String wordlist = jwtWordlistField.getText().trim();
        String argsJson = "{\"crack_secret\":true" + (wordlist.isEmpty() ? "" : ",\"wordlist\":" + Json.quote(wordlist)) + "}";
        runScannerCoreModule(token, "jwt_analyzer", argsJson);
    }

    private void onCrackHash() {
        String value = inputArea.getText().trim();
        if (value.isEmpty()) {
            JOptionPane.showMessageDialog(this, "크랙할 해시 값을 입력하세요.", "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String wordlist = hashWordlistField.getText().trim();
        String argsJson = "{\"crack\":true" + (wordlist.isEmpty() ? "" : ",\"wordlist\":" + Json.quote(wordlist)) + "}";
        runScannerCoreModule(value, "crypto_identifier", argsJson);
    }

    private void runScannerCoreModule(String value, String module, String argsJson) {
        setStatus(true, module + " 실행 중...");
        executor.submit(() -> {
            try {
                Map<String, Object> scan = client.createScan(value, "decoder");
                String scanId = (String) scan.get("id");
                Map<String, Object> task = client.runModule(scanId, module, argsJson);
                String taskId = (String) task.get("id");
                String status;
                do {
                    Thread.sleep(2000);
                    task = client.getTask(taskId);
                    status = (String) task.get("status");
                } while ("pending".equals(status) || "running".equals(status));

                if (!"completed".equals(status)) {
                    Object error = task.get("error");
                    appendOutput("\n[" + module + "] " + status + (error != null ? " -- " + error : ""));
                    setStatus(false, module + " 실패: " + status);
                    return;
                }

                List<Object> issues = client.listIssues(scanId);
                StringBuilder sb = new StringBuilder("\n[" + module + " 결과] (" + issues.size() + "건)\n");
                for (Object o : issues) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> finding = (Map<String, Object>) o;
                    sb.append("  [").append(finding.get("severity")).append("] ").append(finding.get("finding")).append('\n');
                }
                appendOutput(sb.toString());
                setStatus(true, module + " 완료");
            } catch (IOException | InterruptedException e) {
                appendOutput("\n[" + module + "] 오류: " + e.getMessage());
                setStatus(false, module + " 오류 -- " + e.getMessage());
            }
        });
    }

    // -- helpers ----------------------------------------------------------------
    private void withInput(java.util.function.Consumer<String> action) {
        String input = inputArea.getText();
        if (input == null || input.isEmpty()) {
            JOptionPane.showMessageDialog(this, "입력값을 먼저 입력하세요.", "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        action.accept(input);
    }

    private void setOutput(String text) {
        outputArea.setText(text);
    }

    private void appendOutput(String text) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(text);
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }

    private void setStatus(boolean ok, String text) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("● " + text);
            statusLabel.setForeground(ok ? new Color(0x1b6b3a) : new Color(0xb3261e));
        });
    }

    void shutdown() {
        executor.shutdown();
    }
}
