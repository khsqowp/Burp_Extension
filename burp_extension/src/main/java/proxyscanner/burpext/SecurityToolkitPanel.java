package proxyscanner.burpext;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Burp Suite tab (spec §66 items 29/31-33) -- lets the user pick a target
 * and modules, runs them through the Security Toolkit Scanner API (never
 * talks to Orchestrator internals directly, spec §50), and shows progress +
 * results in a log. {@link #sendTarget} is the entry point the Proxy
 * History context menu (spec item 32) calls to pre-fill and kick off a scan
 * without the user needing to type the URL by hand.
 */
final class SecurityToolkitPanel extends JPanel {
    private final SecurityToolkitSettings settings;
    private final SecurityToolkitClient client;
    private final BurpIssueReporter issueReporter;
    private final ExecutorService executor;

    private final JTextField baseUrlField;
    private final JTextField targetField;
    private final Map<String, JCheckBox> moduleChecks = new LinkedHashMap<>();
    private final JButton runButton;
    private final JButton stopButton;
    private final JProgressBar progressBar;
    private final JLabel statusLabel;
    private final JTextArea log;
    private final JTextArea rawLog;

    // spec §60 Process Termination -- which scan (if any) is currently
    // in-flight, so the Stop button knows what to cancel; cancelRequested is
    // checked between modules so a stop doesn't just cancel the current one
    // but also skips the rest of the queued run.
    private volatile String currentScanId;
    private volatile SecurityToolkitClient currentRunClient;
    private volatile boolean cancelRequested;
    private volatile boolean scanActive;

    // spec §35-§37 Phase 6: 파라미터가 있어야 실행 가능한 Active Scanner
    // (params/check_url 등) -- Recon 모듈처럼 체크박스만으로 끝나지 않고
    // 옆에 값 입력 필드가 딸려 있다.
    private final JTextField xssReflectedParamsField;
    private final JTextField xssStoredCheckUrlField;
    private final JTextField xssStoredParamsField;
    private final JTextField pathTraversalParamField;
    private final JTextField jsAnalyzerUrlField;

    // spec §12 SAFE 모듈만 기본 체크 -- CAUTION 모듈(ffuf/gobuster/infra_vuln/
    // default_content/xss_reflected/xss_stored/path_traversal)은 사용자가
    // 명시적으로 켜야 실행되게 한다. js_analyzer는 여기 없음 -- params 없이는
    // 항상 실패하는 xss_reflected 등과 같은 이유로 별도 입력 필드가 딸린
    // 줄에 있다 (spec review finding 2026-09-06: js_analyzer가 이 목록에
    // 있었지만 js_url을 넣을 방법이 없어서 체크만 하면 항상 실패했다).
    private static final String[] RECON_MODULES = {
            "ssl_tls", "crawler", "default_content", "infra_vuln", "ffuf", "gobuster",
            "error_page_disclosure", "http_methods", "directory_listing", "server_header",
            "security_headers", "subdomain_discovery", "virtual_host_isolation",
    };
    private static final java.util.Set<String> DEFAULT_ON = java.util.Set.of("ssl_tls", "crawler");

    // spec review finding (2026-09-06): the progress bar only ever moved in
    // whole-module increments (completed*100/total), so a single-module scan
    // sat at 0% for the entire run and jumped straight to 100% at the end --
    // indistinguishable from a hang. None of the wrapped tools (ffuf/
    // gobuster/nmap/...) report real intra-run progress through the Scanner
    // API, so there is no ground truth for a genuine percentage while a
    // module is executing. These are typical wall-clock durations (seconds)
    // used only to animate the bar smoothly toward a 95% cap while a module
    // is in flight -- an approximation for perceived progress, not a
    // measurement, and it always snaps to the module's real share of 100%
    // the instant that module actually finishes.
    private static final Map<String, Integer> TYPICAL_SECONDS = Map.ofEntries(
            Map.entry("ssl_tls", 15),
            Map.entry("crawler", 20),
            Map.entry("default_content", 15),
            Map.entry("infra_vuln", 30),
            Map.entry("ffuf", 60),
            Map.entry("gobuster", 60),
            Map.entry("js_analyzer", 8),
            Map.entry("xss_reflected", 15),
            Map.entry("xss_stored", 20),
            Map.entry("path_traversal", 15)
            , Map.entry("error_page_disclosure", 5)
            , Map.entry("http_methods", 5)
            , Map.entry("directory_listing", 5)
            , Map.entry("server_header", 5)
            , Map.entry("security_headers", 5)
            , Map.entry("subdomain_discovery", 15)
            , Map.entry("virtual_host_isolation", 20)
    );
    private static final int DEFAULT_TYPICAL_SECONDS = 20;

    SecurityToolkitPanel(SecurityToolkitSettings settings, BurpIssueReporter issueReporter) {
        this.settings = settings;
        this.client = new SecurityToolkitClient(settings);
        this.issueReporter = issueReporter;
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "security-toolkit-panel");
            t.setDaemon(true);
            return t;
        });

        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        JLabel title = new JLabel("Security Toolkit 연동");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 4;
        add(title, c);

        c.gridwidth = 1;
        c.gridy = 1;
        c.gridx = 0;
        add(new JLabel("Scanner API"), c);
        baseUrlField = new JTextField(settings.getBaseUrl(), 24);
        // spec review finding (2026-09-08): this row's column width is shared
        // with every other row in the grid, including the 13-checkbox module
        // row below (~1500px preferred). Whenever the panel is embedded in a
        // Burp Suite tab narrower than that, GridBagLayout's shrink pass eats
        // almost all of the deficit out of the zero-minimum-size text fields
        // (checkboxes/labels barely shrink since they're already near their
        // own minimum) -- confirmed via FieldWidthProbeTest: fields collapsed
        // to 5px wide at container widths below ~1507px. SettingsPanel (Proxy
        // Scanner tab) already guards its fields with setMinimumSize for the
        // same reason; this panel never got the same treatment.
        baseUrlField.setMinimumSize(new Dimension(180, baseUrlField.getPreferredSize().height));
        c.gridx = 1;
        c.gridwidth = 2;
        add(baseUrlField, c);
        c.gridwidth = 1;
        JButton testButton = new JButton("연결 테스트");
        testButton.addActionListener(e -> onTestConnection());
        c.gridx = 3;
        add(testButton, c);

        c.gridy = 2;
        c.gridx = 0;
        add(new JLabel("대상 URL"), c);
        targetField = new JTextField(28);
        targetField.setMinimumSize(new Dimension(220, targetField.getPreferredSize().height));
        c.gridx = 1;
        c.gridwidth = 2;
        add(targetField, c);
        c.gridwidth = 1;

        JPanel checkPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        for (String module : RECON_MODULES) {
            JCheckBox cb = new JCheckBox(module, DEFAULT_ON.contains(module));
            moduleChecks.put(module, cb);
            checkPanel.add(cb);
        }
        c.gridy = 3;
        c.gridx = 0;
        c.gridwidth = 4;
        c.fill = GridBagConstraints.HORIZONTAL;
        add(checkPanel, c);
        c.fill = GridBagConstraints.NONE;
        c.gridwidth = 1;

        // js_analyzer: SAFE 등급이지만 xss_reflected 등과 같은 이유로 대상
        // JS 파일 URL이 있어야 실행 가능하다 -- 체크박스만 있던 예전 자리에
        // 있으면 항상 "js_analyzer requires js_url"로 실패했다.
        JCheckBox jsAnalyzerCheck = new JCheckBox("js_analyzer");
        moduleChecks.put("js_analyzer", jsAnalyzerCheck);
        c.gridy = 4;
        c.gridx = 0;
        add(jsAnalyzerCheck, c);
        c.gridx = 1;
        add(new JLabel("js_url"), c);
        jsAnalyzerUrlField = new JTextField(20);
        jsAnalyzerUrlField.setMinimumSize(new Dimension(160, jsAnalyzerUrlField.getPreferredSize().height));
        c.gridx = 2;
        c.gridwidth = 2;
        add(jsAnalyzerUrlField, c);
        c.gridwidth = 1;

        JLabel activeScannerTitle = new JLabel("Active Scanner (Phase 6)");
        activeScannerTitle.setFont(activeScannerTitle.getFont().deriveFont(Font.BOLD, 12f));
        c.gridy = 5;
        c.gridx = 0;
        c.gridwidth = 4;
        add(activeScannerTitle, c);
        c.gridwidth = 1;

        // xss_reflected: 대상 쿼리 파라미터명 목록 하나만 있으면 됨
        JCheckBox xssReflectedCheck = new JCheckBox("xss_reflected");
        moduleChecks.put("xss_reflected", xssReflectedCheck);
        c.gridy = 6;
        c.gridx = 0;
        add(xssReflectedCheck, c);
        c.gridx = 1;
        add(new JLabel("params"), c);
        xssReflectedParamsField = new JTextField(20);
        xssReflectedParamsField.setMinimumSize(new Dimension(160, xssReflectedParamsField.getPreferredSize().height));
        c.gridx = 2;
        c.gridwidth = 2;
        add(xssReflectedParamsField, c);
        c.gridwidth = 1;

        // xss_stored: 입력 페이지(target)와, 저장된 값을 확인할 별도 check_url이 필요
        JCheckBox xssStoredCheck = new JCheckBox("xss_stored");
        moduleChecks.put("xss_stored", xssStoredCheck);
        c.gridy = 7;
        c.gridx = 0;
        add(xssStoredCheck, c);
        c.gridx = 1;
        add(new JLabel("check_url"), c);
        xssStoredCheckUrlField = new JTextField(20);
        xssStoredCheckUrlField.setMinimumSize(new Dimension(160, xssStoredCheckUrlField.getPreferredSize().height));
        c.gridx = 2;
        c.gridwidth = 2;
        add(xssStoredCheckUrlField, c);
        c.gridwidth = 1;
        c.gridy = 8;
        c.gridx = 1;
        add(new JLabel("params"), c);
        xssStoredParamsField = new JTextField(20);
        xssStoredParamsField.setMinimumSize(new Dimension(160, xssStoredParamsField.getPreferredSize().height));
        c.gridx = 2;
        c.gridwidth = 2;
        add(xssStoredParamsField, c);
        c.gridwidth = 1;

        // path_traversal: 트래버설 페이로드를 주입할 쿼리 파라미터명
        JCheckBox pathTraversalCheck = new JCheckBox("path_traversal");
        moduleChecks.put("path_traversal", pathTraversalCheck);
        c.gridy = 9;
        c.gridx = 0;
        add(pathTraversalCheck, c);
        c.gridx = 1;
        add(new JLabel("param"), c);
        pathTraversalParamField = new JTextField(20);
        pathTraversalParamField.setMinimumSize(new Dimension(160, pathTraversalParamField.getPreferredSize().height));
        c.gridx = 2;
        c.gridwidth = 2;
        add(pathTraversalParamField, c);
        c.gridwidth = 1;

        runButton = new JButton("실행");
        runButton.addActionListener(e -> onRun());
        c.gridy = 10;
        c.gridx = 0;
        add(runButton, c);

        stopButton = new JButton("중지");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> onStop());
        c.gridx = 1;
        add(stopButton, c);

        statusLabel = new JLabel("● 대기 중");
        c.gridx = 2;
        c.gridwidth = 2;
        add(statusLabel, c);
        c.gridwidth = 1;

        // 고정된 한 줄짜리 진행률 표시 -- 로그처럼 계속 새 줄이 추가되는 게
        // 아니라 이 컴포넌트 하나가 0에서 100으로 그 자리에서 채워진다.
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("0%");
        c.gridy = 11;
        c.gridx = 0;
        c.gridwidth = 4;
        c.fill = GridBagConstraints.HORIZONTAL;
        add(progressBar, c);
        c.fill = GridBagConstraints.NONE;
        c.gridwidth = 1;

        log = new JTextArea(16, 60);
        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane processedScroll = new JScrollPane(log);
        processedScroll.setBorder(BorderFactory.createTitledBorder("가공된 결과"));
        rawLog = new JTextArea(10, 60);
        rawLog.setEditable(false);
        rawLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane rawScroll = new JScrollPane(rawLog);
        rawScroll.setBorder(BorderFactory.createTitledBorder("RAW"));
        JSplitPane resultSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, processedScroll, rawScroll);
        resultSplit.setResizeWeight(0.58);
        resultSplit.setContinuousLayout(true);
        resultSplit.setOneTouchExpandable(true);
        c.gridy = 12;
        c.gridx = 0;
        c.gridwidth = 4;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 1;
        add(resultSplit, c);
    }

    /** Called from the Proxy History context menu action (spec item 32) --
     * pre-fills the target and immediately runs the default (SAFE-only)
     * module set, since a right-click action implies "check this now", not
     * "let me open a tab and configure options first". */
    void sendTarget(String url, String scopeHost) {
        SwingUtilities.invokeLater(() -> {
            targetField.setText(url);
            appendLog("컨텍스트 메뉴에서 전송됨: " + url);
        });
        runScan(url, scopeHost, DEFAULT_ON);
    }

    private void onTestConnection() {
        settings.setBaseUrl(baseUrlField.getText());
        setStatus(false, "연결 확인 중...");
        executor.submit(() -> {
            boolean ok = client.healthCheck();
            setStatus(ok, ok ? "연결됨 -- " + settings.getBaseUrl() : "연결 실패 -- " + settings.getBaseUrl());
        });
    }

    private void onRun() {
        settings.setBaseUrl(baseUrlField.getText());
        String target = targetField.getText();
        if (target == null || target.isBlank()) {
            JOptionPane.showMessageDialog(this, "대상 URL을 입력하세요.", "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        target = target.trim();
        // spec review finding (2026-09-06): a typo like "http:192.168.0,12:3000"
        // (missing "//" after the scheme, comma instead of a dot) used to sail
        // through the old startsWith("http://") check below, get a second
        // "http://" prepended on top, and then fail deep inside 4-6 different
        // modules with unrelated, module-specific tracebacks -- the user had no
        // single place to see "your URL is wrong". Catch both root causes here,
        // before anything runs.
        String lowerTarget = target.toLowerCase(java.util.Locale.ROOT);
        int colonIdx = target.indexOf(':');
        String beforeColon = colonIdx > 0 ? lowerTarget.substring(0, colonIdx) : "";
        if ((beforeColon.equals("http") || beforeColon.equals("https"))
                && !lowerTarget.startsWith(beforeColon + "://")) {
            JOptionPane.showMessageDialog(this,
                    "대상 URL 형식이 올바르지 않습니다: \"" + target + "\"\n"
                            + "\"" + beforeColon + ":\" 뒤에 \"//\"가 빠졌습니다. 예: "
                            + beforeColon + "://192.168.0.12:3000",
                    "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (target.indexOf(',') >= 0) {
            JOptionPane.showMessageDialog(this,
                    "대상 URL에 쉼표(,)가 포함되어 있습니다: \"" + target + "\"\n"
                            + "IP 주소의 구분자는 마침표(.)입니다. 예: 192.168.0.12",
                    "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        // spec review finding (2026-09-06): crawler/default_content/ffuf/gobuster
        // all require a real http(s) URL and crash (or, since the tool-side fix,
        // cleanly fail) on a bare host/IP like "192.168.0.12" -- normalizing here
        // means the user never has to know that distinction.
        if (!lowerTarget.startsWith("http://") && !lowerTarget.startsWith("https://")) {
            target = "http://" + target;
            final String normalized = target;
            SwingUtilities.invokeLater(() -> targetField.setText(normalized));
            appendLog("대상 URL에 스킴이 없어 http://를 붙였습니다: " + normalized);
        }
        java.util.Set<String> selected = new java.util.LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> e : moduleChecks.entrySet()) {
            if (e.getValue().isSelected()) {
                selected.add(e.getKey());
            }
        }
        if (selected.isEmpty()) {
            JOptionPane.showMessageDialog(this, "실행할 모듈을 하나 이상 선택하세요.", "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        try {
            for (String module : selected) {
                buildArgsJson(module); // spec §35-§37: 필수 필드 누락은 스캔 시작 전에 걸러낸다
            }
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String scopeHost;
        try {
            scopeHost = new java.net.URI(target.trim()).getHost();
        } catch (Exception e) {
            scopeHost = target.trim();
        }
        runScan(target.trim(), scopeHost != null ? scopeHost : target.trim(), selected);
    }

    private void runScan(String target, String scopeHost, java.util.Set<String> modules) {
        synchronized (this) {
            if (scanActive) {
                appendLog("이미 진단이 실행 중입니다. 현재 진단을 중지하거나 완료될 때까지 기다리세요.");
                return;
            }
            scanActive = true;
            cancelRequested = false;
        }
        SwingUtilities.invokeLater(() -> {
            runButton.setEnabled(false);
            stopButton.setEnabled(true);
        });
        SecurityToolkitSettings runSettings = new SecurityToolkitSettings();
        runSettings.setBaseUrl(settings.getBaseUrl());
        SecurityToolkitClient runClient = new SecurityToolkitClient(runSettings);
        currentRunClient = runClient;
        setProgress(0);
        setStatus(true, "실행 중...");
        SwingUtilities.invokeLater(() -> {
            log.setText("");
            rawLog.setText("");
        });
        executor.submit(() -> {
            int total = modules.size();
            int completed = 0;
            java.util.List<ModuleResult> results = new java.util.ArrayList<>();
            String scanId = null;
            try {
                Map<String, Object> scan = runClient.createScan(target, scopeHost);
                scanId = (String) scan.get("id");
                currentScanId = scanId;
                if (cancelRequested) {
                    runClient.stopScan(scanId);
                }
                appendLog("Scan 생성: " + scanId + " (" + target + ")");
                for (String module : modules) {
                    resetModuleStatus(module);
                }
                for (String module : modules) {
                    if (cancelRequested) {
                        appendLog("중지됨 -- 남은 모듈은 실행하지 않음");
                        break;
                    }
                    setModuleStatus(module, "⏳ 실행중");
                    Timer moduleProgressTimer = startModuleProgressTimer(module, completed, total);
                    try {
                        results.add(runModuleAndWait(runClient, scanId, module));
                    } finally {
                        moduleProgressTimer.stop();
                    }
                    completed++;
                    setProgress(completed * 100 / total);
                }
                ScanOutcome outcome = printFinalSummary(scanId, results, total, completed);
                // spec review finding (2026-09-06): this used to call
                // setStatus(true, ...) unconditionally, so a scan where every
                // module failed still lit up green with "완료" -- directly
                // contradicting the "완료 0 / 실패 1 / 취소 2" line printed
                // just above it in the same log. The status pill now reflects
                // the same ScanOutcome the summary text is built from.
                if (cancelRequested) {
                    setStatus(StatusTone.NEUTRAL, "중지됨 -- Scan " + scanId);
                } else if (outcome.failedCount() > 0 || outcome.cancelledCount() > 0) {
                    setStatus(StatusTone.ERROR, "일부 모듈 실패/취소 -- Scan " + scanId);
                } else if (outcome.okCount() == 0 && outcome.skippedCount() > 0) {
                    setStatus(StatusTone.NEUTRAL, "완료 -- 적용 가능한 모듈 없음 (Scan " + scanId + ")");
                } else if (outcome.totalFindings() > 0) {
                    setStatus(StatusTone.WARN, "완료 -- 취약점 발견 (Scan " + scanId + ")");
                } else {
                    setStatus(StatusTone.OK, "완료 -- 전체 양호 (Scan " + scanId + ")");
                }
            } catch (Exception e) {
                appendLog("오류: " + e.getMessage());
                if (scanId != null) {
                    try {
                        runClient.stopScan(scanId);
                        appendLog("오류 후 서버 Scan 중지 확인: " + scanId);
                    } catch (IOException stopError) {
                        appendLog("오류 후 서버 Scan 중지 실패: " + stopError.getMessage());
                    }
                }
                setStatus(false, "오류 -- " + e.getMessage());
            } finally {
                currentScanId = null;
                currentRunClient = null;
                scanActive = false;
                SwingUtilities.invokeLater(() -> {
                    runButton.setEnabled(true);
                    stopButton.setEnabled(false);
                });
            }
        });
    }

    /** spec §60 -- Stop 버튼. 서버가 PENDING Task는 즉시 취소하고 RUNNING
     * Task는 실제 subprocess를 kill한다 (api/main.py POST /scans/{id}/stop).
     * cancelRequested는 runScan()의 모듈 루프가 다음 모듈을 시작하지 않도록
     * 막는다 -- 이미 시작된 모듈은 서버 쪽 취소가 반영되는 대로 자연히
     * runModuleAndWait()의 폴링 루프에서 "cancelled" 상태로 빠져나온다. */
    private void onStop() {
        String scanId = currentScanId;
        if (scanId == null) {
            cancelRequested = true;
            appendLog("중지 예약됨 -- Scan ID가 발급되는 즉시 중지합니다.");
            return;
        }
        cancelRequested = true;
        SwingUtilities.invokeLater(() -> stopButton.setEnabled(false));
        appendLog("중지 요청 전송...");
        SecurityToolkitClient runClient = currentRunClient;
        executor.submit(() -> {
            try {
                if (runClient == null) {
                    throw new IOException("실행 중 Scanner API 연결 정보를 찾을 수 없습니다.");
                }
                runClient.stopScan(scanId);
            } catch (IOException e) {
                appendLog("중지 요청 실패: " + e.getMessage());
            }
        });
    }

    /** spec §35-§37: xss_reflected/xss_stored/path_traversal은 recon 모듈과
     *달리 요청별 파라미터가 있어야 build_command()가 통과한다 (wrapper 쪽
     * ValueError guard와 동일한 필수값) -- 여기서 그 JSON을 조립한다. Recon
     * 모듈은 지금까지와 동일하게 빈 객체로 충분하다.
     *
     * 모든 분기에 "confirm":true를 포함한다 -- spec review finding
     * (2026-09-06): CAUTION 모듈이 SafetyPolicyEngine.evaluate()에서 확인
     * 없이는 이제 거부되는데(§10), 여기서 확인란을 체크하고 "실행"을 누르는
     * 행위 자체가 이미 그 명시적 확인이다 (SAFE 모듈은 confirm을 무시하므로
     * 항상 보내도 무해함). */
    private String buildArgsJson(String module) {
        switch (module) {
            case "js_analyzer": {
                String jsUrl = jsAnalyzerUrlField.getText().trim();
                if (jsUrl.isEmpty()) {
                    throw new IllegalArgumentException("js_analyzer: js_url(분석할 JS 파일 URL)을 입력하세요.");
                }
                return "{\"confirm\":true,\"js_url\":" + Json.quote(jsUrl) + "}";
            }
            case "xss_reflected": {
                String params = xssReflectedParamsField.getText().trim();
                if (params.isEmpty()) {
                    throw new IllegalArgumentException("xss_reflected: params(쿼리 파라미터명)를 입력하세요.");
                }
                return "{\"confirm\":true,\"params\":" + Json.quote(params) + "}";
            }
            case "xss_stored": {
                String checkUrl = xssStoredCheckUrlField.getText().trim();
                String params = xssStoredParamsField.getText().trim();
                if (checkUrl.isEmpty() || params.isEmpty()) {
                    throw new IllegalArgumentException("xss_stored: check_url과 params를 모두 입력하세요.");
                }
                return "{\"confirm\":true,\"check_url\":" + Json.quote(checkUrl) + ",\"params\":" + Json.quote(params) + "}";
            }
            case "path_traversal": {
                String param = pathTraversalParamField.getText().trim();
                if (param.isEmpty()) {
                    throw new IllegalArgumentException("path_traversal: param(쿼리 파라미터명)을 입력하세요.");
                }
                return "{\"confirm\":true,\"param\":" + Json.quote(param) + "}";
            }
            default:
                return "{\"confirm\":true}";
        }
    }

    /** 모듈 하나의 실행 결과 -- status는 "completed"/"skipped"/"failed"/"cancelled".
     * spec review finding (2026-09-06): 이 status를 최종 요약에서 빼놓고
     * findings 개수만 봤더니 "전부 실패했지만 발견된 이슈는 0건"인 경우까지
     * "전체 양호"로 잘못 보고했다 -- ModuleResult로 같이 들고 다녀서
     * printFinalSummary()가 실패/취소를 findings 유무와 별개로 판단하게 한다. */
    private record ModuleResult(String module, String status, java.util.List<Object> findings) {}

    /** printFinalSummary()가 계산한 것을 runScan()도 그대로 재사용해서 상단
     * 상태 표시줄 색상을 정하게 하는 값 -- 요약 텍스트와 상태 색이 서로 다른
     * 얘기를 하는 일(예: 로그엔 "실패 1"이라 써놓고 상단은 초록 "완료")이
     * 없도록 한 곳에서만 계산한다 (spec review finding 2026-09-06). */
    private record ScanOutcome(long okCount, long skippedCount, long failedCount, long cancelledCount, int totalFindings) {}

    /** spec review finding (2026-09-06): 상단 상태줄이 지금까지 boolean
     * (녹색/빨강) 두 가지뿐이라 "일부 모듈 실패"와 "취약점 발견"과 "중지됨"이
     * 전부 같은 초록/빨강으로 뭉뚱그려졌다 -- 4가지를 구분한다. */
    private enum StatusTone { OK, WARN, ERROR, NEUTRAL }

    /** Task가 끝날 때까지 기다린 다음, 이 모듈의 Task에 해당하는 Finding만
     * 골라 콘솔에 핵심만 요약해 찍고(§ 요구사항: 취약 있으면 그것만, 전부
     * 양호하면 "전체 양호") 그 결과를 반환한다 -- 원본 전체 결과는 지금까지와
     * 동일하게 Scanner Core가 raw JSON으로 이미 저장하므로 여기서 따로 손댈
     * 필요가 없다. */
    private ModuleResult runModuleAndWait(SecurityToolkitClient runClient, String scanId, String module) throws IOException, InterruptedException {
        Map<String, Object> task = runClient.runModule(scanId, module, buildArgsJson(module));
        String taskId = (String) task.get("id");
        String status;
        long deadlineNanos = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(10);
        do {
            if (System.nanoTime() > deadlineNanos) {
                throw new IOException("Task 상태 확인 제한시간(10분)을 초과했습니다: " + taskId);
            }
            Thread.sleep(1000);
            task = runClient.getTask(taskId);
            Object statusObject = task.get("status");
            if (!(statusObject instanceof String)) {
                throw new IOException("Task 응답에 유효한 status가 없습니다: " + taskId);
            }
            status = (String) statusObject;
        } while ("pending".equals(status) || "running".equals(status));

        if (!java.util.Set.of("completed", "skipped", "failed", "cancelled").contains(status)) {
            throw new IOException("알 수 없는 Task status: " + status);
        }

        try {
            Map<String, Object> rawArtifacts = runClient.getTaskRaw(taskId);
            appendRaw(module, rawArtifacts);
            if ("completed".equals(status) || "skipped".equals(status)) {
                appendProcessedObservations(module, rawArtifacts);
            }
        } catch (IOException | RuntimeException rawError) {
            appendRaw(module, Map.of("raw_read_error", rawError.getMessage()));
        }

        java.util.List<Object> moduleIssues = new java.util.ArrayList<>();
        for (Object o : runClient.listIssues(scanId)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> f = (Map<String, Object>) o;
            if (taskId.equals(f.get("task_id"))) {
                moduleIssues.add(o);
            }
        }

        Object errorObj = task.get("error");
        String error = errorObj instanceof String ? (String) errorObj : "";
        if ("skipped".equals(status)) {
            setModuleStatus(module, "- 비적용");
            appendLog("[" + module + "] 비적용 -- " + error);
        } else if ("failed".equals(status)) {
            setModuleStatus(module, "✗ 실패");
            appendLog("[" + module + "] 실패 -- " + error);
        } else if ("cancelled".equals(status)) {
            setModuleStatus(module, "⊘ 취소됨");
            appendLog("[" + module + "] 취소됨");
        } else if (moduleIssues.isEmpty()) {
            setModuleStatus(module, "✓ 양호");
            appendLog("[" + module + "] 완료 -- 전체 양호 (발견된 이슈 없음)");
        } else {
            setModuleStatus(module, "⚠ 이슈 " + moduleIssues.size() + "건");
            appendLog("[" + module + "] 완료 -- 이슈 " + moduleIssues.size() + "건");
            for (Object o : moduleIssues) {
                @SuppressWarnings("unchecked")
                Map<String, Object> f = (Map<String, Object>) o;
                appendLog("   · [" + String.valueOf(f.get("severity")).toUpperCase(java.util.Locale.ROOT) + "] " + f.get("finding"));
                Object description = f.get("description");
                if (description != null && !String.valueOf(description).isBlank()) {
                    appendLog("     예상 피해: " + description);
                }
            }
        }
        return new ModuleResult(module, status, moduleIssues);
    }

    /** 선택한 모듈이 전부 (혹은 중지로 인해 일부) 끝난 뒤 한 번 찍는 종합
     * 정리본 -- Burp Issue 등록도 여기서 한 번에 처리한다.
     *
     * spec review finding (2026-09-06): "전체 양호"는 findings가 0건이라는
     * 것만으로는 부족하다 -- 모듈이 실패/취소돼도 findings는 0건이므로,
     * 전부 실패한 스캔까지 "전체 양호"로 잘못 보고했었다. 이제 성공/실패/
     * 취소 개수를 findings 유무와 별도로 확인한다. */
    private ScanOutcome printFinalSummary(String scanId, java.util.List<ModuleResult> results, int totalModules, int completedModules) {
        appendLog("");
        appendLog("=== 전체 요약 (Scan " + scanId + ") ===");
        appendLog("모듈 실행: " + completedModules + "/" + totalModules);

        long okCount = results.stream().filter(r -> "completed".equals(r.status())).count();
        long skippedCount = results.stream().filter(r -> "skipped".equals(r.status())).count();
        long failedCount = results.stream().filter(r -> "failed".equals(r.status())).count();
        long cancelledCount = results.stream().filter(r -> "cancelled".equals(r.status())).count();
        if (skippedCount > 0 || failedCount > 0 || cancelledCount > 0) {
            appendLog("완료 " + okCount + " / 비적용 " + skippedCount + " / 실패 " + failedCount + " / 취소 " + cancelledCount);
            for (ModuleResult r : results) {
                if (!"completed".equals(r.status()) && !"skipped".equals(r.status())) {
                    appendLog("   · [" + r.module() + "] " + r.status());
                }
            }
        }

        java.util.List<Object> allFindings = new java.util.ArrayList<>();
        for (ModuleResult r : results) {
            allFindings.addAll(r.findings());
        }

        if (allFindings.isEmpty()) {
            if (okCount > 0 && failedCount == 0 && cancelledCount == 0 && completedModules == totalModules) {
                appendLog("전체 양호 -- 발견된 이슈 없음");
            } else {
                appendLog("발견된 이슈는 없지만 모듈이 실패·취소되었거나 전부 비적용임 -- \"전체 양호\"로 볼 수 없음, 위 상태를 확인하세요.");
            }
            return new ScanOutcome(okCount, skippedCount, failedCount, cancelledCount, 0);
        }
        java.util.Map<String, Integer> bySeverity = new java.util.LinkedHashMap<>();
        for (Object o : allFindings) {
            @SuppressWarnings("unchecked")
            Map<String, Object> f = (Map<String, Object>) o;
            String sev = String.valueOf(f.get("severity")).toUpperCase(java.util.Locale.ROOT);
            bySeverity.merge(sev, 1, Integer::sum);
        }
        appendLog("총 이슈 " + allFindings.size() + "건 " + bySeverity);
        int reported = 0;
        for (Object o : allFindings) {
            @SuppressWarnings("unchecked")
            Map<String, Object> f = (Map<String, Object>) o;
            if (issueReporter != null && issueReporter.report(f)) {
                reported++;
            }
        }
        if (reported > 0) {
            appendLog(reported + "건을 Burp Issue로 등록함 (Target 탭 확인)");
        }
        return new ScanOutcome(okCount, skippedCount, failedCount, cancelledCount, allFindings.size());
    }

    private void appendLog(String line) {
        SwingUtilities.invokeLater(() -> {
            log.append(line + "\n");
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    private void appendRaw(String module, Map<String, Object> artifacts) {
        SwingUtilities.invokeLater(() -> {
            rawLog.append("=== " + module + " ===\n");
            for (String key : java.util.List.of("result", "stderr", "meta", "raw_read_error")) {
                Object value = artifacts.get(key);
                if (value != null && !String.valueOf(value).isBlank()) {
                    rawLog.append("[" + key + "]\n" + value + "\n");
                }
            }
            rawLog.append("\n");
            rawLog.setCaretPosition(rawLog.getDocument().getLength());
        });
    }

    @SuppressWarnings("unchecked")
    private void appendProcessedObservations(String module, Map<String, Object> artifacts) {
        Object resultText = artifacts.get("result");
        if (!(resultText instanceof String) || ((String) resultText).isBlank()) {
            return;
        }
        try {
            Map<String, Object> result = SimpleJson.parseObject((String) resultText);
            Object rowsObject = result.get("observations");
            if (!(rowsObject instanceof java.util.List<?> rows) || rows.isEmpty()) {
                return;
            }
            appendLog("[" + module + "] 참고 관찰 " + rows.size() + "건");
            for (Object rowObject : rows) {
                if (!(rowObject instanceof Map<?, ?> row)) {
                    continue;
                }
                Object text = row.get("hostname");
                if (text == null) text = row.get("message");
                if (text == null) text = row.get("type");
                if (text != null) appendLog("   · " + text);
            }
        } catch (RuntimeException parseError) {
            appendLog("[" + module + "] 가공 결과 해석 실패, 하단 RAW를 확인하세요.");
        }
    }

    /** 모듈 하나의 실행 상태를 그 모듈의 체크박스 자체에 표시 -- 새 컴포넌트나
     * 레이아웃 변경 없이 "해당 줄에서" 지금 뭐가 실행중/완료/실패했는지 보이게
     * 한다. ffuf/gobuster/nmap 등은 0~100% 같은 세부 진행률을 API가 보고하지
     * 않으므로, 없는 값을 지어내는 대신 상태(실행중/양호/이슈/실패/취소)만
     * 보여준다. */
    private void setModuleStatus(String module, String suffix) {
        JCheckBox cb = moduleChecks.get(module);
        if (cb == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> cb.setText(module + "  [" + suffix + "]"));
    }

    private void resetModuleStatus(String module) {
        JCheckBox cb = moduleChecks.get(module);
        if (cb == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> cb.setText(module));
    }

    /** 모듈 하나가 실행되는 동안 진행률 바를 0%에서 (그 모듈이 차지하는
     * 구간의) 95% 쪽으로 시간 기반으로 채운다. 실제 진행률 API가 없는 상태의
     * 근사치일 뿐이므로 95%를 넘어 100%를 스스로 찍지는 않는다 -- 실제 100%
     * (그 구간의 끝)는 runScan()의 루프가 이 모듈이 정말 끝났을 때
     * completed*100/total로 찍는다.
     *
     * spec review finding (2026-09-06): 이전엔 `min(95, elapsed/typical*100)`
     * 방식이라 모듈이 예상 시간(TYPICAL_SECONDS)보다 오래 걸리면(느린
     * ffuf/gobuster 등) 정확히 95%에 도달한 채 숫자가 더 이상 안 움직여서
     * "진행률이 멈췄다"는 오해를 샀다 -- 실제로는 멈춘 게 아니라 그 모듈이
     * 예상보다 오래 걸리는 것뿐이었다. 점근선(95*t/(t+typical)) 방식으로
     * 바꿔서 시간이 아무리 지나도 100%엔 도달 못 하되, 항상 미세하게라도
     * 계속 움직이게 한다. 체크박스 텍스트에 경과 시간도 함께 갱신해서
     * "죽은 게 아니라 실행 중"이라는 신호를 준다. */
    private Timer startModuleProgressTimer(String module, int completedSoFar, int totalModules) {
        long startNanos = System.nanoTime();
        int typicalSeconds = TYPICAL_SECONDS.getOrDefault(module, DEFAULT_TYPICAL_SECONDS);
        Timer timer = new Timer(300, e -> {
            double elapsedSeconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
            double moduleProgress = 95.0 * elapsedSeconds / (elapsedSeconds + typicalSeconds);
            int overall = (int) ((completedSoFar * 100 + moduleProgress) / totalModules);
            setProgress(overall);
            setModuleStatus(module, "⏳ 실행중 " + (int) elapsedSeconds + "s");
        });
        timer.setRepeats(true);
        timer.start();
        return timer;
    }

    /** 고정된 한 자리 프로그레스바를 갱신 -- 로그처럼 줄을 추가하는 게 아니라
     * 이 컴포넌트 자체의 값/문자열만 바뀐다. */
    private void setProgress(int percent) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(percent);
            progressBar.setString(percent + "%");
        });
    }

    private void setStatus(boolean ok, String text) {
        setStatus(ok ? StatusTone.OK : StatusTone.ERROR, text);
    }

    private void setStatus(StatusTone tone, String text) {
        Color color = switch (tone) {
            case OK -> new Color(0x1b6b3a);      // 녹색 -- 전체 양호
            case WARN -> new Color(0xb36b00);    // 주황 -- 완료됐지만 취약점 발견
            case ERROR -> new Color(0xb3261e);   // 빨강 -- 일부 모듈 실패/취소 (또는 연결 오류)
            case NEUTRAL -> new Color(0x5f6368); // 회색 -- 사용자가 직접 중지
        };
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("● " + text);
            statusLabel.setForeground(color);
        });
    }

    void shutdown() {
        executor.shutdown();
    }
}
