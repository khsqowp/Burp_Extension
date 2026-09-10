package proxyscanner.burpext;

import javax.swing.*;
import java.awt.*;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Burp Suite tab (spec 3.3 최초 연결 흐름) -- shows the local port Proxy
 * Scanner needs, a token field the user pastes Proxy Scanner's own
 * (canonical) token into, and a start/stop toggle for actually forwarding
 * traffic. Nothing is sent anywhere until the user presses 연결 시작.
 *
 * Fixed a real pairing bug (design review finding, P0): this field used to
 * be setEditable(false) while ALSO independently generating its own random
 * token, same as Proxy Scanner's own field -- with both sides read-only and
 * each generating a different value, there was no way to ever actually
 * make them match. Proxy Scanner is the side that generates the canonical
 * token now; this field is the one the user pastes it into.
 */
final class SettingsPanel extends JPanel {
    private final BridgeSettings settings;
    private final JTextField portField;
    private final JTextField tokenField;
    private final JButton connectButton;
    private final JButton testButton;
    private final JLabel statusLabel;

    SettingsPanel(BridgeSettings settings) {
        this.settings = settings;
        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        JLabel title = new JLabel("Proxy Scanner 연동");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 3;
        add(title, c);

        JTextArea desc = new JTextArea(
                "Burp Browser (Proxy > Intercept > Open browser)를 통과한 요청/응답을 Proxy Scanner의 HTTP History로 "
                        + "자동 전달합니다. Burp Repeater/Scanner 등 다른 도구의 요청은 전달하지 않습니다.\n"
                        + "(Montoya API가 구분해주는 것은 'Proxy 도구를 통과했는지'까지입니다 -- Burp 내장 브라우저와 "
                        + "같은 Proxy 리스너를 쓰는 별도 외부 브라우저가 있다면 그 트래픽까지는 완전히 구분되지 않을 수 있습니다.)"
        );
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setFont(desc.getFont().deriveFont(Font.PLAIN, 12f));
        c.gridy = 1;
        c.gridwidth = 3;
        c.fill = GridBagConstraints.HORIZONTAL;
        add(desc, c);
        c.fill = GridBagConstraints.NONE;

        c.gridwidth = 1;
        c.gridy = 2;
        c.gridx = 0;
        add(new JLabel("로컬 포트"), c);
        portField = new JTextField(String.valueOf(settings.getPort()), 8);
        portField.setMinimumSize(new Dimension(70, portField.getPreferredSize().height));
        c.gridx = 1;
        add(portField, c);

        c.gridy = 3;
        c.gridx = 0;
        add(new JLabel("세션 토큰"), c);
        tokenField = new JTextField(settings.getToken(), 32);
        tokenField.setMinimumSize(new Dimension(320, tokenField.getPreferredSize().height));
        c.gridx = 1;
        c.gridwidth = 2;
        add(tokenField, c);
        c.gridwidth = 1;

        JButton applyTokenButton = new JButton("토큰 적용");
        applyTokenButton.addActionListener(e -> onApplyToken());
        c.gridy = 4;
        c.gridx = 1;
        add(applyTokenButton, c);

        testButton = new JButton("연결 테스트");
        testButton.addActionListener(e -> onTestConnection());
        c.gridx = 2;
        add(testButton, c);

        connectButton = new JButton("연결 시작");
        connectButton.addActionListener(e -> onToggleConnect());
        c.gridy = 5;
        c.gridx = 0;
        add(connectButton, c);

        statusLabel = new JLabel("● 연결 안 됨");
        c.gridx = 1;
        c.gridwidth = 2;
        add(statusLabel, c);
        c.gridwidth = 1;

        c.gridy = 6;
        c.gridx = 0;
        c.gridwidth = 3;
        add(new JLabel(
                "<html>Proxy Scanner의 'Burp 연동' 탭에서 '토큰 복사'로 토큰을 복사한 뒤 위 칸에 붙여넣고<br>"
                        + "'토큰 적용' -> '연결 테스트'로 확인 -> '연결 시작' 순서로 진행하세요.</html>"
        ), c);
    }

    private void onApplyToken() {
        String typed = tokenField.getText();
        if (typed == null || typed.isBlank()) {
            JOptionPane.showMessageDialog(this, "토큰을 입력하세요.", "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        settings.setToken(typed);
        setStatus(false, "토큰 적용됨 -- '연결 테스트'로 확인하세요");
    }

    /**
     * Synchronous authenticated GET to Proxy Scanner's own /ping endpoint --
     * gives the user an immediate, unambiguous answer to "does this token
     * actually match?" instead of silently waiting for the first real Burp
     * Browser request to reveal a mismatch (design review finding: "연결
     * 성공은 실제 인증된 ping/health 응답으로 확인해야 한다").
     */
    private void onTestConnection() {
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException ex) {
            setStatus(false, "포트가 올바르지 않음");
            return;
        }
        final int finalPort = port;
        testButton.setEnabled(false);
        Thread t = new Thread(() -> {
            boolean ok;
            String msg;
            HttpURLConnection conn = null;
            try {
                URL url = new URL("http://127.0.0.1:" + finalPort + "/ping");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(2000);
                conn.setReadTimeout(2000);
                conn.setRequestProperty("X-Session-Token", settings.getToken());
                int code = conn.getResponseCode();
                ok = code == 200;
                msg = ok ? "연결 테스트 성공 -- 토큰이 일치합니다" : "연결 테스트 실패 (HTTP " + code + ") -- 토큰을 다시 확인하세요";
            } catch (Exception e) {
                ok = false;
                msg = "연결 테스트 실패 -- " + e.getClass().getSimpleName() + ": " + e.getMessage();
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
            boolean finalOk = ok;
            String finalMsg = msg;
            SwingUtilities.invokeLater(() -> {
                setStatus(finalOk, finalMsg);
                testButton.setEnabled(true);
            });
        }, "proxyscanner-ping");
        t.setDaemon(true);
        t.start();
    }

    private void onToggleConnect() {
        try {
            int port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) {
                throw new NumberFormatException();
            }
            settings.setPort(port);
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "포트는 1~65535 사이의 숫자여야 합니다.", "입력 오류", JOptionPane.ERROR_MESSAGE);
            return;
        }
        boolean nowConnected = !settings.isConnected();
        settings.setConnected(nowConnected);
        portField.setEditable(!nowConnected);
        tokenField.setEditable(!nowConnected);
        connectButton.setText(nowConnected ? "연결 중지" : "연결 시작");
        setStatus(nowConnected, nowConnected ? "연결 대기 중 -- 127.0.0.1:" + settings.getPort() : "연결 안 됨");
    }

    void setStatus(boolean ok, String text) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("● " + text);
            statusLabel.setForeground(ok ? new Color(0x1b6b3a) : new Color(0xb3261e));
        });
    }
}
