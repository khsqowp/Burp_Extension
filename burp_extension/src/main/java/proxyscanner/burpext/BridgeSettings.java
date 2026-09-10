package proxyscanner.burpext;

import java.security.SecureRandom;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Mutable connection settings shared between the Swing settings tab and the
 * HTTP sender -- local port + session token (spec 3.2: "임의의 다른
 * 프로세스가 History를 주입하지 못하도록 실행 세션 토큰을 검증") + whether
 * forwarding is currently active (spec 3.3: user must explicitly start the
 * connection, nothing is sent before that).
 */
public final class BridgeSettings {
    public interface Listener {
        void onSettingsChanged();
    }

    private volatile int port = 8899;
    private volatile String token = generateToken();
    private volatile boolean connected = false;
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    public static String generateToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
        fireChanged();
    }

    public String getToken() {
        return token;
    }

    /**
     * Sets the token to a value the user typed in (pasted from Proxy
     * Scanner's own side) -- Proxy Scanner is the side that generates the
     * canonical token (spec review finding P0: both sides used to generate
     * their own independent random token with no way to reconcile them,
     * since this field used to be read-only). Ignores a blank value rather
     * than clearing a working token by accident.
     */
    public void setToken(String token) {
        if (token == null || token.isBlank()) {
            return;
        }
        this.token = token.trim();
        fireChanged();
    }

    public void regenerateToken() {
        this.token = generateToken();
        fireChanged();
    }

    public boolean isConnected() {
        return connected;
    }

    public void setConnected(boolean connected) {
        this.connected = connected;
        fireChanged();
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    private void fireChanged() {
        for (Listener l : listeners) {
            l.onSettingsChanged();
        }
    }
}
