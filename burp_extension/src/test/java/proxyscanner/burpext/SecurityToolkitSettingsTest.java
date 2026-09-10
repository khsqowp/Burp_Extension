package proxyscanner.burpext;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityToolkitSettingsTest {
    @Test
    void acceptsOnlyLoopbackHttpApiAddresses() {
        SecurityToolkitSettings settings = new SecurityToolkitSettings();
        settings.setBaseUrl("http://localhost:9000/");
        assertEquals("http://localhost:9000", settings.getBaseUrl());
        settings.setBaseUrl("http://[::1]:8000");
        assertEquals("http://[::1]:8000", settings.getBaseUrl());

        assertThrows(IllegalArgumentException.class,
                () -> settings.setBaseUrl("https://scanner.example:8000"));
        assertThrows(IllegalArgumentException.class,
                () -> settings.setBaseUrl("http://192.168.0.12:8000"));
        assertThrows(IllegalArgumentException.class,
                () -> settings.setBaseUrl("http://127.0.0.1:8000/path"));
    }
}
