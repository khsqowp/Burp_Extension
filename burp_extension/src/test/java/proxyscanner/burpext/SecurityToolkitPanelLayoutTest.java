package proxyscanner.burpext;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityToolkitPanelLayoutTest {
    @Test
    void exposesProcessedAndRawAreasAndAllSafeModules() throws Exception {
        System.setProperty("java.awt.headless", "true");
        SecurityToolkitPanel panel = new SecurityToolkitPanel(new SecurityToolkitSettings(), null);
        try {
            Field rawField = SecurityToolkitPanel.class.getDeclaredField("rawLog");
            rawField.setAccessible(true);
            assertNotNull(rawField.get(panel));

            JSplitPane split = findSplitPane(panel);
            assertNotNull(split);
            assertEquals(JSplitPane.VERTICAL_SPLIT, split.getOrientation());

            Field checksField = SecurityToolkitPanel.class.getDeclaredField("moduleChecks");
            checksField.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<String, JCheckBox> checks = (Map<String, JCheckBox>) checksField.get(panel);
            assertTrue(checks.keySet().containsAll(java.util.Set.of(
                    "error_page_disclosure", "http_methods", "directory_listing",
                    "server_header", "security_headers", "subdomain_discovery",
                    "virtual_host_isolation")));
        } finally {
            panel.shutdown();
        }
    }

    private static JSplitPane findSplitPane(Container root) {
        for (Component child : root.getComponents()) {
            if (child instanceof JSplitPane split) return split;
            if (child instanceof Container nested) {
                JSplitPane found = findSplitPane(nested);
                if (found != null) return found;
            }
        }
        return null;
    }
}
