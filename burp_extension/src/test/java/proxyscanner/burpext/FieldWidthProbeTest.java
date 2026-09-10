package proxyscanner.burpext;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression test for a real bug (2026-09-08): the panel's own preferred
 * width is ~1500px, driven by the 13-checkbox module row. Whenever Burp
 * hands this panel a narrower Suite tab, GridBagLayout's shrink pass ate
 * almost the entire deficit out of the zero-minimum-size JTextFields
 * (checkboxes/labels barely shrink since they're already near their own
 * minimum) -- confirmed collapsing to 5px wide, unable to show even one
 * character. setMinimumSize on each field (same pattern SettingsPanel /
 * Proxy Scanner tab already used) keeps them usable at realistic widths. */
class FieldWidthProbeTest {
    private static final int MIN_USABLE_WIDTH = 100;

    @Test
    void textFieldsStayUsableEvenInANarrowContainer() throws Exception {
        System.setProperty("java.awt.headless", "true");
        SecurityToolkitPanel panel = new SecurityToolkitPanel(new SecurityToolkitSettings(), null);
        try {
            JTextField baseUrlField = field(panel, "baseUrlField");
            JTextField targetField = field(panel, "targetField");

            // narrower than the panel's own preferred width (~1500px, driven
            // by the module checkbox row) -- exactly the scenario a Burp
            // Suite tab that hasn't been widened produces.
            int prefH = panel.getPreferredSize().height;
            panel.setSize(900, prefH);
            panel.doLayout();

            assertTrue(baseUrlField.getWidth() >= MIN_USABLE_WIDTH,
                    "Scanner API field collapsed to " + baseUrlField.getWidth() + "px in a 900px container");
            assertTrue(targetField.getWidth() >= MIN_USABLE_WIDTH,
                    "대상 URL field collapsed to " + targetField.getWidth() + "px in a 900px container");
        } finally {
            panel.shutdown();
        }
    }

    private static JTextField field(SecurityToolkitPanel panel, String name) throws Exception {
        Field f = SecurityToolkitPanel.class.getDeclaredField(name);
        f.setAccessible(true);
        return (JTextField) f.get(panel);
    }
}
