package proxyscanner.burpext;

import java.util.List;
import java.util.Map;

/**
 * Live smoke test against a real running Scanner API (spec §66 Phase 5 item
 * 30 verification) -- deliberately NOT a JUnit test: it needs an external
 * process (uvicorn) already running on the port below, so it's a manual
 * run, same convention as this whole project's Python side
 * (test_*_manual.py). Run with:
 *   mvn test-compile
 *   java -cp target/test-classes:target/classes:$(find ~/.m2 -name 'montoya-api-*.jar') \
 *        proxyscanner.burpext.ManualClientSmokeTest
 */
public final class ManualClientSmokeTest {
    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        SecurityToolkitSettings settings = new SecurityToolkitSettings();
        settings.setBaseUrl("http://127.0.0.1:8011");
        SecurityToolkitClient client = new SecurityToolkitClient(settings);

        check("healthCheck", client.healthCheck());

        Map<String, Object> scan = client.createScan("https://example.com", "example.com");
        System.out.println("created scan: " + scan);
        check("scan has id", scan.get("id") != null && ((String) scan.get("id")).startsWith("scan-"));
        check("scan status is pending", "pending".equals(scan.get("status")));
        String scanId = (String) scan.get("id");

        Map<String, Object> fetchedScan = client.getScan(scanId);
        check("getScan round-trips id", scanId.equals(fetchedScan.get("id")));

        Map<String, Object> task = client.runModule(scanId, "ssl_tls", "{\"port\":443}");
        System.out.println("created task: " + task);
        String taskId = (String) task.get("id");
        check("task has id", taskId != null && taskId.startsWith("task-"));

        System.out.println("polling task (real ssl_tls scan, ~45-90s)...");
        Map<String, Object> finalTask = null;
        for (int i = 0; i < 60; i++) {
            Thread.sleep(2000);
            Map<String, Object> t = client.getTask(taskId);
            String status = (String) t.get("status");
            if (!"pending".equals(status) && !"running".equals(status)) {
                finalTask = t;
                break;
            }
        }
        check("task reached a terminal state", finalTask != null);
        System.out.println("final task: " + finalTask);
        check("task completed", finalTask != null && "completed".equals(finalTask.get("status")));

        Map<String, Object> results = client.getScanResults(scanId);
        @SuppressWarnings("unchecked")
        List<Object> findings = (List<Object>) results.get("findings");
        System.out.println("findings: " + findings);
        check("real findings present (example.com is known to offer TLSv1.0/1.1)", !findings.isEmpty());

        List<Object> issues = client.listIssues(scanId);
        check("listIssues matches results.findings count", issues.size() == findings.size());

        // -- error path: unknown module returns 200 with a Task that fails
        // asynchronously (not an HTTP error) -- the API itself never throws
        // for this, so the eventual task status is what's checked.
        try {
            Map<String, Object> badTaskCreate = client.runModule(scanId, "totally_unknown_module_xyz", "{}");
            String badTaskId = (String) badTaskCreate.get("id");
            Thread.sleep(1000);
            Map<String, Object> badTask = client.getTask(badTaskId);
            check("unknown module task fails", "failed".equals(badTask.get("status")));
        } catch (SecurityToolkitClient.ApiException e) {
            check("unexpected ApiException for unknown module: " + e.getMessage(), false);
        }

        // -- 404 path: unknown scan id must throw ApiException(404) --
        try {
            client.getScan("scan-does-not-exist");
            check("expected ApiException for unknown scan id", false);
        } catch (SecurityToolkitClient.ApiException e) {
            check("404 for unknown scan id", e.statusCode == 404);
        }

        System.out.println(failures == 0 ? "\nALL MANUAL CLIENT SMOKE TESTS OK" : "\n" + failures + " CHECK(S) FAILED");
        if (failures > 0) {
            System.exit(1);
        }
    }

    private static void check(String label, boolean condition) {
        if (condition) {
            System.out.println("OK   " + label);
        } else {
            System.out.println("FAIL " + label);
            failures++;
        }
    }
}
