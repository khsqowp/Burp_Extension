package proxyscanner.burpext;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimpleJsonTest {

    @Test
    void parsesFlatObject() {
        Map<String, Object> obj = SimpleJson.parseObject(
                "{\"id\":\"scan-abc123\",\"status\":\"pending\",\"port\":443,\"active\":true,\"error\":null}"
        );
        assertEquals("scan-abc123", obj.get("id"));
        assertEquals("pending", obj.get("status"));
        assertEquals(443.0, obj.get("port"));
        assertEquals(Boolean.TRUE, obj.get("active"));
        assertNull(obj.get("error"));
    }

    @Test
    void parsesArrayOfObjects_matchingScannerApiFindingShape() {
        // exactly the shape /issues?scan_id=... returns (spec §61)
        List<Object> arr = SimpleJson.parseArray(
                "[{\"finding\":\"TLSv1.0 Supported\",\"severity\":\"high\",\"port\":443},"
                + "{\"finding\":\"HSTS Header\",\"severity\":\"medium\",\"port\":443}]"
        );
        assertEquals(2, arr.size());
        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) arr.get(0);
        assertEquals("TLSv1.0 Supported", first.get("finding"));
        assertEquals("high", first.get("severity"));
    }

    @Test
    void parsesNestedObjectInsideObject_matchingScanResultsShape() {
        // exactly the shape GET /scans/{id}/results returns
        Map<String, Object> obj = SimpleJson.parseObject(
                "{\"scan\":{\"id\":\"scan-1\",\"status\":\"completed\"},\"tasks\":[],\"findings\":[]}"
        );
        @SuppressWarnings("unchecked")
        Map<String, Object> scan = (Map<String, Object>) obj.get("scan");
        assertEquals("scan-1", scan.get("id"));
        assertTrue(((List<?>) obj.get("tasks")).isEmpty());
        assertTrue(((List<?>) obj.get("findings")).isEmpty());
    }

    @Test
    void handlesEscapedStringsAndUnicode() {
        Map<String, Object> obj = SimpleJson.parseObject(
                "{\"finding\":\"line1\\nline2\\t\\\"quoted\\\"\",\"korean\":\"\\uD55C\\uAE00\"}"
        );
        assertEquals("line1\nline2\t\"quoted\"", obj.get("finding"));
        assertEquals("한글", obj.get("korean"));
    }

    @Test
    void handlesNegativeAndDecimalNumbers() {
        Map<String, Object> obj = SimpleJson.parseObject("{\"a\":-5,\"b\":3.14,\"c\":0}");
        assertEquals(-5.0, obj.get("a"));
        assertEquals(3.14, obj.get("b"));
        assertEquals(0.0, obj.get("c"));
    }

    @Test
    void rejectsMalformedJson() {
        assertThrows(RuntimeException.class, () -> SimpleJson.parseObject("{not valid json"));
    }

    @Test
    void parseObjectRejectsTopLevelArray() {
        assertThrows(IllegalArgumentException.class, () -> SimpleJson.parseObject("[1,2,3]"));
    }
}
