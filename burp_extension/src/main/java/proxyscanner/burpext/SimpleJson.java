package proxyscanner.burpext;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal hand-rolled JSON parser -- Scanner API responses are always flat
 * or one-level-nested objects/arrays of strings/numbers/booleans (spec
 * §61 standardized Finding shape etc.), so a small recursive-descent parser
 * covers everything without pulling in an extra dependency (same rationale
 * as {@link Json}, which only ever needed to escape outgoing strings).
 * Parses into plain {@code Map<String,Object>} / {@code List<Object>} /
 * {@code String} / {@code Double} / {@code Boolean} / {@code null} --
 * callers cast with the shape they already know the endpoint returns.
 */
final class SimpleJson {
    private final String src;
    private int pos;

    private SimpleJson(String src) {
        this.src = src;
        this.pos = 0;
    }

    static Object parse(String json) {
        SimpleJson p = new SimpleJson(json);
        p.skipWs();
        Object result = p.parseValue();
        p.skipWs();
        return result;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String json) {
        Object v = parse(json);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object, got: " + json);
        }
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    static List<Object> parseArray(String json) {
        Object v = parse(json);
        if (!(v instanceof List)) {
            throw new IllegalArgumentException("expected a JSON array, got: " + json);
        }
        return (List<Object>) v;
    }

    private Object parseValue() {
        skipWs();
        if (pos >= src.length()) {
            throw new IllegalArgumentException("unexpected end of JSON input");
        }
        char c = src.charAt(pos);
        switch (c) {
            case '{':
                return parseObjectValue();
            case '[':
                return parseArrayValue();
            case '"':
                return parseString();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return parseNumber();
        }
    }

    private Map<String, Object> parseObjectValue() {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++; // '{'
        skipWs();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipWs();
            String key = parseString();
            skipWs();
            if (peek() != ':') {
                throw new IllegalArgumentException("expected ':' at position " + pos);
            }
            pos++;
            Object value = parseValue();
            map.put(key, value);
            skipWs();
            char c = peek();
            if (c == ',') {
                pos++;
            } else if (c == '}') {
                pos++;
                break;
            } else {
                throw new IllegalArgumentException("expected ',' or '}' at position " + pos);
            }
        }
        return map;
    }

    private List<Object> parseArrayValue() {
        List<Object> list = new ArrayList<>();
        pos++; // '['
        skipWs();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            list.add(parseValue());
            skipWs();
            char c = peek();
            if (c == ',') {
                pos++;
            } else if (c == ']') {
                pos++;
                break;
            } else {
                throw new IllegalArgumentException("expected ',' or ']' at position " + pos);
            }
        }
        return list;
    }

    private String parseString() {
        if (peek() != '"') {
            throw new IllegalArgumentException("expected '\"' at position " + pos);
        }
        pos++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = src.charAt(pos++);
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                char esc = src.charAt(pos++);
                switch (esc) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'u':
                        String hex = src.substring(pos, pos + 4);
                        sb.append((char) Integer.parseInt(hex, 16));
                        pos += 4;
                        break;
                    default:
                        throw new IllegalArgumentException("invalid escape '\\" + esc + "' at position " + pos);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private Double parseNumber() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        while (pos < src.length() && (Character.isDigit(src.charAt(pos)) || "+-.eE".indexOf(src.charAt(pos)) >= 0)) {
            pos++;
        }
        return Double.parseDouble(src.substring(start, pos));
    }

    private void expect(String literal) {
        if (!src.startsWith(literal, pos)) {
            throw new IllegalArgumentException("expected '" + literal + "' at position " + pos);
        }
        pos += literal.length();
    }

    private char peek() {
        return pos < src.length() ? src.charAt(pos) : '\0';
    }

    private void skipWs() {
        while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
            pos++;
        }
    }
}
