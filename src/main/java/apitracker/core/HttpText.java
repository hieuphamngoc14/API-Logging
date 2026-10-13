package apitracker.core;

import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Readable text form of a raw HTTP message, stored with each original request so the log can be handed to an AI with
 * full context: headers as-is, text bodies decoded as UTF-8, binary bodies replaced by a placeholder, size capped.
 */
public final class HttpText {
    private HttpText() {}

    /** Cap on the stored text of one message (characters). */
    public static final int MAX_CHARS = 256 * 1024;
    /** Cap on the raw bytes read from a response before converting it. */
    public static final int MAX_RAW = 1024 * 1024;

    /** null for an empty message. */
    public static String of(byte[] raw, int maxChars) {
        if (raw == null || raw.length == 0) return null;
        int headEnd = raw.length, bodyStart = raw.length;
        int sep = indexOf(raw, new byte[]{'\r', '\n', '\r', '\n'});
        if (sep >= 0) { headEnd = sep; bodyStart = sep + 4; }
        else {
            sep = indexOf(raw, new byte[]{'\n', '\n'});
            if (sep >= 0) { headEnd = sep; bodyStart = sep + 2; }
        }
        StringBuilder b = new StringBuilder(Math.min(raw.length, maxChars) + 64);
        b.append(utf8(raw, 0, headEnd).replace("\r\n", "\n"));
        int bodyLen = raw.length - bodyStart;
        if (bodyStart < raw.length || headEnd < raw.length) b.append("\n\n");
        if (bodyLen > 0) {
            if (binary(raw, bodyStart)) b.append("[binary body: ").append(String.format("%,d", bodyLen)).append(" bytes]");
            else b.append(utf8(raw, bodyStart, bodyLen));
        }
        if (b.length() > maxChars) {
            b.setLength(maxChars);
            b.append("\n… [truncated]");
        }
        return b.toString();
    }

    /** A NUL byte or many invalid UTF-8 sequences in the first 4 KB: treat as binary (images, gzip, protobuf...). */
    static boolean binary(byte[] raw, int from) {
        int end = Math.min(raw.length, from + 4096);
        for (int i = from; i < end; i++) if (raw[i] == 0) return true;
        String s = utf8(raw, from, end - from);
        int bad = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '�') bad++;
        return bad > Math.max(8, s.length() / 20);
    }

    private static String utf8(byte[] raw, int off, int len) {
        CharsetDecoder d = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE);
        try {
            return d.decode(ByteBuffer.wrap(raw, off, len)).toString();
        } catch (java.nio.charset.CharacterCodingException e) {
            return new String(raw, off, len, StandardCharsets.ISO_8859_1);
        }
    }

    private static int indexOf(byte[] a, byte[] pat) {
        outer:
        for (int i = 0; i + pat.length <= a.length; i++) {
            for (int j = 0; j < pat.length; j++) if (a[i + j] != pat[j]) continue outer;
            return i;
        }
        return -1;
    }
}
