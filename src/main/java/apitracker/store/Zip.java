package apitracker.store;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Fast compression (Deflater level 1) for raw requests. A send is compressed with its original request as dictionary:
 * the two differ by a few bytes, so the output is a few dozen bytes instead of a few KB (less disk I/O, smaller DB).
 * Old data compressed without a dictionary still inflates normally (zlib flags when a dictionary is needed).
 */
public final class Zip {
    /** Deflate only looks back 32 KB: the dictionary is the original request's first 32 KB (first line + headers + body start). */
    public static final int DICT_MAX = 32 * 1024;

    private Zip() {}

    public static byte[] deflate(byte[] in) {
        return deflate(in, null);
    }

    /** Compresses with a dictionary (null: none). The dictionary must be rebuilt identically when inflating. */
    public static byte[] deflate(byte[] in, byte[] dict) {
        if (in == null) return null;
        Deflater d = new Deflater(1);
        try {
            if (dict != null && dict.length > 0) d.setDictionary(dict);
            d.setInput(in);
            d.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, in.length / 4));
            byte[] buf = new byte[8192];
            while (!d.finished()) {
                int n = d.deflate(buf);
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            d.end();
        }
    }

    public static byte[] inflate(byte[] in) {
        return inflate(in, null);
    }

    /** Inflates; returns null if the stream was compressed with a dictionary and dict is null. */
    public static byte[] inflate(byte[] in, byte[] dict) {
        if (in == null) return null;
        Inflater inf = new Inflater();
        try {
            inf.setInput(in);
            ByteArrayOutputStream out = new ByteArrayOutputStream(in.length * 4 + 64);
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0) {
                    if (inf.needsDictionary()) {
                        if (dict == null) return null;
                        inf.setDictionary(dict);
                        continue;
                    }
                    if (inf.needsInput() || !inf.finished()) break;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (DataFormatException | IllegalArgumentException e) {
            return null;
        } finally {
            inf.end();
        }
    }

    /** Standard dictionary built from the (decompressed) original request. */
    public static byte[] dictOf(byte[] originalRaw) {
        if (originalRaw == null || originalRaw.length == 0) return null;
        return originalRaw.length <= DICT_MAX ? originalRaw : Arrays.copyOf(originalRaw, DICT_MAX);
    }
}
