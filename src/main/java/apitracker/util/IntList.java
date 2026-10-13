package apitracker.util;

import java.util.Arrays;

/** Growable int array, no boxing. Not thread-safe. */
public final class IntList {
    private int[] a;
    private int n;

    public IntList() { this(4); }
    public IntList(int cap) { a = new int[Math.max(1, cap)]; }

    public void add(int v) {
        if (n == a.length) a = Arrays.copyOf(a, a.length * 2);
        a[n++] = v;
    }

    public int size() { return n; }
    public boolean isEmpty() { return n == 0; }
    public void clear() { n = 0; if (a.length > 1024) a = new int[4]; }
    public int get(int i) { return a[i]; }
    public int[] toArray() { return Arrays.copyOf(a, n); }

    public void removeValue(int v) {
        for (int i = 0; i < n; i++) {
            if (a[i] == v) {
                System.arraycopy(a, i + 1, a, i, n - i - 1);
                n--;
                return;
            }
        }
    }
}
