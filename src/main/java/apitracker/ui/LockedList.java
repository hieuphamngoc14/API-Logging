package apitracker.ui;

import javax.swing.JList;
import javax.swing.ListCellRenderer;
import javax.swing.ListModel;

/**
 * JList that keeps the extension's renderer fixed. Burp applies its theme to extension components
 * ({@code applyThemeToComponent}, light/dark theme switch) and may swap in the default renderer, after which the list
 * only shows each element's {@code toString()}. This class ignores renderer changes once locked, and always returns
 * the locked renderer when Swing paints.
 */
final class LockedList<E> extends JList<E> {
    private ListCellRenderer<? super E> locked;

    LockedList(ListModel<E> model) { super(model); }

    void lockRenderer(ListCellRenderer<? super E> r) {
        locked = r;
        super.setCellRenderer(r);
    }

    @Override
    public void setCellRenderer(ListCellRenderer<? super E> r) {
        super.setCellRenderer(locked != null ? locked : r);
    }

    @Override
    public ListCellRenderer<? super E> getCellRenderer() {
        return locked != null ? locked : super.getCellRenderer();
    }
}
