export const ORDER_BOOK_OVERSCAN_ROWS = 2;

export interface VirtualWindow {
  startIndex: number;
  endIndex: number;
  topPadding: number;
  bottomPadding: number;
  renderedRows: number;
}

export function normalizeVisibleRows(visibleRows: number): number {
  return Math.max(1, Math.floor(Number.isFinite(visibleRows) ? visibleRows : 1));
}

export function getVirtualWindow({
  rowCount,
  rowHeight,
  scrollTop,
  visibleRows,
  overscanRows = ORDER_BOOK_OVERSCAN_ROWS,
}: {
  rowCount: number;
  rowHeight: number;
  scrollTop: number;
  visibleRows: number;
  overscanRows?: number;
}): VirtualWindow {
  const safeRowCount = Math.max(0, Math.floor(rowCount));
  const safeRowHeight = Math.max(1, rowHeight);
  const safeVisibleRows = normalizeVisibleRows(visibleRows);
  const safeOverscanRows = Math.max(0, Math.floor(overscanRows));

  if (safeRowCount === 0) {
    return {
      startIndex: 0,
      endIndex: 0,
      topPadding: 0,
      bottomPadding: 0,
      renderedRows: 0,
    };
  }

  const firstVisibleIndex = Math.floor(Math.max(0, scrollTop) / safeRowHeight);
  const startIndex = Math.max(0, firstVisibleIndex - safeOverscanRows);
  const endIndex = Math.min(
    safeRowCount,
    firstVisibleIndex + safeVisibleRows + safeOverscanRows,
  );
  const renderedRows = Math.max(0, endIndex - startIndex);
  const totalHeight = safeRowCount * safeRowHeight;
  const topPadding = startIndex * safeRowHeight;
  const renderedHeight = renderedRows * safeRowHeight;

  return {
    startIndex,
    endIndex,
    topPadding,
    bottomPadding: Math.max(0, totalHeight - topPadding - renderedHeight),
    renderedRows,
  };
}

export function maxRenderedOrderBookRows(
  visibleRows: number,
  sideCount = 2,
  overscanRows = ORDER_BOOK_OVERSCAN_ROWS,
): number {
  return (normalizeVisibleRows(visibleRows) + overscanRows * 2) * sideCount;
}
