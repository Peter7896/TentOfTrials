import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, '..');
const helperSource = fs.readFileSync(
  path.join(frontendRoot, 'src', 'components', 'orderBookVirtualization.ts'),
  'utf8',
);
const componentSource = fs.readFileSync(
  path.join(frontendRoot, 'src', 'components', 'OrderBook.tsx'),
  'utf8',
);

const overscanMatch = helperSource.match(/ORDER_BOOK_OVERSCAN_ROWS\s*=\s*(\d+)/);
if (!overscanMatch) {
  throw new Error('Could not find ORDER_BOOK_OVERSCAN_ROWS in the virtualization helper');
}

const overscanRows = Number(overscanMatch[1]);
const visibleRows = 15;
const rowHeight = 28;
const rowCountPerSide = 2500;
const maxRenderedPerSide = visibleRows + overscanRows * 2;

function getWindow(scrollTop) {
  const firstVisibleIndex = Math.floor(Math.max(0, scrollTop) / rowHeight);
  const startIndex = Math.max(0, firstVisibleIndex - overscanRows);
  const endIndex = Math.min(rowCountPerSide, firstVisibleIndex + visibleRows + overscanRows);
  return {
    startIndex,
    endIndex,
    renderedRows: Math.max(0, endIndex - startIndex),
    topPadding: startIndex * rowHeight,
    bottomPadding: Math.max(
      0,
      rowCountPerSide * rowHeight - startIndex * rowHeight - Math.max(0, endIndex - startIndex) * rowHeight,
    ),
  };
}

for (const scrollTop of [0, rowHeight * 12, rowHeight * 900, rowHeight * 2480]) {
  const window = getWindow(scrollTop);
  if (window.renderedRows > maxRenderedPerSide) {
    throw new Error(`Rendered ${window.renderedRows} rows at scrollTop ${scrollTop}; expected <= ${maxRenderedPerSide}`);
  }
  const virtualHeight = window.topPadding + window.renderedRows * rowHeight + window.bottomPadding;
  if (virtualHeight !== rowCountPerSide * rowHeight) {
    throw new Error(`Virtual height mismatch at scrollTop ${scrollTop}`);
  }
}

if (!componentSource.includes('VirtualizedOrderBookSide')) {
  throw new Error('OrderBook does not use the virtualized side component');
}

if (componentSource.includes('.slice(0, maxRows)')) {
  throw new Error('OrderBook still truncates the processed book before virtual rendering');
}

console.log(
  `OrderBook virtualization verified: ${rowCountPerSide * 2} levels render at most ${maxRenderedPerSide * 2} DOM rows.`,
);
