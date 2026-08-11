const DEFAULT_GAP = 4;
const MIN_TILE_WIDTH = 104;
const MIN_CONTENT_WIDTH = 72;
const MIN_TILE_HEIGHT = 72;
const MAX_BATCH_TILE_HEIGHT = 260;
const MAX_TILE_HEIGHT = 520;

function finite(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(maximum, value));
}

function balancedColumnCount(count, maximumColumns) {
    let columns = Math.max(1, Math.min(count, maximumColumns));
    if (columns >= count) return columns;

    // Prefer the widest useful grid, but avoid an orphaned last row when the
    // same number of rows can be distributed more evenly with one fewer column.
    while (columns > 2) {
        const rows = Math.ceil(count / columns);
        const finalRowItems = count % columns || columns;
        if (finalRowItems >= Math.ceil(columns / 2)) break;
        const candidate = columns - 1;
        if (Math.ceil(count / candidate) !== rows) break;
        columns = candidate;
    }
    return columns;
}

/** Pure responsive-grid geometry used by the encrypted image preview. */
export function responsiveGridGeometry(itemCount, availableWidth, aspects = [], gap = DEFAULT_GAP) {
    const count = Math.max(0, Math.floor(finite(itemCount, 0)));
    const width = Math.max(MIN_CONTENT_WIDTH, finite(availableWidth, MIN_CONTENT_WIDTH));
    const safeGap = Math.max(0, finite(gap, DEFAULT_GAP));
    if (!count) return { columns: 0, rows: 0, cellWidth: width, rowHeights: [], height: 0 };

    // Fill the horizontal space first, then wrap. A small minimum tile width
    // keeps batches compact while still allowing very narrow nodes to use one
    // column without overflowing their DOM allocation.
    const desiredColumns = Math.max(1, Math.floor((width + safeGap) / (MIN_TILE_WIDTH + safeGap)));
    const columns = balancedColumnCount(count, desiredColumns);
    const rows = Math.ceil(count / columns);
    const cellWidth = Math.max(1, (width - safeGap * (columns - 1)) / columns);
    const rowHeights = [];

    for (let row = 0; row < rows; row++) {
        let rowHeight;
        if (count > 1) {
            // Batch output uses consistent thumbnail cells. Images keep their
            // own aspect ratio via object-fit:contain, so a single portrait or
            // panorama cannot make an entire row disproportionately tall.
            rowHeight = clamp(cellWidth, MIN_TILE_HEIGHT, MAX_BATCH_TILE_HEIGHT);
        } else {
            const aspect = clamp(finite(aspects[0], 1), 0.4, 3);
            rowHeight = clamp(cellWidth / aspect, MIN_TILE_HEIGHT, MAX_TILE_HEIGHT);
        }
        rowHeights.push(rowHeight);
    }

    const height = rowHeights.reduce((sum, value) => sum + value, 0) + safeGap * Math.max(0, rows - 1);
    return { columns, rows, cellWidth, rowHeights, height: Math.ceil(height) };
}

/**
 * Keep the LiteGraph node border at least as tall as its DOM preview.
 * The computed height is kept as a candidate because different ComfyUI
 * generations account for DOM widget height differently.
 */
export function requiredNodeHeight(baseHeight, previewHeight, verticalGap = 8) {
    const base = Math.max(0, finite(baseHeight, 0));
    const preview = Math.max(0, finite(previewHeight, 0));
    const gap = Math.max(0, finite(verticalGap, 8));
    return Math.ceil(base + preview + gap);
}
