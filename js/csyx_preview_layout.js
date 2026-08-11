const DEFAULT_GAP = 4;
const TARGET_TILE_WIDTH = 170;
const MIN_CONTENT_WIDTH = 160;
const MIN_TILE_HEIGHT = 96;
const MAX_TILE_HEIGHT = 520;

function finite(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(maximum, value));
}

/** Pure responsive-grid geometry used by the encrypted image preview. */
export function responsiveGridGeometry(itemCount, availableWidth, aspects = [], gap = DEFAULT_GAP) {
    const count = Math.max(0, Math.floor(finite(itemCount, 0)));
    const width = Math.max(MIN_CONTENT_WIDTH, finite(availableWidth, MIN_CONTENT_WIDTH));
    const safeGap = Math.max(0, finite(gap, DEFAULT_GAP));
    if (!count) return { columns: 0, rows: 0, cellWidth: width, rowHeights: [], height: 0 };

    // Rounding, instead of flooring, gives a useful two-column layout near 300px
    // while still growing naturally to five columns around 900px.
    const desiredColumns = Math.max(1, Math.round((width + safeGap) / (TARGET_TILE_WIDTH + safeGap)));
    const columns = Math.min(count, desiredColumns);
    const rows = Math.ceil(count / columns);
    const cellWidth = Math.max(1, (width - safeGap * (columns - 1)) / columns);
    const rowHeights = [];

    for (let row = 0; row < rows; row++) {
        let rowHeight = MIN_TILE_HEIGHT;
        const start = row * columns;
        const end = Math.min(count, start + columns);
        for (let index = start; index < end; index++) {
            const aspect = clamp(finite(aspects[index], 1), 0.4, 3);
            rowHeight = Math.max(rowHeight, cellWidth / aspect);
        }
        // Extremely tall images remain fully visible via object-fit without making
        // one preview row consume the entire canvas.
        rowHeights.push(clamp(rowHeight, MIN_TILE_HEIGHT, Math.min(MAX_TILE_HEIGHT, cellWidth * 2.2)));
    }

    const height = rowHeights.reduce((sum, value) => sum + value, 0) + safeGap * Math.max(0, rows - 1);
    return { columns, rows, cellWidth, rowHeights, height: Math.ceil(height) };
}

/**
 * Keep the LiteGraph node border at least as tall as its DOM preview.
 * The computed height is kept as a candidate because different ComfyUI
 * generations account for DOM widget height differently.
 */
export function requiredNodeHeight(baseHeight, previewHeight, computedHeight = 0, verticalGap = 8) {
    const base = Math.max(0, finite(baseHeight, 0));
    const preview = Math.max(0, finite(previewHeight, 0));
    const computed = Math.max(0, finite(computedHeight, 0));
    const gap = Math.max(0, finite(verticalGap, 8));
    return Math.ceil(Math.max(computed, base + preview + gap));
}
