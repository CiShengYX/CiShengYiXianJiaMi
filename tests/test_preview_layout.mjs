import assert from "node:assert/strict";
import { requiredNodeHeight, responsiveGridGeometry } from "../js/csyx_preview_layout.js";

const wideFive = responsiveGridGeometry(5, 880, [0.7, 0.7, 0.7, 0.7, 0.7]);
assert.equal(wideFive.columns, 5);
assert.equal(wideFive.rows, 1);
assert.equal(wideFive.height, Math.ceil(wideFive.cellWidth), "batch thumbnails did not use a compact uniform row");

const narrowMany = responsiveGridGeometry(8, 300, Array(8).fill(1));
assert.equal(narrowMany.columns, 2);
assert.equal(narrowMany.rows, 4);
assert.ok(narrowMany.height > 500, "multi-row preview height did not expand");

const draggedNarrow = responsiveGridGeometry(3, 180, Array(3).fill(1));
assert.equal(draggedNarrow.columns, 1);
assert.equal(draggedNarrow.rows, 3);

const draggedWide = responsiveGridGeometry(3, 900, Array(3).fill(1));
assert.equal(draggedWide.columns, 3);
assert.equal(draggedWide.rows, 1);
assert.ok(draggedWide.height > 250, "wide square previews remained at the old fixed 180px height");

const horizontalFirst = responsiveGridGeometry(6, 540, Array(6).fill(1));
assert.equal(horizontalFirst.columns, 4, "batch previews did not balance horizontal fill and the final row");
assert.equal(horizontalFirst.rows, 2);

const balancedEight = responsiveGridGeometry(8, 540, Array(8).fill(1));
assert.equal(balancedEight.columns, 5, "a naturally balanced final row was reduced unnecessarily");
assert.equal(balancedEight.rows, 2);

const veryNarrow = responsiveGridGeometry(6, 80, Array(6).fill(1));
assert.equal(veryNarrow.columns, 1);
assert.equal(veryNarrow.cellWidth, 80, "very narrow preview retained the old fixed content width");
assert.equal(veryNarrow.rows, 6);

const mixed = responsiveGridGeometry(4, 620, [3, 0.4, 1, 1.5]);
assert.ok(mixed.rowHeights.every((height) => height >= 96 && height <= 520));
assert.ok(mixed.rowHeights.every((height) => height === mixed.rowHeights[0]), "mixed aspect batch created uneven rows");
assert.equal(mixed.height, Math.ceil(mixed.rowHeights.reduce((sum, value) => sum + value, 0)));

const singlePortrait = responsiveGridGeometry(1, 240, [0.5]);
assert.equal(singlePortrait.height, 480, "single-image preview stopped respecting its aspect ratio");

assert.deepEqual(
    responsiveGridGeometry(0, 600),
    { columns: 0, rows: 0, cellWidth: 600, rowHeights: [], height: 0 },
);

assert.equal(
    requiredNodeHeight(210, 400),
    618,
    "node height did not include the full preview height and bottom spacing",
);
assert.equal(
    requiredNodeHeight(210, 100),
    318,
    "node height retained stale blank space after the grid became shorter",
);

console.log("encrypted preview responsive layout tests passed");
