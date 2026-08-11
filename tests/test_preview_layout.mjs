import assert from "node:assert/strict";
import { requiredNodeHeight, responsiveGridGeometry } from "../js/csyx_preview_layout.js";

const wideFive = responsiveGridGeometry(5, 880, [0.7, 0.7, 0.7, 0.7, 0.7]);
assert.equal(wideFive.columns, 5);
assert.equal(wideFive.rows, 1);
assert.ok(wideFive.height > wideFive.cellWidth, "portrait row did not preserve image aspect");

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

const mixed = responsiveGridGeometry(4, 620, [3, 0.4, 1, 1.5]);
assert.ok(mixed.rowHeights.every((height) => height >= 96 && height <= 520));
assert.equal(mixed.height, Math.ceil(mixed.rowHeights.reduce((sum, value) => sum + value, 0)));

assert.deepEqual(
    responsiveGridGeometry(0, 600),
    { columns: 0, rows: 0, cellWidth: 600, rowHeights: [], height: 0 },
);

assert.equal(
    requiredNodeHeight(210, 400, 390),
    618,
    "node height did not include the full preview height and bottom spacing",
);
assert.equal(
    requiredNodeHeight(210, 100, 450),
    450,
    "a larger ComfyUI-computed height should not be reduced",
);

console.log("encrypted preview responsive layout tests passed");
