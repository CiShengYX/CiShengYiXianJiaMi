import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "..", "CiShengYX_decrypt.html"), "utf8");
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
    .map((match) => match[1])
    .filter((source) => source.trim());

assert.ok(scripts.length > 0, "no inline decrypt script found");
for (const source of scripts) new Function(source);
assert.match(html, /VERSION_V3=3/);
assert.match(html, /iterations:V3_PBKDF2_ITERATIONS/);
console.log("decrypt HTML syntax and V3 declarations: ok");
