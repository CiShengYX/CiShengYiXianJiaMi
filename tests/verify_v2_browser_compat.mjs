import fs from "node:fs";
import crypto from "node:crypto";


const [filePath, password, expectedHash] = process.argv.slice(2);
if (!filePath || expectedHash === undefined) {
    throw new Error("usage: node verify_v2_browser_compat.mjs FILE PASSWORD SHA256");
}

const file = new Uint8Array(fs.readFileSync(filePath));
const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
let position = 8;
while (position + 12 <= file.length) {
    const length = view.getUint32(position, false);
    const type = String.fromCharCode(...file.slice(position + 4, position + 8));
    position += 12 + length;
    if (type === "IEND") break;
}

const packetOffset = position;
const version = file[packetOffset + 8];
if (version !== 2 && version !== 3) throw new Error(`unexpected version ${version}`);
const chunkSize = view.getUint32(packetOffset + 12, false);
const plainSize = Number(view.getBigUint64(packetOffset + 16, false));
const chunkCount = view.getUint32(packetOffset + 24, false);
const salt = file.slice(packetOffset + 28, packetOffset + 44);
const noncePrefix = file.slice(packetOffset + 44, packetOffset + 52);
const metadataLength = view.getUint32(packetOffset + 52, false);
const headerEnd = packetOffset + 56 + metadataLength;
const header = file.slice(packetOffset, headerEnd);

const encoder = new TextEncoder();
const passwordBytes = encoder.encode(password || "CSYX_DEFAULT_KEY");
let key;
if (version === 2) {
    const domain = encoder.encode("CSYX-V2-KEY\0");
    const keySource = new Uint8Array(domain.length + salt.length + passwordBytes.length);
    keySource.set(domain);
    keySource.set(salt, domain.length);
    keySource.set(passwordBytes, domain.length + salt.length);
    const keyBytes = await crypto.webcrypto.subtle.digest("SHA-256", keySource);
    key = await crypto.webcrypto.subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"],
    );
} else {
    const domain = encoder.encode("CSYX-V3-PBKDF2\0");
    const domainSalt = new Uint8Array(domain.length + salt.length);
    domainSalt.set(domain);
    domainSalt.set(salt, domain.length);
    const material = await crypto.webcrypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
    key = await crypto.webcrypto.subtle.deriveKey(
        { name: "PBKDF2", salt: domainSalt, iterations: 600000, hash: "SHA-256" },
        material, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
    );
}

position = headerEnd;
const parts = [];
let decoded = 0;
for (let index = 0; index < chunkCount; index++) {
    const plainLength = view.getUint32(position, false);
    position += 4;
    const expectedLength = plainSize === 0 ? 0 : Math.min(chunkSize, plainSize - decoded);
    if (plainLength !== expectedLength) throw new Error("chunk length mismatch");
    const encrypted = file.slice(position, position + plainLength + 16);
    position += plainLength + 16;
    const nonce = new Uint8Array(12);
    nonce.set(noncePrefix);
    new DataView(nonce.buffer).setUint32(8, index, false);
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, false);
    const aad = new Uint8Array(header.length + 4);
    aad.set(header);
    aad.set(indexBytes, header.length);
    const plain = await crypto.webcrypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, encrypted,
    );
    parts.push(new Uint8Array(plain));
    decoded += plain.byteLength;
}

const output = new Uint8Array(decoded);
let outputPosition = 0;
for (const part of parts) {
    output.set(part, outputPosition);
    outputPosition += part.length;
}
const actualHash = crypto.createHash("sha256").update(output).digest("hex");
if (actualHash !== expectedHash) throw new Error(`hash mismatch: ${actualHash}`);
console.log(`V${version} browser compatibility OK: ${decoded} bytes, ${chunkCount} chunks`);
