"""CSYX 单文件加密核心。

V1 是旧版整体 AES-GCM 格式，仅保留解密兼容。
V2/V3 使用合法 PNG 封面和 IEND 后的分块 AES-256-GCM 载荷；V3 强化密码派生。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import struct
from typing import BinaryIO, Dict, Optional, Tuple


MAGIC = b"CSYX_ENC"
LEGACY_VERSION = 1
COMPAT_VERSION = 2
VERSION = 3

CONTENT_IMAGE = 0x01
CONTENT_VIDEO = 0x02
CONTENT_TEXT = 0x03
CONTENT_AUDIO = 0x04
CONTENT_FILE = 0x05

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
TAG_SIZE = 16
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
_V2_FIXED = struct.Struct(">8sBBBBIQI16s8sI")
_V2_DOMAIN = b"CSYX-V2-KEY\x00"
_V3_DOMAIN = b"CSYX-V3-PBKDF2\x00"
_DEFAULT_PASSWORD = b"CSYX_DEFAULT_KEY"
_MAX_METADATA_SIZE = 1024 * 1024

PBKDF2_ITERATIONS = 100000
V3_PBKDF2_ITERATIONS = 600000
_LEGACY_KEY_CACHE: Dict[Tuple[str, bytes], bytes] = {}
_COVER_CLEAN: Optional[bytes] = None


class CSYXFormatError(ValueError):
    """文件不是有效的 CSYX 加密文件。"""


class CSYXDependencyError(RuntimeError):
    """缺少高速加密依赖。"""


def _new_aesgcm(key: bytes):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key)
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise CSYXDependencyError(
            "缺少高速加密库 cryptography（也未检测到 pycryptodome）。"
            "请安装节点 requirements.txt 后重启 ComfyUI；为避免长视频极慢，"
            "本节点不会使用纯 Python 慢速加密。"
        ) from exc

    class PyCryptodomeAESGCM:
        def encrypt(self, nonce: bytes, data: bytes, aad: Optional[bytes]) -> bytes:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
            if aad:
                cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return ciphertext + tag

        def decrypt(self, nonce: bytes, data: bytes, aad: Optional[bytes]) -> bytes:
            if len(data) < TAG_SIZE:
                raise CSYXFormatError("AES-GCM 数据太短")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
            if aad:
                cipher.update(aad)
            return cipher.decrypt_and_verify(data[:-TAG_SIZE], data[-TAG_SIZE:])

    return PyCryptodomeAESGCM()


def has_fast_crypto() -> bool:
    try:
        _new_aesgcm(bytes(32))
        return True
    except CSYXDependencyError:
        return False


def _password_bytes(password: str) -> bytes:
    return password.encode("utf-8") if password else _DEFAULT_PASSWORD


def _derive_key_v2(password: str, salt: bytes) -> bytes:
    if len(salt) != SALT_SIZE:
        raise ValueError("V2 salt 长度无效")
    return hashlib.sha256(_V2_DOMAIN + salt + _password_bytes(password)).digest()


def _derive_key_v3(password: str, salt: bytes) -> bytes:
    """V3 password hardening. The domain is part of the authenticated format."""
    if len(salt) != SALT_SIZE:
        raise ValueError("V3 salt 长度无效")
    return hashlib.pbkdf2_hmac(
        "sha256",
        _password_bytes(password),
        _V3_DOMAIN + salt,
        V3_PBKDF2_ITERATIONS,
        dklen=32,
    )


def _derive_key(password: str, salt: bytes) -> bytes:
    """V1 PBKDF2 密钥派生，供历史文件解密兼容。"""
    cache_key = (password, salt)
    cached = _LEGACY_KEY_CACHE.get(cache_key)
    if cached is not None:
        return cached
    if len(_LEGACY_KEY_CACHE) >= 64:
        _LEGACY_KEY_CACHE.clear()
    key = hashlib.pbkdf2_hmac(
        "sha256", _password_bytes(password), salt, PBKDF2_ITERATIONS, dklen=32
    )
    _LEGACY_KEY_CACHE[cache_key] = key
    return key


def _get_cover_png() -> bytes:
    cover_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cover.png")
    with open(cover_path, "rb") as handle:
        return handle.read()


def _strip_png_metadata(png_data: bytes) -> bytes:
    if png_data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("封面不是有效的 PNG")
    keep = {
        b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA",
        b"iCCP", b"sBIT", b"sRGB", b"bKGD", b"hIST", b"pHYs", b"sPLT",
        b"acTL", b"fcTL", b"fdAT",
    }
    result = bytearray(png_data[:8])
    pos = 8
    found_iend = False
    while pos + 12 <= len(png_data):
        length = struct.unpack_from(">I", png_data, pos)[0]
        end = pos + 12 + length
        if end > len(png_data):
            raise ValueError("封面 PNG 数据不完整")
        chunk_type = png_data[pos + 4:pos + 8]
        if chunk_type in keep:
            result.extend(png_data[pos:end])
        pos = end
        if chunk_type == b"IEND":
            found_iend = True
            break
    if not found_iend:
        raise ValueError("封面 PNG 缺少 IEND")
    return bytes(result)


def _get_clean_cover_png() -> bytes:
    global _COVER_CLEAN
    if _COVER_CLEAN is None:
        _COVER_CLEAN = _strip_png_metadata(_get_cover_png())
    return _COVER_CLEAN


def png_end_offset(data: bytes) -> int:
    """返回 PNG IEND 之后的精确偏移，拒绝伪造的 IEND 字节搜索。"""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise CSYXFormatError("不是有效的 PNG 文件")
    pos = 8
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        end = pos + 12 + length
        if end > len(data):
            raise CSYXFormatError("PNG 数据不完整")
        if data[pos + 4:pos + 8] == b"IEND":
            if length != 0:
                raise CSYXFormatError("PNG IEND 长度无效")
            return end
        pos = end
    raise CSYXFormatError("PNG 缺少 IEND")


def _safe_original_name(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/"))
    name = "".join(ch for ch in name if ch >= " " and ch not in '\\/:*?"<>|')
    return name[:240] or "decrypted.bin"


def _canonical_metadata(
    original_filename: str, mime_type: str, source_size: int
) -> bytes:
    payload = {
        "filename": _safe_original_name(original_filename),
        "mime": mime_type or "application/octet-stream",
        "size": source_size,
        "version": VERSION,
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    if len(encoded) > _MAX_METADATA_SIZE:
        raise ValueError("元数据过大")
    return encoded


def _source_size(source: BinaryIO) -> int:
    if not hasattr(source, "seek") or not hasattr(source, "tell"):
        raise ValueError("流式加密需要可定位的数据源或明确的 source_size")
    current = source.tell()
    source.seek(0, os.SEEK_END)
    size = source.tell() - current
    source.seek(current, os.SEEK_SET)
    return size


def encrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    content_type: int,
    password: str = "",
    original_filename: str = "",
    mime_type: str = "application/octet-stream",
    source_size: Optional[int] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Dict[str, object]:
    """把数据源加密为 V3 PNG 单文件，额外内存上限约为一个分块。"""
    if content_type not in {
        CONTENT_IMAGE, CONTENT_VIDEO, CONTENT_TEXT, CONTENT_AUDIO, CONTENT_FILE
    }:
        raise ValueError("未知内容类型")
    if chunk_size < 64 * 1024 or chunk_size > 64 * 1024 * 1024:
        raise ValueError("分块大小必须在 64 KiB 到 64 MiB 之间")
    if source_size is None:
        source_size = _source_size(source)
    if source_size < 0:
        raise ValueError("数据长度无效")

    chunk_count = max(1, (source_size + chunk_size - 1) // chunk_size)
    if chunk_count > 0xFFFFFFFF:
        raise ValueError("文件过大，分块数量超出格式限制")

    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    metadata = _canonical_metadata(original_filename, mime_type, source_size)
    flags = 1 if password else 0
    fixed = _V2_FIXED.pack(
        MAGIC, VERSION, content_type, flags, 0, chunk_size, source_size,
        chunk_count, salt, nonce_prefix, len(metadata),
    )
    header = fixed + metadata
    key = _derive_key_v3(password, salt)
    aesgcm = _new_aesgcm(key)

    destination.write(_get_clean_cover_png())
    destination.write(header)
    bytes_read = 0
    for index in range(chunk_count):
        expected = min(chunk_size, source_size - bytes_read)
        if source_size == 0:
            expected = 0
        parts = []
        remaining = expected
        while remaining:
            part = source.read(remaining)
            if not part:
                break
            if len(part) > remaining:
                raise OSError("数据源返回了超过请求长度的数据")
            parts.append(part)
            remaining -= len(part)
        plain = b"".join(parts)
        if len(plain) != expected:
            raise OSError(
                f"读取源数据时提前结束：期望 {expected} 字节，实际 {len(plain)} 字节"
            )
        nonce = nonce_prefix + struct.pack(">I", index)
        aad = header + struct.pack(">I", index)
        encrypted = aesgcm.encrypt(nonce, plain, aad)
        destination.write(struct.pack(">I", len(plain)))
        destination.write(encrypted)
        bytes_read += len(plain)

    if bytes_read != source_size:
        raise OSError("读取的数据长度与声明长度不一致")
    extra = source.read(1)
    if extra:
        raise OSError("数据源在声明长度之后仍有内容")
    return {
        "version": VERSION,
        "content_type": content_type,
        "source_size": source_size,
        "chunk_count": chunk_count,
        "chunk_size": chunk_size,
        "metadata": json.loads(metadata.decode("utf-8")),
    }


def encrypt_data(
    raw_data: bytes,
    content_type: int,
    password: str = "",
    original_filename: str = "",
    mime_type: str = "application/octet-stream",
) -> bytes:
    """小数据兼容接口；大文件应使用 encrypt_stream。"""
    source = io.BytesIO(raw_data)
    destination = io.BytesIO()
    encrypt_stream(
        source, destination, content_type, password, original_filename,
        mime_type, len(raw_data),
    )
    return destination.getvalue()


def _decrypt_v1(packet: bytes, password: str) -> Tuple[bytes, Dict[str, object]]:
    if len(packet) < 65 or packet[8] != LEGACY_VERSION:
        raise CSYXFormatError("V1 加密数据太短或版本错误")
    has_password = packet[10] == 1
    if has_password != bool(password):
        raise CSYXFormatError("密码设置不匹配（加密时有密码/无密码）")
    content_type = packet[9]
    salt, nonce, tag = packet[11:27], packet[27:39], packet[39:55]
    filename_len = struct.unpack_from(">H", packet, 55)[0]
    data_length_offset = 57 + filename_len
    if data_length_offset + 8 > len(packet):
        raise CSYXFormatError("V1 文件头不完整")
    filename = packet[57:data_length_offset].decode("utf-8", errors="replace")
    encrypted_len = struct.unpack_from(">Q", packet, data_length_offset)[0]
    cipher_offset = data_length_offset + 8
    ciphertext = packet[cipher_offset:cipher_offset + encrypted_len]
    if len(ciphertext) != encrypted_len or cipher_offset + encrypted_len != len(packet):
        raise CSYXFormatError("V1 密文长度不正确")
    key = _derive_key(password, salt)
    plain = _new_aesgcm(key).decrypt(nonce, ciphertext + tag, None)
    return plain, {
        "version": LEGACY_VERSION,
        "content_type": content_type,
        "has_password": has_password,
        "filename": filename,
    }


def _decrypt_chunked(packet: bytes, password: str) -> Tuple[bytes, Dict[str, object]]:
    if len(packet) < _V2_FIXED.size:
        raise CSYXFormatError("分块加密文件头不完整")
    (
        magic, version, content_type, flags, reserved, chunk_size, plain_size,
        chunk_count, salt, nonce_prefix, metadata_len,
    ) = _V2_FIXED.unpack_from(packet)
    if magic != MAGIC or version not in (COMPAT_VERSION, VERSION) or reserved != 0:
        raise CSYXFormatError("分块加密文件头无效")
    if flags & ~1:
        raise CSYXFormatError("分块加密标志位无效")
    if bool(flags & 1) != bool(password):
        raise CSYXFormatError("密码设置不匹配（加密时有密码/无密码）")
    if not 64 * 1024 <= chunk_size <= 64 * 1024 * 1024:
        raise CSYXFormatError("分块大小无效")
    expected_count = max(1, (plain_size + chunk_size - 1) // chunk_size)
    if chunk_count != expected_count or metadata_len > _MAX_METADATA_SIZE:
        raise CSYXFormatError("分块加密长度字段无效")
    meta_start = _V2_FIXED.size
    meta_end = meta_start + metadata_len
    if meta_end > len(packet):
        raise CSYXFormatError("分块加密元数据不完整")
    header = packet[:meta_end]
    try:
        metadata = json.loads(packet[meta_start:meta_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CSYXFormatError("分块加密元数据无效") from exc
    if not isinstance(metadata, dict) or metadata.get("size") != plain_size:
        raise CSYXFormatError("分块加密元数据长度与文件头不一致")

    derive_key = _derive_key_v2 if version == COMPAT_VERSION else _derive_key_v3
    aesgcm = _new_aesgcm(derive_key(password, salt))
    output = bytearray()
    pos = meta_end
    for index in range(chunk_count):
        if pos + 4 > len(packet):
            raise CSYXFormatError("加密块不完整")
        plain_len = struct.unpack_from(">I", packet, pos)[0]
        pos += 4
        expected_len = min(chunk_size, plain_size - len(output))
        if plain_size == 0:
            expected_len = 0
        if plain_len != expected_len or pos + plain_len + TAG_SIZE > len(packet):
            raise CSYXFormatError("加密块长度无效")
        encrypted = packet[pos:pos + plain_len + TAG_SIZE]
        pos += plain_len + TAG_SIZE
        nonce = nonce_prefix + struct.pack(">I", index)
        aad = header + struct.pack(">I", index)
        output.extend(aesgcm.decrypt(nonce, encrypted, aad))
    if pos != len(packet) or len(output) != plain_size:
        raise CSYXFormatError("分块加密文件尾或总长度无效")
    metadata.update({
        "version": version,
        "content_type": content_type,
        "has_password": bool(flags & 1),
    })
    return bytes(output), metadata


def decrypt_data_with_metadata(data: bytes, password: str = "") -> Tuple[bytes, Dict[str, object]]:
    packet_offset = png_end_offset(data)
    if packet_offset >= len(data):
        raise CSYXFormatError("文件没有加密数据")
    packet = data[packet_offset:]
    if len(packet) < 9 or packet[:8] != MAGIC:
        raise CSYXFormatError("不是 CSYX 加密文件")
    if packet[8] == LEGACY_VERSION:
        return _decrypt_v1(packet, password)
    if packet[8] in (COMPAT_VERSION, VERSION):
        return _decrypt_chunked(packet, password)
    raise CSYXFormatError(f"不支持的 CSYX 版本：{packet[8]}")


def decrypt_data(data: bytes, password: str = "") -> bytes:
    plain, _ = decrypt_data_with_metadata(data, password)
    return plain
