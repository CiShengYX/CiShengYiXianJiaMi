"""
ComfyUI 节点 - B站-此生已陷-数据加密
优化版本：硬件编码、帧批处理、预加载
"""
import os, sys, struct, threading, tempfile, subprocess
import numpy as np
import torch

from .encrypt_core import (
    encrypt_data, CONTENT_IMAGE, CONTENT_VIDEO, CONTENT_TEXT,
    CONTENT_AUDIO, CONTENT_FILE, MAGIC,
    _AESCipher, _ghash, _gcm_ctr, _derive_key
)

# ============================================================
# 预加载（在 FFmpeg 编码期间后台完成）
# ============================================================
def _prewarm_encryption():
    try:
        from .encrypt_core import _get_clean_cover_png, _get_aes_encrypt_func
        _get_clean_cover_png()
        _get_aes_encrypt_func()
    except Exception:
        pass


# ============================================================
# 通用工具
# ============================================================
def _read_file_bytes(fp):
    with open(fp, "rb") as f:
        return f.read()


def _get_aes_decrypt_func():
    for mod_name, cls_name in [
        ("Crypto.Cipher", "AES"),
        ("cryptography.hazmat.primitives.ciphers.aead", "AESGCM"),
    ]:
        try:
            mod = __import__(mod_name, fromlist=[cls_name])
            cls = getattr(mod, cls_name)
            if mod_name == "Crypto.Cipher":
                def _pycrypto_decrypt(key, iv, ct_tag):
                    cipher = cls.new(key, cls.MODE_GCM, nonce=iv)
                    tag = ct_tag[-16:]
                    ct = ct_tag[:-16]
                    return cipher.decrypt_and_verify(ct, tag)
                return _pycrypto_decrypt
            else:
                def _cryptography_decrypt(key, iv, ct_tag):
                    aesgcm = cls(key)
                    return aesgcm.decrypt(iv, ct_tag, None)
                return _cryptography_decrypt
        except ImportError:
            continue
    return _pure_python_aes_gcm_decrypt


def _pure_python_aes_gcm_decrypt(key, iv, ciphertext_with_tag):
    """纯 Python AES-256-GCM 解密（仅在没有 pycryptodome/cryptography 时使用）"""
    aes = _AESCipher(key)
    H = aes.encrypt_block(b'\x00' * 16)
    J0 = iv + b'\x00\x00\x00\x01'
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    plaintext = _gcm_ctr(aes, J0, ciphertext)
    S = _ghash(H, b'', ciphertext)
    ej0 = aes.encrypt_block(J0)
    expected_tag = bytes(a ^ b for a, b in zip(S, ej0))
    if expected_tag != tag:
        raise ValueError("解密失败：标签验证未通过（可能密钥错误或文件损坏）")
    return plaintext


def decrypt_data(data, password=""):
    """解密 CSYX 加密数据（与网页版兼容，不可修改格式）

    二进制包格式（encrypt_data 输出）：
      MAGIC(8) | VERSION(1) | content_type(1) | has_password(1) |
      salt(16) | iv(12) | tag(16) | fn_len(2) | filename(fn_len) |
      ct_len(8) | ciphertext(ct_len)
    """
    if len(data) < 8 or data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError("不是有效的 PNG 文件")

    pos = data.find(b"IEND")
    if pos < 0:
        raise ValueError("未找到 IEND 标记")
    # IEND chunk: 4 bytes 'IEND' + 4 bytes CRC
    end = pos + 8

    if end >= len(data):
        raise ValueError("文件格式不完整")

    pkt = data[end:]
    if len(pkt) < 57:
        raise ValueError("加密数据块太小")

    if pkt[:8] != MAGIC:
        raise ValueError("不是 CSYX 加密文件")

    content_type = pkt[9]
    has_password = 1 if password else 0
    has_pass_flag = pkt[10]

    if has_pass_flag != has_password:
        raise ValueError("密码设置不匹配（该文件可能需要/不需要密码）")

    salt = pkt[11:27]
    iv = pkt[27:39]
    tag = pkt[39:55]

    fn_len = struct.unpack(">H", pkt[55:57])[0]
    orig_fn = pkt[57:57 + fn_len].decode("utf-8", errors="replace")

    ct_len_offset = 57 + fn_len
    ct_len = struct.unpack(">Q", pkt[ct_len_offset:ct_len_offset + 8])[0]
    ct_offset = ct_len_offset + 8
    ct = pkt[ct_offset:ct_offset + ct_len]

    aes_decrypt = _get_aes_decrypt_func()
    pwd = password if password else "CSYX_DEFAULT_KEY"
    key = _derive_key(pwd, salt)
    plain = aes_decrypt(key, iv, ct + tag)
    return plain


# ============================================================
# OUTPUT / TEMP 目录
# ============================================================
OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "output"
)

try:
    import folder_paths
    TEMP_DIR = folder_paths.get_temp_directory()
except Exception:
    TEMP_DIR = os.path.join(os.path.dirname(OUTPUT_DIR), "temp")


# ============================================================
# 保存
# ============================================================
def _save(data, prefix, name="", ext=".png", target_dir=None):
    d = target_dir or OUTPUT_DIR
    os.makedirs(d, exist_ok=True)
    base = name.strip().lower().replace(" ", "_") or prefix
    if not base.endswith(ext):
        base += ext

    fn = os.path.join(d, base)
    if os.path.exists(fn):
        existing = {n.lower() for n in os.listdir(d)}
        i = 1
        while base.lower() in existing:
            base = f"{prefix}_{i:05d}{ext}"
            i += 1
        fn = os.path.join(d, base)

    with open(fn, "wb") as f:
        f.write(data)
    return os.path.basename(fn)


# ============================================================
# Tensor → PNG（用于图片加密节点）
# ============================================================
def _tensor_to_png(t):
    import zlib
    img = (t.cpu().numpy() * 255).clip(0, 255).astype(np.uint8)
    a, h, w, c = img.shape
    ct = {4: 6, 3: 2, 1: 0}.get(c, 2)

    # 构建扫描线（filter byte 0 + 像素数据），单条 zlib 流压缩
    raw = bytearray()
    img_hwc = img[0]  # (H, W, C)
    for y in range(h):
        raw.append(0)  # filter: None
        raw.extend(img_hwc[y].tobytes())  # row pixels: R,G,B or R,G,B,A or Gray
    compressed = zlib.compress(bytes(raw))

    def _chunk(chunk_type, data):
        """构建带 CRC32 的 PNG 块"""
        chunk = chunk_type + data
        return struct.pack(">I", len(data)) + chunk + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)

    png = bytearray(b'\x89PNG\r\n\x1a\n')
    png.extend(_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, ct, 0, 0, 0)))
    png.extend(_chunk(b"IDAT", compressed))
    png.extend(_chunk(b"IEND", b""))
    return bytes(png)


# ============================================================
# 音频编码
# ============================================================
def _save_wav(audio_data, fp):
    waveform_key = "waveform" if hasattr(audio_data, "get") else None
    if waveform_key:
        wf = audio_data[waveform_key]
        sr = audio_data.get("sample_rate", 16000)
    else:
        wf = audio_data
        sr = 16000

    a = wf.cpu().numpy()
    if a.ndim == 3 and a.shape[0] == 1:
        a = a[0]
    ch = a.shape[0] if a.ndim == 2 else 1
    ns = a.shape[-1]

    a16 = (a.clip(-1, 1) * 32767).astype(np.int16)

    # 多声道交织：PyTorch tensor (channels, samples) → WAV interleaved (s0_c0, s0_c1, s1_c0, ...)
    if ch > 1:
        il = np.zeros(ns * ch, dtype=np.int16)
        for c in range(ch):
            il[c::ch] = a16[c]
    else:
        il = a16

    with open(fp, "wb") as f:
        dsz = ns * ch * 2
        f.write(b"RIFF")
        f.write(struct.pack("<I", 36 + dsz))
        f.write(b"WAVEfmt ")
        f.write(struct.pack("<I", 16))
        f.write(struct.pack("<H", 1))
        f.write(struct.pack("<H", ch))
        f.write(struct.pack("<I", sr))
        f.write(struct.pack("<I", sr * ch * 2))
        f.write(struct.pack("<H", ch * 2))
        f.write(struct.pack("<H", 16))
        f.write(b"data")
        f.write(struct.pack("<I", dsz))
        f.write(il.astype(np.int16).tobytes())


def _wav_bytes(audio_data):
    fd, tp = tempfile.mkstemp(suffix=".wav")
    os.close(fd)
    try:
        _save_wav(audio_data, tp)
        with open(tp, "rb") as f:
            return f.read()
    finally:
        os.unlink(tp)


def _save_temp(data, name):
    os.makedirs(TEMP_DIR, exist_ok=True)
    with open(os.path.join(TEMP_DIR, name), "wb") as f:
        f.write(data)


# ============================================================
# 视频编码（优化版）
# ============================================================
def _video_bytes(image_tensor, fps, audio_data=None):
    """帧张量+音频 → MP4 字节（硬件编码优先 + 批量写入）"""
    n, h, w = image_tensor.shape[0], image_tensor.shape[1], image_tensor.shape[2]

    # 预处理帧数据（只做一次）
    frames_np = (image_tensor.cpu().numpy() * 255).clip(0, 255).astype(np.uint8)

    # 准备临时目录
    td = tempfile.mkdtemp()
    has_audio = audio_data is not None
    if has_audio:
        af = os.path.join(td, "a.wav")
        _save_wav(audio_data, af)

    def _cleanup():
        import shutil
        shutil.rmtree(td, ignore_errors=True)

    # 统一用临时文件输出（兼容所有系统和编码器）
    out_file = os.path.join(td, "o.mp4")

    # 统一 libx264 软件编码（云端 NVENC 库依赖问题不稳定，直接软编最快最可靠）
    encoder_configs = [
        ("libx264", ["-preset", "ultrafast", "-crf", "28",
         "-tune", "zerolatency", "-bf", "0", "-refs", "1",
         "-sc_threshold", "0", "-g", "99999"], "libx264"),
    ]

    last_error = None
    for enc_name, enc_args, enc_label in encoder_configs:
        cmd = [
            "ffmpeg", "-y",
            "-f", "rawvideo", "-pix_fmt", "rgb24",
            "-s", f"{w}x{h}", "-r", str(fps), "-i", "pipe:0",
        ]
        if has_audio:
            cmd.extend(["-i", af])
        cmd.extend(["-c:v", enc_name, *enc_args])
        if has_audio:
            cmd.extend(["-c:a", "aac", "-b:a", "128k", "-shortest"])
        cmd.extend(["-pix_fmt", "yuv420p", "-f", "mp4", out_file])

        # 启动 FFmpeg
        popen_kw = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.PIPE,
        }
        if sys.platform == "win32":
            popen_kw["creationflags"] = subprocess.CREATE_NO_WINDOW
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            popen_kw["startupinfo"] = si

        try:
            proc = subprocess.Popen(cmd, **popen_kw)
        except FileNotFoundError:
            _cleanup()
            raise RuntimeError("未找到 ffmpeg，请确认已安装并加入 PATH")

        # stderr 读取线程
        stderr_chunks = []
        def _drain_stderr():
            try:
                for chunk in iter(lambda: proc.stderr.read(4096), b""):
                    stderr_chunks.append(chunk)
            except Exception:
                pass
        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        # 批量写入帧
        write_error = None
        frame_bytes = w * h * 3
        batch_frames = max(1, min(30, (256 * 1024 * 1024) // max(frame_bytes, 1)))
        try:
            for batch_start in range(0, n, batch_frames):
                batch_end = min(batch_start + batch_frames, n)
                batch = bytearray()
                for i in range(batch_start, batch_end):
                    batch.extend(np.ascontiguousarray(frames_np[i]).tobytes())
                proc.stdin.write(bytes(batch))
        except (BrokenPipeError, OSError) as e:
            write_error = e

        try:
            proc.stdin.close()
        except Exception:
            pass

        try:
            proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            stderr_thread.join(timeout=5)
            last_error = RuntimeError(f"ffmpeg 编码超时 ({enc_label})")
            continue
        except Exception:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            stderr_thread.join(timeout=5)
            raise

        stderr_thread.join(timeout=5)

        if proc.returncode != 0:
            stderr_output = b"".join(stderr_chunks)
            err = stderr_output.decode("utf-8", errors="replace")[:500] if stderr_output else "unknown"
            if write_error:
                err += f" (写入中断: {write_error})"
            last_error = RuntimeError(f"ffmpeg 编码失败 ({enc_label}): {err}")
            continue

        # 成功 — 读取临时文件
        with open(out_file, "rb") as f:
            mp4_bytes = f.read()
        _cleanup()
        return mp4_bytes

    _cleanup()
    raise last_error or RuntimeError("ffmpeg 编码失败：未知错误")


# ============================================================
# ComfyUI 节点类
# ============================================================
class ImageEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "图片": ("IMAGE",),
                "密码": ("STRING", {"default": ""}),
                "文件名": ("STRING", {"default": ""}),
            }
        }

    RETURN_TYPES = ("STRING",)
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-数据加密"
    OUTPUT_NODE = True

    def encrypt(self, 图片, 密码="", 文件名="", unique_id=None):
        png_data = _tensor_to_png(图片)
        enc = encrypt_data(png_data, CONTENT_IMAGE, 密码, 文件名 or "image.png")
        fn = _save(enc, "encrypted_image", 文件名, ".png")
        return {"ui": {"csyx_image": [fn], "csyx_mode": ["encrypt"]}, "result": (fn,)}


class VideoEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "图像": ("IMAGE",),
                "帧率": ("FLOAT", {"default": 16.0, "min": 1, "max": 120}),
                "音频": ("AUDIO",),
                "密码": ("STRING", {"default": ""}),
                "文件名": ("STRING", {"default": ""}),
            }
        }

    RETURN_TYPES = ("STRING",)
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-数据加密"
    OUTPUT_NODE = True

    def encrypt(self, 图像, 帧率=16.0, 音频=None, 密码="", 文件名="", unique_id=None):
        prewarm_done = threading.Event()

        def prewarm():
            try:
                _prewarm_encryption()
            finally:
                prewarm_done.set()

        prewarm_thread = threading.Thread(target=prewarm, daemon=True)
        prewarm_thread.start()

        vb = _video_bytes(图像, 帧率, 音频)
        prewarm_done.wait(timeout=0.5)
        enc = encrypt_data(vb, CONTENT_VIDEO, 密码, 文件名 or "video.mp4")
        fn = _save(enc, "encrypted_video", 文件名, ".png")
        return {"ui": {"csyx_image": [fn], "csyx_mode": ["encrypt"]}, "result": (fn,)}


class TextEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "文本": ("STRING", {"multiline": True}),
                "密码": ("STRING", {"default": ""}),
                "文件名": ("STRING", {"default": ""}),
            }
        }

    RETURN_TYPES = ("STRING",)
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-数据加密"
    OUTPUT_NODE = True

    def encrypt(self, 文本, 密码="", 文件名="", unique_id=None):
        data = 文本.encode("utf-8")
        enc = encrypt_data(data, CONTENT_TEXT, 密码, 文件名 or "text.txt")
        fn = _save(enc, "encrypted_text", 文件名, ".png")
        return {"ui": {"csyx_image": [fn], "csyx_mode": ["encrypt"]}, "result": (fn,)}


class AudioEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "音频": ("AUDIO",),
                "密码": ("STRING", {"default": ""}),
                "文件名": ("STRING", {"default": ""}),
            }
        }

    RETURN_TYPES = ("STRING",)
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-数据加密"
    OUTPUT_NODE = True

    def encrypt(self, 音频, 密码="", 文件名="", unique_id=None):
        wav_data = _wav_bytes(音频)
        enc = encrypt_data(wav_data, CONTENT_AUDIO, 密码, 文件名 or "audio.wav")
        fn = _save(enc, "encrypted_audio", 文件名, ".png")
        return {"ui": {"csyx_image": [fn], "csyx_mode": ["encrypt"]}, "result": (fn,)}


class FileEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "文件路径": ("STRING", {"default": ""}),
                "密码": ("STRING", {"default": ""}),
                "文件名": ("STRING", {"default": ""}),
            }
        }

    RETURN_TYPES = ("STRING",)
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-数据加密"
    OUTPUT_NODE = True

    def encrypt(self, 文件路径, 密码="", 文件名="", unique_id=None):
        if not 文件路径 or not os.path.exists(文件路径):
            raise ValueError(f"文件不存在: {文件路径}")
        data = _read_file_bytes(文件路径)
        fn_base = 文件名 or os.path.basename(文件路径)
        enc = encrypt_data(data, CONTENT_FILE, 密码, fn_base)
        fn = _save(enc, "encrypted_file", 文件名, ".png")
        return {"ui": {"csyx_image": [fn], "csyx_mode": ["encrypt"]}, "result": (fn,)}


# ============================================================
# ComfyUI 注册
# ============================================================
NODE_CLASS_MAPPINGS = {
    "CSYX_ImageEncrypt": ImageEncryptNode,
    "CSYX_VideoEncrypt": VideoEncryptNode,
    "CSYX_TextEncrypt": TextEncryptNode,
    "CSYX_AudioEncrypt": AudioEncryptNode,
    "CSYX_FileEncrypt": FileEncryptNode,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "CSYX_ImageEncrypt": "B站-此生已陷-图片加密",
    "CSYX_VideoEncrypt": "B站-此生已陷-视频加密",
    "CSYX_TextEncrypt": "B站-此生已陷-文字加密",
    "CSYX_AudioEncrypt": "B站-此生已陷-音频加密",
    "CSYX_FileEncrypt": "B站-此生已陷-文件加密",
}
