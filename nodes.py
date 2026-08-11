"""ComfyUI 节点 - B站-此生已陷-内容加密。"""

from __future__ import annotations

import io
import mimetypes
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import wave

import numpy as np

from .encrypt_core import (
    CONTENT_AUDIO,
    CONTENT_FILE,
    CONTENT_IMAGE,
    CONTENT_TEXT,
    CONTENT_VIDEO,
    encrypt_stream,
    has_fast_crypto,
)


try:
    import folder_paths
except ImportError:
    folder_paths = None


_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_MODULE_PARENT = os.path.dirname(_MODULE_DIR)
_FALLBACK_ROOT = (
    os.path.dirname(_MODULE_PARENT)
    if os.path.basename(_MODULE_PARENT).lower() == "custom_nodes"
    else _MODULE_PARENT
)
_NAME_LOCK = threading.Lock()
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _output_dir() -> str:
    path = (
        folder_paths.get_output_directory()
        if folder_paths is not None
        else os.path.join(_FALLBACK_ROOT, "output")
    )
    os.makedirs(path, exist_ok=True)
    return path


def _temp_dir() -> str:
    path = (
        folder_paths.get_temp_directory()
        if folder_paths is not None
        else os.path.join(_FALLBACK_ROOT, "temp")
    )
    os.makedirs(path, exist_ok=True)
    return path


def _input_dir() -> str:
    path = (
        folder_paths.get_input_directory()
        if folder_paths is not None
        else os.path.join(_FALLBACK_ROOT, "input")
    )
    os.makedirs(path, exist_ok=True)
    return os.path.realpath(path)


def _input_files() -> list[str]:
    root = _input_dir()
    files = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(current, name))]
        for name in names:
            candidate = os.path.realpath(os.path.join(current, name))
            try:
                if os.path.commonpath((root, candidate)) != root or not os.path.isfile(candidate):
                    continue
            except ValueError:
                continue
            files.append(os.path.relpath(candidate, root).replace(os.sep, "/"))
    return sorted(files, key=str.casefold) or ["未找到输入文件"]


def _resolve_input_file(relative_name: str) -> str:
    value = (relative_name or "").strip().replace("\\", "/")
    if not value or value == "未找到输入文件" or os.path.isabs(value):
        raise ValueError("请选择 ComfyUI input 目录中的文件")
    root = _input_dir()
    candidate = os.path.realpath(os.path.join(root, value.replace("/", os.sep)))
    try:
        inside = os.path.commonpath((root, candidate)) == root
    except ValueError:
        inside = False
    if not inside or not os.path.isfile(candidate):
        raise ValueError("文件不存在或超出 ComfyUI input 目录")
    return candidate


def _ensure_fast_crypto() -> None:
    if not has_fast_crypto():
        raise RuntimeError(
            "缺少高速加密库 cryptography。请在此节点目录执行 "
            "pip install -r requirements.txt，然后重启 ComfyUI。"
        )


def _safe_base(name: str, fallback: str) -> str:
    value = (name or "").strip()
    if value.lower().endswith(".png"):
        value = value[:-4]
    value = os.path.basename(value.replace("\\", "/"))
    value = "".join(ch for ch in value if ch >= " " and ch not in '\\/:*?"<>|')
    value = value.rstrip(". ")[:180]
    if not value:
        value = fallback
    if value.upper() in _WINDOWS_RESERVED:
        value = f"_{value}"
    return value


def _reserve_output(prefix: str, requested_name: str = ""):
    output_dir = _output_dir()
    base = _safe_base(requested_name, prefix)
    has_requested_name = bool((requested_name or "").strip())
    with _NAME_LOCK:
        index = 0
        while True:
            if has_requested_name:
                filename = f"{base}.png" if index == 0 else f"{base}_{index}.png"
            else:
                filename = f"{base}_{index + 1:05d}.png"
            final_path = os.path.join(output_dir, filename)
            try:
                fd = os.open(final_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except FileExistsError:
                index += 1
    return final_path, {
        "filename": filename,
        "subfolder": "",
        "type": "output",
    }


def _save_encrypted_stream(
    source,
    source_size: int,
    content_type: int,
    password: str,
    original_filename: str,
    mime_type: str,
    prefix: str,
    requested_name: str,
):
    _ensure_fast_crypto()
    final_path, descriptor = _reserve_output(prefix, requested_name)
    temp_fd, temp_path = tempfile.mkstemp(
        prefix="._csyx_", suffix=".tmp", dir=os.path.dirname(final_path)
    )
    started = time.perf_counter()
    try:
        with os.fdopen(temp_fd, "wb") as destination:
            encrypt_stream(
                source=source,
                destination=destination,
                content_type=content_type,
                password=password,
                original_filename=original_filename,
                mime_type=mime_type,
                source_size=source_size,
            )
            destination.flush()
        os.replace(temp_path, final_path)
    except Exception:
        try:
            os.close(temp_fd)
        except OSError:
            pass
        for path in (temp_path, final_path):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        raise
    elapsed = time.perf_counter() - started
    size_mib = source_size / (1024 * 1024)
    print(f"[CSYX] 已加密 {size_mib:.2f} MiB，用时 {elapsed:.3f} 秒")
    return descriptor


def _ui_result(descriptors):
    # csyx_image 保留字符串格式，避免新版资产扫描重复登记同一描述符。
    return {
        "ui": {
            "images": descriptors,
            "csyx_image": [item["filename"] for item in descriptors],
            "csyx_mode": ["encrypt"],
        }
    }


def _remove_created_outputs(descriptors) -> None:
    output_root = os.path.realpath(_output_dir())
    for descriptor in descriptors:
        candidate = os.path.realpath(os.path.join(
            output_root, descriptor.get("subfolder", ""), descriptor["filename"]
        ))
        try:
            if os.path.commonpath([output_root, candidate]) == output_root:
                os.remove(candidate)
        except (FileNotFoundError, OSError, ValueError):
            pass


def _tensor_frame_to_png(frame) -> io.BytesIO:
    from PIL import Image

    array = frame.detach().cpu().numpy() if hasattr(frame, "detach") else frame.cpu().numpy()
    array = np.nan_to_num(array, nan=0.0, posinf=1.0, neginf=0.0)
    array = (array * 255.0).clip(0, 255).astype(np.uint8)
    if array.ndim == 2:
        image = Image.fromarray(array, mode="L")
    elif array.ndim == 3 and array.shape[2] == 1:
        image = Image.fromarray(array[:, :, 0], mode="L")
    elif array.ndim == 3 and array.shape[2] == 4:
        image = Image.fromarray(array, mode="RGBA")
    elif array.ndim == 3 and array.shape[2] >= 3:
        image = Image.fromarray(array[:, :, :3], mode="RGB")
    else:
        raise ValueError(f"不支持的图片形状：{array.shape}")
    stream = io.BytesIO()
    image.save(stream, format="PNG", compress_level=4, optimize=False)
    stream.seek(0)
    return stream


def _write_wav(audio_data, filepath: str) -> None:
    waveform = audio_data["waveform"]
    sample_rate = int(audio_data["sample_rate"])
    if len(waveform.shape) == 3:
        waveform = waveform[0]
    if len(waveform.shape) != 2:
        raise ValueError(f"不支持的音频形状：{tuple(waveform.shape)}")
    channels, samples = int(waveform.shape[0]), int(waveform.shape[1])
    if channels < 1 or channels > 32:
        raise ValueError(f"不支持的音频声道数：{channels}")
    block_samples = 262144
    with wave.open(filepath, "wb") as output:
        output.setnchannels(channels)
        output.setsampwidth(2)
        output.setframerate(sample_rate)
        for start in range(0, samples, block_samples):
            block = waveform[:, start:start + block_samples]
            if hasattr(block, "detach"):
                block = block.detach()
            array = block.cpu().numpy()
            interleaved = (
                np.nan_to_num(array, nan=0.0, posinf=1.0, neginf=-1.0)
                .clip(-1.0, 1.0)
                .T.reshape(-1)
            )
            pcm = (interleaved * 32767.0).clip(-32768, 32767).astype("<i2")
            output.writeframesraw(pcm.tobytes())


def _ffmpeg_executable() -> str:
    executable = shutil.which("ffmpeg")
    if not executable:
        raise RuntimeError("未找到 FFmpeg。请在云端镜像或本地环境安装 FFmpeg 并加入 PATH。")
    return executable


def _encode_video(image_tensor, fps: float, audio_data, output_path: str) -> float:
    frame_count = int(image_tensor.shape[0])
    height = int(image_tensor.shape[1])
    width = int(image_tensor.shape[2])
    channels = int(image_tensor.shape[3]) if len(image_tensor.shape) > 3 else 1
    if frame_count < 1 or width < 1 or height < 1:
        raise ValueError("视频输入没有有效帧")

    audio_path = None
    if audio_data is not None:
        audio_fd, audio_path = tempfile.mkstemp(suffix=".wav", dir=_temp_dir())
        os.close(audio_fd)
        try:
            _write_wav(audio_data, audio_path)
        except Exception:
            try:
                os.remove(audio_path)
            except OSError:
                pass
            raise

    command = [
        _ffmpeg_executable(), "-hide_banner", "-loglevel", "error", "-y",
        "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{width}x{height}",
        "-r", str(float(fps)), "-i", "pipe:0",
    ]
    if audio_path:
        command += ["-i", audio_path]
    command += [
        "-c:v", "libx264", "-preset", "ultrafast", "-crf", "28",
        "-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2", "-pix_fmt", "yuv420p",
    ]
    if audio_path:
        command += ["-c:a", "aac", "-b:a", "128k", "-shortest"]
    command += ["-movflags", "+faststart", output_path]

    popen_kwargs = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    started = time.perf_counter()
    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except Exception:
        if audio_path:
            try:
                os.remove(audio_path)
            except OSError:
                pass
        raise
    stderr_tail = bytearray()

    def drain_stderr():
        try:
            while True:
                chunk = process.stderr.read(4096)
                if not chunk:
                    break
                stderr_tail.extend(chunk)
                if len(stderr_tail) > 65536:
                    del stderr_tail[:-65536]
        except Exception:
            pass

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    stderr_thread.start()
    write_error = None
    try:
        for index in range(frame_count):
            frame = image_tensor[index]
            if hasattr(frame, "detach"):
                frame = frame.detach()
            array = frame.cpu().numpy()
            array = np.nan_to_num(array, nan=0.0, posinf=1.0, neginf=0.0)
            array = (array * 255.0).clip(0, 255).astype(np.uint8)
            if array.ndim == 2:
                array = np.repeat(array[:, :, None], 3, axis=2)
            elif channels == 1 or array.shape[2] == 1:
                array = np.repeat(array[:, :, :1], 3, axis=2)
            else:
                array = array[:, :, :3]
            try:
                process.stdin.write(np.ascontiguousarray(array).tobytes())
            except (BrokenPipeError, OSError) as exc:
                write_error = exc
                break
    finally:
        try:
            process.stdin.close()
        except Exception:
            pass

    try:
        process.wait(timeout=300)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise RuntimeError("FFmpeg 编码超过 300 秒，已停止") from exc
    finally:
        stderr_thread.join(timeout=5)
        try:
            process.stderr.close()
        except Exception:
            pass
        if audio_path:
            try:
                os.remove(audio_path)
            except OSError:
                pass

    if process.returncode != 0:
        detail = stderr_tail.decode("utf-8", errors="replace").strip()[-2000:]
        if write_error:
            detail = f"{detail}\n写入视频帧失败：{write_error}".strip()
        raise RuntimeError(f"FFmpeg 编码失败：{detail or '未知错误'}")
    elapsed = time.perf_counter() - started
    print(f"[CSYX] FFmpeg 编码 {frame_count} 帧，用时 {elapsed:.3f} 秒")
    return elapsed


class ImageEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {"图片": ("IMAGE",)},
            "optional": {
                "密码": ("STRING", {"default": "", "multiline": False}),
                "文件名": ("STRING", {"default": "", "multiline": False}),
            },
        }

    RETURN_TYPES = ()
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-内容加密"
    OUTPUT_NODE = True

    def encrypt(self, 图片, 密码="", 文件名=""):
        descriptors = []
        count = int(图片.shape[0])
        try:
            for index in range(count):
                stream = _tensor_frame_to_png(图片[index])
                requested = f"{文件名}_{index + 1}" if 文件名 and count > 1 else 文件名
                try:
                    descriptors.append(_save_encrypted_stream(
                        stream, stream.getbuffer().nbytes, CONTENT_IMAGE, 密码,
                        f"image_{index + 1}.png" if count > 1 else "image.png",
                        "image/png", "encrypted_image", requested,
                    ))
                finally:
                    stream.close()
        except Exception:
            _remove_created_outputs(descriptors)
            raise
        return _ui_result(descriptors)


class VideoEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "图像": ("IMAGE",),
                "帧率": ("FLOAT", {"default": 16.0, "min": 1.0, "max": 120.0, "step": 0.01}),
            },
            "optional": {
                "音频": ("AUDIO",),
                "密码": ("STRING", {"default": "", "multiline": False}),
                "文件名": ("STRING", {"default": "", "multiline": False}),
            },
            "hidden": {"unique_id": "UNIQUE_ID"},
        }

    RETURN_TYPES = ()
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-内容加密"
    OUTPUT_NODE = True

    def encrypt(self, 图像, 帧率=16.0, 音频=None, 密码="", 文件名="", unique_id=None):
        _ensure_fast_crypto()
        fd, video_path = tempfile.mkstemp(suffix=".mp4", dir=_temp_dir())
        os.close(fd)
        try:
            _encode_video(图像, 帧率, 音频, video_path)
            with open(video_path, "rb") as source:
                descriptor = _save_encrypted_stream(
                    source, os.path.getsize(video_path), CONTENT_VIDEO, 密码,
                    "video.mp4", "video/mp4", "encrypted_video", 文件名,
                )
        finally:
            try:
                os.remove(video_path)
            except OSError:
                pass
        return _ui_result([descriptor])


class TextEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {"文字内容": ("STRING", {"default": "", "multiline": True})},
            "optional": {
                "密码": ("STRING", {"default": "", "multiline": False}),
                "文件名": ("STRING", {"default": "", "multiline": False}),
            },
        }

    RETURN_TYPES = ()
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-内容加密"
    OUTPUT_NODE = True

    def encrypt(self, 文字内容, 密码="", 文件名=""):
        data = 文字内容.encode("utf-8")
        source = io.BytesIO(data)
        descriptor = _save_encrypted_stream(
            source, len(data), CONTENT_TEXT, 密码, "text.txt", "text/plain;charset=utf-8",
            "encrypted_text", 文件名,
        )
        return _ui_result([descriptor])


class AudioEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {"音频": ("AUDIO",)},
            "optional": {
                "密码": ("STRING", {"default": "", "multiline": False}),
                "文件名": ("STRING", {"default": "", "multiline": False}),
            },
            "hidden": {"unique_id": "UNIQUE_ID"},
        }

    RETURN_TYPES = ()
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-内容加密"
    OUTPUT_NODE = True

    def encrypt(self, 音频, 密码="", 文件名="", unique_id=None):
        _ensure_fast_crypto()
        fd, wav_path = tempfile.mkstemp(suffix=".wav", dir=_temp_dir())
        os.close(fd)
        try:
            _write_wav(音频, wav_path)
            with open(wav_path, "rb") as source:
                descriptor = _save_encrypted_stream(
                    source, os.path.getsize(wav_path), CONTENT_AUDIO, 密码,
                    "audio.wav", "audio/wav", "encrypted_audio", 文件名,
                )
        finally:
            try:
                os.remove(wav_path)
            except OSError:
                pass
        return _ui_result([descriptor])


class FileEncryptNode:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {"文件路径": (_input_files(), {"image_upload": False})},
            "optional": {
                "密码": ("STRING", {"default": "", "multiline": False}),
                "文件名": ("STRING", {"default": "", "multiline": False}),
            },
        }

    RETURN_TYPES = ()
    FUNCTION = "encrypt"
    CATEGORY = "B站-此生已陷-内容加密"
    OUTPUT_NODE = True

    @classmethod
    def VALIDATE_INPUTS(cls, **kwargs):
        # 文件列表会随上传变化；真正的路径边界在执行时校验。
        return True

    def encrypt(self, 文件路径, 密码="", 文件名=""):
        expanded = _resolve_input_file(文件路径)
        mime_type = mimetypes.guess_type(expanded)[0] or "application/octet-stream"
        with open(expanded, "rb") as source:
            descriptor = _save_encrypted_stream(
                source, os.path.getsize(expanded), CONTENT_FILE, 密码,
                os.path.basename(expanded), mime_type, "encrypted_file", 文件名,
            )
        return _ui_result([descriptor])


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
