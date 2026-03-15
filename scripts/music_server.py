#!/usr/bin/env python3
"""
Standalone music conversion HTTP server for BDFFHD mod.

Listens on port 8889 and accepts audio file uploads (MP3, WAV, OGG, FLAC).
Converts them to HCA format using ffmpeg + PyCriCodecs, then saves the result
to the game's CustomBGM directory.

The browser UI at :8888 sends upload requests directly here via CORS-enabled
fetch, so there's no multipart parsing needed inside Wine/.NET.

Usage:
    uv run python scripts/music_server.py
    # or
    ./scripts/start_music_server.sh

Environment variables:
    BDFFHD_STREAMING_ASSETS  Override the StreamingAssets path
    MUSIC_SERVER_PORT        Override the listen port (default: 8889)
"""

import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote

# -- Configuration --

PORT = int(os.environ.get("MUSIC_SERVER_PORT", "8889"))
PROJECT_DIR = Path(__file__).resolve().parent.parent
TMP_DIR = PROJECT_DIR / "tmp"

DEFAULT_STREAMING_ASSETS = Path.home() / ".steam/debian-installation/steamapps/common/BDFFHD/BDFFHD_Data/StreamingAssets"
STREAMING_ASSETS = Path(os.environ.get("BDFFHD_STREAMING_ASSETS", str(DEFAULT_STREAMING_ASSETS)))
CUSTOM_BGM_DIR = STREAMING_ASSETS / "CustomBGM"

ALLOWED_EXTENSIONS = {".mp3", ".wav", ".ogg", ".flac", ".hca", ".m4a", ".aac", ".wma"}

# -- Conversion tracking --

_conversions: dict[str, dict] = {}
_conversions_lock = threading.Lock()

# -- Helpers --

def sanitize_filename(name: str) -> str:
    """Replace non-alphanumeric chars with hyphens, collapse duplicates."""
    base = Path(name).stem
    safe = re.sub(r"[^a-zA-Z0-9._-]", "-", base)
    safe = re.sub(r"-{2,}", "-", safe).strip("-")
    return safe or "upload"


def ensure_dirs():
    """Create temp and output directories."""
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    CUSTOM_BGM_DIR.mkdir(parents=True, exist_ok=True)


def convert_to_hca(source_path: Path, output_name: str) -> dict:
    """
    Convert an audio file to HCA.

    Steps:
      1. ffmpeg: source -> WAV (44100 Hz, stereo, 16-bit PCM, no metadata)
      2. PyCriCodecs: WAV -> HCA
      3. Copy HCA to CustomBGM/

    Returns a dict with 'success', 'path', 'size', or 'error'.
    """
    ensure_dirs()
    # Use a distinct intermediate name to avoid overwriting the source
    # (e.g., if the source is already a .wav in tmp/)
    wav_path = TMP_DIR / f"{output_name}_converted.wav"
    hca_path = TMP_DIR / f"{output_name}.hca"
    dest_path = CUSTOM_BGM_DIR / f"{output_name}.hca"

    try:
        # Step 1: Convert to WAV with ffmpeg
        cmd = [
            "ffmpeg", "-y", "-i", str(source_path),
            "-ar", "44100",
            "-ac", "2",
            "-sample_fmt", "s16",
            "-acodec", "pcm_s16le",
            "-fflags", "+bitexact",
            "-map_metadata", "-1",
            "-flags:a", "+bitexact",
            str(wav_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            stderr = result.stderr[-500:] if len(result.stderr) > 500 else result.stderr
            return {"error": f"ffmpeg failed (exit {result.returncode}): {stderr.strip()}"}

        if not wav_path.exists():
            return {"error": "ffmpeg produced no output WAV file"}

        # Step 2: Encode WAV to HCA with PyCriCodecs
        from PyCriCodecs import HCA

        h = HCA(str(wav_path))
        hca_bytes = h.encode(force_not_looping=True)

        hca_path.write_bytes(hca_bytes)

        if not hca_path.exists() or hca_path.stat().st_size == 0:
            return {"error": "HCA encoding produced empty output"}

        # Step 3: Copy to CustomBGM
        dest_path.write_bytes(hca_bytes)

        relative_path = f"CustomBGM/{output_name}.hca"
        size = dest_path.stat().st_size

        # Clean up temp files
        try:
            wav_path.unlink(missing_ok=True)
            hca_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)
        except OSError:
            pass

        return {"success": True, "path": relative_path, "size": size}

    except subprocess.TimeoutExpired:
        return {"error": "Conversion timed out (120s)"}
    except Exception as e:
        return {"error": f"Conversion error: {e}"}


def run_conversion_async(key: str, source_path: Path, output_name: str):
    """Run conversion in a background thread, updating _conversions."""
    try:
        result = convert_to_hca(source_path, output_name)
        with _conversions_lock:
            if key in _conversions:
                _conversions[key].update(result)
                _conversions[key]["done"] = True
    except Exception as e:
        with _conversions_lock:
            if key in _conversions:
                _conversions[key]["done"] = True
                _conversions[key]["error"] = str(e)


# -- HTTP Handler --

class MusicHandler(http.server.BaseHTTPRequestHandler):
    """Handle music conversion HTTP requests with CORS support."""

    def log_message(self, format, *args):
        """Override to prefix log messages."""
        print(f"[MusicServer] {args[0]}", flush=True)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_cors_headers(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self._send_cors_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._send_json({
                "service": "BDFFHD Music Conversion Server",
                "port": PORT,
                "custom_bgm_dir": str(CUSTOM_BGM_DIR),
                "endpoints": ["/convert", "/convert-status", "/convert-path", "/files"],
            })
        elif path == "/files":
            self._handle_files()
        elif path == "/convert-status":
            self._handle_convert_status()
        elif path == "/health":
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/convert":
            self._handle_convert()
        elif path == "/convert-path":
            self._handle_convert_path()
        else:
            self._send_json({"error": "Not found"}, 404)

    # -- Handlers --

    def _handle_files(self):
        """GET /files - List HCA files in CustomBGM/."""
        files = []
        try:
            if CUSTOM_BGM_DIR.exists():
                for f in sorted(CUSTOM_BGM_DIR.glob("*.hca")):
                    files.append({
                        "name": f.name,
                        "path": f"CustomBGM/{f.name}",
                        "size": f.stat().st_size,
                    })
        except Exception as e:
            return self._send_json({"error": str(e)}, 500)
        self._send_json({"files": files})

    def _handle_convert_status(self):
        """GET /convert-status?name=xxx - Poll conversion status."""
        qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        name = qs.get("name", [None])[0]
        if not name:
            return self._send_json({"done": True, "error": "Missing name parameter"})

        with _conversions_lock:
            status = _conversions.get(name)

        if status is None:
            return self._send_json({"done": True, "error": "No conversion found for this name"})

        if not status.get("done"):
            return self._send_json({"done": False})

        # Done -- return result and clean up
        result = dict(status)
        result["done"] = True
        with _conversions_lock:
            _conversions.pop(name, None)
        self._send_json(result)

    def _handle_convert(self):
        """POST /convert - Accept multipart audio file upload and convert to HCA."""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            return self._send_json({"error": "Expected multipart/form-data"}, 400)

        # Parse boundary
        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[len("boundary="):].strip('"')
                break
        if not boundary:
            return self._send_json({"error": "Could not parse multipart boundary"}, 400)

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Parse multipart to extract file
        file_name, file_data = self._parse_multipart(body, boundary)
        if not file_name or not file_data:
            return self._send_json({"error": "No file found in upload"}, 400)

        ext = Path(file_name).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return self._send_json({
                "error": f"Unsupported format '{ext}'. Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            }, 400)

        safe_base = sanitize_filename(file_name)

        # If it's already HCA, just save it
        if ext == ".hca":
            if len(file_data) < 4 or file_data[:3] != b"HCA":
                return self._send_json({"error": "File does not appear to be valid HCA (bad magic bytes)"}, 400)
            ensure_dirs()
            dest = CUSTOM_BGM_DIR / f"{safe_base}.hca"
            dest.write_bytes(file_data)
            return self._send_json({
                "success": True,
                "path": f"CustomBGM/{safe_base}.hca",
                "name": f"{safe_base}.hca",
                "size": len(file_data),
            })

        # Save source to tmp, start async conversion
        ensure_dirs()
        source_path = TMP_DIR / f"{safe_base}{ext}"
        source_path.write_bytes(file_data)

        with _conversions_lock:
            _conversions[safe_base] = {"done": False, "source": str(source_path)}

        t = threading.Thread(target=run_conversion_async, args=(safe_base, source_path, safe_base), daemon=True)
        t.start()

        return self._send_json({
            "converting": True,
            "name": safe_base,
            "source": f"{safe_base}{ext}",
        })

    def _handle_convert_path(self):
        """POST /convert-path - Convert a file from a local filesystem path."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # Parse form body (path=xxx) or JSON
        file_path = None
        content_type = self.headers.get("Content-Type", "")
        if "json" in content_type:
            try:
                data = json.loads(body)
                file_path = data.get("path")
            except json.JSONDecodeError:
                pass
        else:
            # URL-encoded form
            for pair in body.split("&"):
                parts = pair.split("=", 1)
                if len(parts) == 2 and unquote(parts[0].strip()) == "path":
                    file_path = unquote(parts[1].strip())

        if not file_path:
            return self._send_json({"error": "No path provided"}, 400)

        # Handle Wine Z:\ paths
        if file_path.startswith("Z:\\") or file_path.startswith("Z:/"):
            file_path = file_path[2:].replace("\\", "/")

        source = Path(file_path)
        if not source.exists():
            return self._send_json({"error": f"File not found: {file_path}"}, 400)

        ext = source.suffix.lower()
        name = sanitize_filename(source.name)

        if ext == ".hca":
            # Just copy
            ensure_dirs()
            dest = CUSTOM_BGM_DIR / source.name
            dest.write_bytes(source.read_bytes())
            return self._send_json({
                "success": True,
                "path": f"CustomBGM/{source.name}",
                "size": dest.stat().st_size,
            })

        if ext not in ALLOWED_EXTENSIONS:
            return self._send_json({
                "error": f"Unsupported format '{ext}'. Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            }, 400)

        with _conversions_lock:
            _conversions[name] = {"done": False, "source": str(source)}

        t = threading.Thread(target=run_conversion_async, args=(name, source, name), daemon=True)
        t.start()

        return self._send_json({
            "converting": True,
            "name": name,
        })

    # -- Multipart parser --

    @staticmethod
    def _parse_multipart(body: bytes, boundary: str) -> tuple:
        """Extract the first file from a multipart/form-data body.

        Returns (filename, file_data) or (None, None).
        """
        boundary_bytes = f"--{boundary}".encode("utf-8")
        parts = body.split(boundary_bytes)

        for part in parts:
            if not part or part == b"--\r\n" or part == b"--":
                continue

            # Split headers from body at double CRLF
            sep = part.find(b"\r\n\r\n")
            if sep < 0:
                continue

            headers_raw = part[:sep].decode("utf-8", errors="replace")
            data = part[sep + 4:]

            # Strip trailing CRLF before next boundary
            if data.endswith(b"\r\n"):
                data = data[:-2]

            # Look for filename in Content-Disposition
            filename = None
            for line in headers_raw.split("\r\n"):
                if line.lower().startswith("content-disposition:"):
                    match = re.search(r'filename="([^"]+)"', line)
                    if match:
                        filename = match.group(1)

            if filename:
                return filename, data

        return None, None


def main():
    ensure_dirs()
    print(f"[MusicServer] Starting on port {PORT}", flush=True)
    print(f"[MusicServer] CustomBGM directory: {CUSTOM_BGM_DIR}", flush=True)
    print(f"[MusicServer] Temp directory: {TMP_DIR}", flush=True)
    print(f"[MusicServer] Project directory: {PROJECT_DIR}", flush=True)

    server = http.server.HTTPServer(("0.0.0.0", PORT), MusicHandler)
    print(f"[MusicServer] Listening on http://localhost:{PORT}/", flush=True)
    print(f"[MusicServer] Ready for uploads from the BDFFHD web UI.", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[MusicServer] Shutting down.", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
