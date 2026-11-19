"""FastAPI entrypoint for Automated Log Forensics & Incident Timeline Builder."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.agent import analyze_logs
from backend.models import AnalysisResult, AnalyzeTextRequest
from backend.security import (
    MAX_UPLOAD_BYTES,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    is_probably_text_upload,
)

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
SAMPLES = ROOT / "samples"

load_dotenv(ROOT / ".env")

ALLOWED_EXTENSIONS = {".log", ".txt", ".csv"}
ALLOWED_SAMPLE_NAMES = frozenset({"apache", "ssh"})

# Restrict CORS to local demo origins (no wildcard + credentials).
_DEFAULT_ORIGINS = (
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
)
_cors_env = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
ALLOW_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()] or list(_DEFAULT_ORIGINS)

app = FastAPI(
    title="Log Forensics Timeline Builder",
    description="AI-assisted DFIR log analysis and chronological incident timeline.",
    version="1.1.0",
    docs_url="/docs" if os.getenv("ENABLE_API_DOCS", "1") == "1" else None,
    redoc_url="/redoc" if os.getenv("ENABLE_API_DOCS", "1") == "1" else None,
)

# Middleware is applied in reverse add-order (last added = outermost).
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, _exc: Exception) -> JSONResponse:
    """Avoid leaking stack traces / secrets to clients (OWASP A09 / misconfig)."""
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/sample")
async def get_sample(name: str = "apache") -> dict[str, str]:
    key = name.strip().lower()
    if key not in ALLOWED_SAMPLE_NAMES:
        raise HTTPException(status_code=404, detail="Sample not found. Use name=apache or name=ssh.")
    mapping = {
        "apache": SAMPLES / "sample_apache.log",
        "ssh": SAMPLES / "sample_ssh.log",
    }
    path = mapping[key]
    # Defense-in-depth: ensure resolved path stays under samples/
    resolved = path.resolve()
    if not str(resolved).startswith(str(SAMPLES.resolve())) or not resolved.is_file():
        raise HTTPException(status_code=404, detail="Sample not found.")
    return {"name": key, "content": resolved.read_text(encoding="utf-8", errors="replace")}


@app.post("/api/analyze/text", response_model=AnalysisResult)
async def analyze_text(payload: AnalyzeTextRequest) -> AnalysisResult:
    result = await analyze_logs(payload.text)
    return AnalysisResult(**result)


@app.post("/api/analyze/file", response_model=AnalysisResult)
async def analyze_file(file: UploadFile = File(...)) -> AnalysisResult:
    filename = Path(file.filename or "upload.log").name  # drop any path components
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    if not is_probably_text_upload(file.content_type, filename):
        raise HTTPException(status_code=400, detail="Upload must be a text-based log file.")

    # Stream with a hard cap to avoid loading oversized bodies into memory twice.
    chunks: list[bytes] = []
    total = 0
    while True:
        piece = await file.read(64 * 1024)
        if not piece:
            break
        total += len(piece)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=400, detail="File exceeds 5 MB limit.")
        chunks.append(piece)

    raw_bytes = b"".join(chunks)
    if not raw_bytes.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Reject NUL-heavy binary payloads pretending to be logs.
    if raw_bytes.count(b"\x00") > 0:
        raise HTTPException(status_code=400, detail="Binary content is not allowed in log uploads.")

    text = raw_bytes.decode("utf-8", errors="replace")
    result = await analyze_logs(text)
    return AnalysisResult(**result)


if FRONTEND.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(FRONTEND / "index.html")
