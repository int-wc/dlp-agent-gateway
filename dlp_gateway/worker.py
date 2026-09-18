"""Loopback parser worker used by the Go gateway for rich document formats."""

import asyncio

from fastapi import FastAPI, File, HTTPException, UploadFile

from .parsing import MAX_BYTES, extract, signals


def create_worker_app() -> FastAPI:
    app = FastAPI(title="DLP Analyzer Worker", version="0.1.0")

    @app.get("/health")
    def health():
        return {"status": "ok", "role": "analyzer"}

    @app.post("/analyze")
    async def analyze(file: UploadFile = File(...)):
        data = await file.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise HTTPException(413, "file_too_large")
        try:
            text = await asyncio.to_thread(extract, data, file.filename or "unnamed")
        except Exception:
            return {"text": "", "signals": [], "parser_status": "unparseable", "model_status": "skipped", "risk": "high"}
        if not text.strip():
            return {"text": "", "signals": [], "parser_status": "empty", "model_status": "skipped", "risk": "high"}
        return {"text": text, "signals": signals(text), "parser_status": "ok", "model_status": "disabled", "risk": "low"}

    return app


app = create_worker_app()
