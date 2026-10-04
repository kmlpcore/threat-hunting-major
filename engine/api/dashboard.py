"""Dashboard service: serves the single-page app and proxies to the APIs.

    GET  /                 the app
    GET  /api/q/<path>     -> query API   (read side)
    POST /api/c/<path>     -> command API (write side)

Keeping CQRS visible: the UI never talks to a database, only to the two APIs.
"""
from __future__ import annotations

import os
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

STATIC = Path(__file__).resolve().parents[1] / "dashboard" / "static"


def create_app() -> FastAPI:
    query_url = os.environ.get("QUERY_API_URL", "http://localhost:8001")
    command_url = os.environ.get("COMMAND_API_URL", "http://localhost:8000")
    app = FastAPI(title="Threat Hunting Engine - Dashboard", docs_url=None, redoc_url=None)
    client = httpx.AsyncClient(timeout=120)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/q/{path:path}")
    async def query(path: str, request: Request):
        r = await client.get(f"{query_url}/{path}", params=request.query_params)
        return Response(r.content, status_code=r.status_code, media_type="application/json")

    @app.post("/api/c/{path:path}")
    async def command(path: str, request: Request):
        r = await client.post(f"{command_url}/{path}", content=await request.body(),
                              headers={"Content-Type": "application/json", "X-Submitted-By": "dashboard"})
        return Response(r.content, status_code=r.status_code, media_type="application/json")

    @app.exception_handler(httpx.HTTPError)
    async def upstream_error(_, exc: httpx.HTTPError):
        return JSONResponse({"detail": f"upstream unavailable: {exc}"}, status_code=502)

    return app
