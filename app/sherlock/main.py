import base64
import hashlib
import math
import re
import sqlite3
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, HTTPException, Path as PathParam, Query, Request, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from sherlock import __version__, config
from sherlock.db import connect, init_db

BASE_DIR = Path(__file__).parent

SEVERITY_SQL = """CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
                  WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END"""
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEARCH_MAX_LENGTH = 100
PAGE_SIZE = 100
API_MAX_LIMIT = 500

SWAGGER_VERSION = "5.34.0"
SWAGGER_CDN = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_VERSION}"
SWAGGER_JS_SRI = "sha384-9Td7MKiIr2S83E1kZyyVi8KdJw/S8CpAvu0llLyMeg0xq/hDGiZJfVn0fV4llCmK"
SWAGGER_CSS_SRI = "sha384-4c3vsE5f+trhFyHrFrLM1fFGUn531NIaC7dcqEWIJdoRQJ5CkJbSuSCwXLpaS1KF"

CSP_SITE = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db(config.DB_PATH)
    yield


app = FastAPI(
    title="sherlock",
    version=__version__,
    description=(
        "Published vulnerabilities (NVD) for a demo application inventory. "
        "Read-only API. This product uses the NVD API but is not endorsed or certified by the NVD."
    ),
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def filter_url(base: str, filters: dict, key: str, value: str | int) -> str:
    params = {k: v for k, v in {**filters, key: value}.items() if v}
    return f"{base}?{urlencode(params)}" if params else base


templates.env.globals["filter_url"] = filter_url


def _build_docs_page() -> tuple[str, str]:
    html = get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="sherlock · API",
        swagger_js_url=f"{SWAGGER_CDN}/swagger-ui-bundle.js",
        swagger_css_url=f"{SWAGGER_CDN}/swagger-ui.css",
        swagger_favicon_url="/static/favicon.png",
        swagger_ui_parameters={"syntaxHighlight": {"theme": "monokai"}, "validatorUrl": None},
    ).body.decode()

    header = (
        '<header class="sherlock-bar"><a class="brand" href="/">'
        '<img src="/static/logo.png" alt="" width="40" height="40">sherlock</a>'
        '<nav><a href="/">Offen</a><a href="/history">History</a>'
        '<a href="/apps">Applikationen</a><a href="/docs" aria-current="page">API</a></nav></header>'
    )
    replacements = [
        (f'href="{SWAGGER_CDN}/swagger-ui.css">',
         f'href="{SWAGGER_CDN}/swagger-ui.css" integrity="{SWAGGER_CSS_SRI}" crossorigin="anonymous">'),
        (f'<script src="{SWAGGER_CDN}/swagger-ui-bundle.js"></script>',
         f'<script src="{SWAGGER_CDN}/swagger-ui-bundle.js" integrity="{SWAGGER_JS_SRI}" '
         'crossorigin="anonymous"></script>'),
        ("</head>", f'<link rel="stylesheet" href="/static/swagger-dark.css?v={__version__}"></head>'),
        ("<body>", f"<body>{header}"),
    ]
    for old, new in replacements:
        if html.count(old) != 1:
            raise RuntimeError(f"Unexpected Swagger HTML, cannot patch {old!r}")
        html = html.replace(old, new)

    inline = re.findall(r"<script>(.*?)</script>", html, re.DOTALL)
    hashes = " ".join(
        f"'sha256-{base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()}'" for s in inline
    )
    csp = (
        f"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net {hashes}; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return html, csp


DOCS_HTML, CSP_DOCS = _build_docs_page()


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP_DOCS if request.url.path == "/docs" else CSP_SITE
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect(config.DB_PATH, timeout=5)
    try:
        yield conn
    finally:
        conn.close()


Db = Annotated[sqlite3.Connection, Depends(get_db)]


def _findings_where(
    status: str,
    app_id: str | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    patch: bool | None = None,
    q: str | None = None,
) -> tuple[str, list]:
    where = ["f.status = ?"]
    params: list = [status]
    if q:
        where.append("(f.cve_id LIKE ? ESCAPE '\\' OR f.description LIKE ? ESCAPE '\\')")
        literal = q[:SEARCH_MAX_LENGTH].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params += [f"%{literal}%"] * 2
    if app_id:
        where.append("f.app_id = ?")
        params.append(app_id)
    if severity:
        where.append("f.severity = ?")
        params.append(severity)
    if kev is not None:
        where.append("f.kev = ?")
        params.append(int(kev))
    if patch is not None:
        where.append("f.patch_available = ?")
        params.append(int(patch))
    return " AND ".join(where), params


def query_findings(db: sqlite3.Connection, status: str, *, limit: int, offset: int = 0,
                   **filters) -> tuple[list[dict], int]:
    where, params = _findings_where(status, **filters)
    base = f"FROM findings f JOIN apps a ON a.id = f.app_id WHERE {where}"
    total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    order = (
        f"f.kev DESC, {SEVERITY_SQL} DESC, f.score DESC, f.published DESC, f.cve_id"
        if status == "open"
        else "f.resolved_at DESC, f.cve_id"
    )
    rows = db.execute(
        f"SELECT f.*, a.name AS app_name, a.version AS app_version {base} ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    return [dict(r) for r in rows], total


def query_apps(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        """
        SELECT a.*,
          SUM(f.status = 'open')                               AS open,
          SUM(f.status = 'open' AND f.severity = 'CRITICAL')   AS critical,
          SUM(f.status = 'open' AND f.kev = 1)                 AS kev,
          SUM(f.status = 'open' AND f.patch_available = 1)     AS patchable,
          SUM(f.status = 'resolved')                           AS resolved
        FROM apps a LEFT JOIN findings f ON f.app_id = a.id
        GROUP BY a.id ORDER BY open DESC, a.name
        """
    )
    return [{k: (v or 0) if k in ("open", "critical", "kev", "patchable", "resolved") else v
             for k, v in dict(r).items()} for r in rows]


def last_sync(db: sqlite3.Connection) -> dict | None:
    row = db.execute("SELECT * FROM sync_runs ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def render(request: Request, db: sqlite3.Connection, name: str, **context) -> HTMLResponse:
    apps = query_apps(db)
    return templates.TemplateResponse(
        request,
        name,
        {
            "apps": apps,
            "app_options": sorted(((a["id"], a["name"]) for a in apps), key=lambda o: o[1].lower()),
            "last_sync": last_sync(db),
            "version": __version__,
            **context,
        },
    )


def _flag(value: str | None) -> bool | None:
    return {"1": True, "0": False}.get(value or "")


def _clean(value: str | None, allowed: tuple[str, ...] | None = None) -> str:
    value = (value or "").strip()[:SEARCH_MAX_LENGTH]
    return value if allowed is None or value in allowed else ""


def _paged(db: sqlite3.Connection, status: str, filters: dict, page: int, **query) -> dict:
    _, total = query_findings(db, status, limit=0, **query)
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(page, pages)
    findings, _ = query_findings(db, status, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE, **query)
    return {"findings": findings, "total": total, "page": page, "pages": pages, "filters": filters}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def page_open(request: Request, db: Db, app_id: str | None = None, severity: str | None = None,
              kev: str | None = None, patch: str | None = None, q: str | None = None,
              page: Annotated[int, Query(ge=1, le=10_000)] = 1):
    filters = {
        "app_id": _clean(app_id),
        "severity": _clean(severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
        "patch": _clean(patch, ("1", "0")),
        "kev": _clean(kev, ("1",)),
        "q": _clean(q),
    }
    context = _paged(db, "open", filters, page, app_id=filters["app_id"], severity=filters["severity"],
                     kev=_flag(filters["kev"]), patch=_flag(filters["patch"]), q=filters["q"])
    return render(request, db, "open.html", page_name="open", **context)


@app.get("/history", response_class=HTMLResponse, include_in_schema=False)
def page_history(request: Request, db: Db, app_id: str | None = None, q: str | None = None,
                 page: Annotated[int, Query(ge=1, le=10_000)] = 1):
    filters = {"app_id": _clean(app_id), "q": _clean(q)}
    context = _paged(db, "resolved", filters, page, app_id=filters["app_id"], q=filters["q"])
    return render(request, db, "history.html", page_name="history", **context)


@app.get("/apps", response_class=HTMLResponse, include_in_schema=False)
def page_apps(request: Request, db: Db):
    return render(request, db, "apps.html", page_name="apps")


@app.get("/docs", include_in_schema=False)
def api_docs() -> HTMLResponse:
    return HTMLResponse(DOCS_HTML)


@app.get("/healthz", include_in_schema=False)
def healthz(db: Db) -> dict:
    db.execute("SELECT 1")
    return {"status": "ok"}


class AppOut(BaseModel):
    id: str
    name: str
    category: str
    version: str
    last_synced: str | None
    sync_ok: bool
    open: int
    critical: int
    kev: int
    patchable: int
    resolved: int


class VulnerabilityOut(BaseModel):
    app_id: str
    app_name: str
    cve_id: str
    status: Literal["open", "resolved"]
    severity: str | None
    score: float | None
    published: str | None
    description: str
    fixed_in: str | None
    patch_available: bool
    patch_url: str | None
    kev: bool
    kev_added: str | None
    first_seen: str
    opened_version: str
    resolved_at: str | None
    resolved_version: str | None
    resolution: str | None


class SyncRunOut(BaseModel):
    id: int
    started_at: str
    finished_at: str | None
    status: str
    message: str | None


@app.get("/api/apps", response_model=list[AppOut], tags=["api"])
def api_apps(db: Db):
    return query_apps(db)


@app.get("/api/vulnerabilities", response_model=list[VulnerabilityOut], tags=["api"])
def api_vulnerabilities(
    db: Db,
    response: Response,
    status: Literal["open", "resolved"] = "open",
    app_id: Annotated[str | None, Query(max_length=SEARCH_MAX_LENGTH,
                                        description="Filter by app id, e.g. nginx")] = None,
    severity: Severity | None = None,
    kev: Annotated[bool | None, Query(description="Only (not) actively exploited")] = None,
    patch: Annotated[bool | None, Query(description="Only with (without) available patch")] = None,
    q: Annotated[str | None, Query(max_length=SEARCH_MAX_LENGTH,
                                   description="Search in CVE number and description")] = None,
    limit: Annotated[int, Query(ge=1, le=API_MAX_LIMIT, description="Page size")] = 100,
    offset: Annotated[int, Query(ge=0, description="Number of entries to skip")] = 0,
):
    rows, total = query_findings(db, status, limit=limit, offset=offset, app_id=app_id,
                                 severity=severity, kev=kev, patch=patch, q=q)
    response.headers["X-Total-Count"] = str(total)
    return rows


@app.get("/api/vulnerabilities/{cve_id}", response_model=list[VulnerabilityOut], tags=["api"])
def api_vulnerability(cve_id: Annotated[str, PathParam(max_length=30, pattern=r"^[A-Za-z0-9-]+$")], db: Db):
    rows = db.execute(
        "SELECT f.*, a.name AS app_name FROM findings f JOIN apps a ON a.id = f.app_id WHERE f.cve_id = ?",
        (cve_id.upper(),),
    ).fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="CVE not found")
    return [dict(r) for r in rows]


@app.get("/api/sync", response_model=list[SyncRunOut], tags=["api"])
def api_sync(db: Db, limit: Annotated[int, Query(ge=1, le=50)] = 10):
    rows = db.execute("SELECT * FROM sync_runs ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(r) for r in rows]
