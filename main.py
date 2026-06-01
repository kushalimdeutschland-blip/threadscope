"""
ThreatScope — Privacy-first threat intelligence dashboard.
Local SQLite lookups + Ollama summaries + HTMX UI.
"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import aiosqlite
import httpx
from fastapi import BackgroundTasks, FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

import database
from config import get_settings
from middleware.security import SecurityHeadersMiddleware
from models.schemas import HealthResponse
from services.ai_analyst import generate_file_re_guidance, generate_threat_summary
from services.report_export import (
    build_bulk_report_text,
    build_file_report_text,
    build_indicator_report_text,
)
from services.admin_auth import (
    ADMIN_LOGIN_RATE_LIMIT,
    admin_auth_configured,
    clear_admin_session_cookie,
    is_admin_request,
    set_admin_session_cookie,
    verify_admin_password,
)
from services.csrf import CSRF_COOKIE, csrf_tokens_match, generate_csrf_token, validate_csrf_token
from services.rate_limit import get_client_ip, is_admin_context, reset_admin_context, set_admin_context
from services.file_analysis import build_file_threat_report
from services.file_upload import FileUploadError, read_upload_file
from services.lookup import lookup_indicator
from services.analysis_merge import merge_dynamic_into_threat
from services.sandbox.base import DynamicReport
from services.sandbox.registry import resolve_backend
from services.sample_store import store_sample
from services.sandbox.staging import write_sample
from services.static_analysis import analyze_bytes
from services.bulk_ioc_upload import read_bulk_ioc_upload
from services.bulk_lookup import bulk_lookup_indicators, bulk_lookup_tokens
from services.export_blocklist import export_blocklist_csv
from services.escalation import file_escalation_context, indicator_escalation_context
from services.intel.search import search_intel_with_ai
from services.lab_scan import resolve_scan_target, validate_scan_allowed
from services.validation import IndicatorType, resolve_indicator, type_label

VALID_FEEDBACK_VERDICTS = frozenset({"MALICIOUS", "SUSPICIOUS", "CLEAN", "STALE", "UNKNOWN"})

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


async def _prepare_file_result(
    threat: dict,
    *,
    sample_path: Path | str | None,
    client: httpx.AsyncClient,
) -> tuple[str, dict, str]:
    """Parallel AI summary + RE guidance; build escalation and clipboard report."""
    summary, ai_steps = await asyncio.gather(
        generate_threat_summary(threat, client),
        generate_file_re_guidance(threat, client),
    )
    escalation = file_escalation_context(threat, sample_path=sample_path)
    if ai_steps:
        escalation["re_workflow"] = ai_steps
        escalation["re_workflow_source"] = "ai"
    else:
        escalation["re_workflow_source"] = "static"
    report_text = build_file_report_text(threat, summary, escalation)
    return summary, escalation, report_text

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
settings = get_settings()
secret_key = settings.ensure_secret_key()

limiter = Limiter(key_func=lambda request: get_client_ip(request, settings), default_limits=[])


def _admin_rate_exempt() -> bool:
    """slowapi exempt_when: signed-in admin skips visitor rate limits."""
    return is_admin_context()


def _allow_dynamic_sandbox(request: Request) -> bool:
    app_settings = getattr(request.app.state, "settings", settings)
    is_admin = getattr(request.state, "is_admin", False)
    return app_settings.allow_dynamic_for_request(is_admin)

IndicatorFormType = Literal["auto", "ipv4", "ipv6", "domain", "hash", "phone", "email"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.init_db()
    await database.open_read_pool()
    app.state.http = httpx.AsyncClient(timeout=settings.ollama_timeout)
    app.state.settings = settings
    app.state.secret_key = secret_key
    yield
    await app.state.http.aclose()
    await database.close_read_pool()


app = FastAPI(
    title="ThreatScope",
    description="Privacy-first threat intelligence — local DB + local LLM",
    version="2.3.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.debug else None,
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware, settings=settings)

if settings.is_production:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)


@app.middleware("http")
async def attach_admin_state(request: Request, call_next):
    """Expose request.state.is_admin for templates, route guards, and rate-limit exemption."""
    app_settings = getattr(request.app.state, "settings", settings)
    app_secret = getattr(request.app.state, "secret_key", secret_key)
    request.state.is_admin = is_admin_request(request, app_settings, app_secret)
    token = set_admin_context(request.state.is_admin)
    try:
        return await call_next(request)
    finally:
        reset_admin_context(token)


static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir), check_dir=True), name="static")


def _html_error(request: Request, message: str, status_code: int) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "partials/error.html",
        {"request": request, "message": message},
        status_code=status_code,
    )


def _verify_csrf(request: Request, csrf_token: str) -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE)
    return csrf_tokens_match(cookie_token, csrf_token) and validate_csrf_token(secret_key, csrf_token)


def _is_admin(request: Request) -> bool:
    return bool(getattr(request.state, "is_admin", False))


def _intel_search_enabled(request: Request) -> bool:
    if _is_admin(request):
        return True
    if settings.public_mode:
        return False
    return settings.env_threatscope_admin


def _show_lookup_history(request: Request) -> bool:
    if settings.public_mode:
        return _is_admin(request)
    return True


def _should_record_lookup_history(request: Request) -> bool:
    return _show_lookup_history(request)


def _require_admin_route(request: Request) -> HTMLResponse | None:
    if _is_admin(request):
        return None
    return _html_error(request, "Forbidden.", 403)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    if request.headers.get("HX-Request"):
        return _html_error(request, "Rate limit exceeded. Please wait before trying again.", 429)
    return JSONResponse({"detail": "Too many requests"}, status_code=429)


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    if request.headers.get("HX-Request"):
        return _html_error(request, "Invalid request.", 422)
    return JSONResponse({"detail": "Invalid request"}, status_code=422)


@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception):
    logging.getLogger("threatscope").exception("Unhandled error")
    if request.headers.get("HX-Request"):
        return _html_error(request, "An internal error occurred.", 500)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


@app.get("/api/history", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("60/minute", exempt_when=_admin_rate_exempt)
async def lookup_history_partial(request: Request):
    """HTMX fragment: recent indicator and file lookups."""
    if not _show_lookup_history(request):
        return templates.TemplateResponse(
            request,
            "partials/lookup_history.html",
            {"request": request, "history": []},
        )
    history = await database.list_lookup_history(limit=20)
    return templates.TemplateResponse(
        request,
        "partials/lookup_history.html",
        {"request": request, "history": history},
    )


@app.get("/about", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("60/minute", exempt_when=_admin_rate_exempt)
async def about_page(request: Request):
    return templates.TemplateResponse(
        request,
        "about.html",
        {"request": request, "public_mode": settings.public_mode},
    )


@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("60/minute", exempt_when=_admin_rate_exempt)
async def privacy_page(request: Request):
    return templates.TemplateResponse(
        request,
        "privacy.html",
        {"request": request, "public_mode": settings.public_mode},
    )


@app.get("/robots.txt", include_in_schema=False)
@limiter.limit("60/minute", exempt_when=_admin_rate_exempt)
async def robots_txt(request: Request):
    path = static_dir / "robots.txt"
    if path.is_file():
        return Response(content=path.read_text(encoding="utf-8"), media_type="text/plain")
    return Response(content="User-agent: *\nDisallow: /api/\n", media_type="text/plain")


@app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("30/minute", exempt_when=_admin_rate_exempt)
async def admin_dashboard(request: Request):
    if not _is_admin(request):
        return RedirectResponse(url="/admin/login", status_code=303)
    collector_runs = await database.list_collector_runs(limit=10)
    token = generate_csrf_token(secret_key)
    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        {
            "request": request,
            "csrf_token": token,
            "collector_runs": collector_runs,
        },
    )


@app.get("/admin/login", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("30/minute", exempt_when=_admin_rate_exempt)
async def admin_login_page(request: Request):
    if _is_admin(request):
        return RedirectResponse(url="/admin", status_code=303)
    token = generate_csrf_token(secret_key)
    response = templates.TemplateResponse(
        request,
        "admin/login.html",
        {"request": request, "csrf_token": token, "error": None},
    )
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        secure=settings.is_production,
        max_age=3600,
        path="/",
    )
    return response


@app.post("/admin/login", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit(ADMIN_LOGIN_RATE_LIMIT)
async def admin_login_submit(
    request: Request,
    password: str = Form(..., max_length=256),
    csrf_token: str = Form(..., max_length=128),
):
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session. Refresh and try again.", 403)
    if settings.is_production and not admin_auth_configured(settings):
        return _html_error(
            request,
            "Admin login is not configured. Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH in .env.",
            503,
        )
    if not verify_admin_password(settings, password):
        token = generate_csrf_token(secret_key)
        response = templates.TemplateResponse(
            request,
            "admin/login.html",
            {"request": request, "csrf_token": token, "error": "Invalid password."},
            status_code=401,
        )
        response.set_cookie(
            key=CSRF_COOKIE,
            value=token,
            httponly=True,
            samesite="strict",
            secure=settings.is_production,
            max_age=3600,
            path="/",
        )
        return response
    response = RedirectResponse(url="/admin", status_code=303)
    set_admin_session_cookie(response, secret_key, secure=settings.is_production)
    return response


@app.post("/admin/logout", include_in_schema=False)
@limiter.limit("30/minute", exempt_when=_admin_rate_exempt)
async def admin_logout(request: Request, csrf_token: str = Form(..., max_length=128)):
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session.", 403)
    response = RedirectResponse(url="/admin/login", status_code=303)
    clear_admin_session_cookie(response)
    return response


@app.get("/health", response_model=HealthResponse, tags=["Meta"])
@limiter.limit("60/minute", exempt_when=_admin_rate_exempt)
async def health(request: Request):
    return {"status": "ok", "timestamp": int(time.time())}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("60/minute", exempt_when=_admin_rate_exempt)
async def index(request: Request):
    token = generate_csrf_token(secret_key)
    response = templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "csrf_token": token,
            "lab_scan_enabled": settings.effective_lab_scan_enabled,
            "intel_search_enabled": _intel_search_enabled(request),
            "public_mode": settings.public_mode,
            "allow_dynamic_sandbox": _allow_dynamic_sandbox(request),
            "admin_dynamic_opt_in": settings.public_mode
            and settings.admin_allow_dynamic
            and getattr(request.state, "is_admin", False),
            "show_history": _show_lookup_history(request),
        },
    )
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        secure=settings.is_production,
        max_age=3600,
        path="/",
    )
    return response


@app.get("/api/export/blocklist.csv", tags=["Lookup"])
@limiter.limit(settings.effective_blocklist_rate_limit, exempt_when=_admin_rate_exempt)
async def export_blocklist(
    request: Request,
    min_score: int = 70,
    indicator_type: Literal["ipv4", "ipv6", "domain", "hash", "phone", "email", "all"] = "all",
):
    """Download CSV of local indicators at or above min_score (lab blocklists)."""
    if min_score < 0 or min_score > 100:
        return _html_error(request, "min_score must be 0–100", 400)
    csv_body = await export_blocklist_csv(min_score=min_score, indicator_type=indicator_type)
    return Response(
        content=csv_body,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatscope_blocklist.csv"},
    )


@app.post("/api/bulk-lookup", response_class=HTMLResponse, tags=["Lookup"])
@limiter.limit(settings.effective_rate_limit, exempt_when=_admin_rate_exempt)
async def bulk_lookup(
    request: Request,
    iocs: str = Form(..., max_length=16000),
    csrf_token: str = Form(..., max_length=128),
):
    """Lookup many indicators (one per line, max 50)."""
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session. Refresh the page and try again.", 403)

    rows = await bulk_lookup_indicators(iocs)
    for row in rows:
        if row.get("error") or not row.get("type"):
            continue
        if _should_record_lookup_history(request):
            await database.record_lookup_history(
                row["value"],
                row["type"],
                verdict=row.get("verdict"),
                risk_score=row.get("risk_score"),
                in_database=bool(row.get("in_database")),
            )

    report_text = build_bulk_report_text(rows)
    return templates.TemplateResponse(
        request,
        "partials/bulk_result.html",
        {"request": request, "rows": rows, "report_text": report_text},
    )


@app.post("/api/bulk-lookup-file", response_class=HTMLResponse, tags=["Lookup"])
@limiter.limit(settings.effective_rate_limit, exempt_when=_admin_rate_exempt)
async def bulk_lookup_file(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(..., max_length=128),
):
    """Lookup many indicators from a .txt, .csv, or .list file (max 50 IOCs)."""
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session. Refresh the page and try again.", 403)

    try:
        tokens = await read_bulk_ioc_upload(file)
    except FileUploadError as exc:
        return _html_error(request, str(exc), 400)

    rows = await bulk_lookup_tokens(tokens)
    for row in rows:
        if row.get("error") or not row.get("type"):
            continue
        if _should_record_lookup_history(request):
            await database.record_lookup_history(
                row["value"],
                row["type"],
                verdict=row.get("verdict"),
                risk_score=row.get("risk_score"),
                in_database=bool(row.get("in_database")),
            )

    report_text = build_bulk_report_text(rows)
    return templates.TemplateResponse(
        request,
        "partials/bulk_result.html",
        {"request": request, "rows": rows, "report_text": report_text},
    )


@app.post("/api/lookup", response_class=HTMLResponse, tags=["Lookup"])
@limiter.limit(settings.effective_rate_limit, exempt_when=_admin_rate_exempt)
async def lookup(
    request: Request,
    q: str = Form(..., max_length=512),
    indicator_type: IndicatorFormType = Form("auto"),
    csrf_token: str = Form(..., max_length=128),
):
    """Query local SQLite for IPv4, IPv6, domain, or hash indicators."""
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session. Refresh the page and try again.", 403)

    try:
        resolved_type, normalized = resolve_indicator(q, indicator_type)
    except ValueError:
        if indicator_type == "auto":
            return _html_error(
                request,
                "Could not parse indicator. Paste an IP, domain, URL, hash, phone, or email — extra paths like /foo are OK.",
                400,
            )
        return _html_error(request, f"Invalid {type_label(indicator_type)}.", 400)

    threat = await lookup_indicator(normalized, resolved_type, http_client=request.app.state.http)
    if _should_record_lookup_history(request):
        await database.record_lookup_history(
            normalized,
            resolved_type,
            verdict=threat.get("verdict"),
            risk_score=threat.get("risk_score"),
            in_database=bool(threat.get("in_database")),
        )
    summary = await generate_threat_summary(threat, request.app.state.http)
    escalation = indicator_escalation_context(threat)
    report_text = build_indicator_report_text(threat, summary, escalation)

    return templates.TemplateResponse(
        request,
        "partials/result.html",
        {
            "request": request,
            "threat": threat,
            "summary": summary,
            "escalation": escalation,
            "csrf_token": csrf_token,
            "lab_scan_enabled": settings.effective_lab_scan_enabled,
            "report_text": report_text,
        },
    )


def _feedback_error(request: Request, message: str, status_code: int) -> HTMLResponse:
    return _html_error(request, message, status_code)


@app.post("/api/feedback", response_class=HTMLResponse, tags=["Lookup"])
@limiter.limit(settings.effective_rate_limit, exempt_when=_admin_rate_exempt)
async def submit_feedback(
    request: Request,
    background_tasks: BackgroundTasks,
    value: str = Form(..., max_length=512),
    indicator_type: IndicatorType = Form(..., alias="type"),
    observed_verdict: str = Form(..., max_length=32),
    expected_verdict: str = Form(..., max_length=32),
    note: str | None = Form(None, max_length=2000),
    csrf_token: str = Form(..., max_length=128),
):
    """Record analyst verdict feedback; recompute per-feed accuracy in background."""
    if not _verify_csrf(request, csrf_token):
        return _feedback_error(request, "Invalid session. Refresh and try again.", 403)

    if observed_verdict not in VALID_FEEDBACK_VERDICTS or expected_verdict not in VALID_FEEDBACK_VERDICTS:
        return _feedback_error(request, "Invalid verdict value.", 400)

    try:
        resolved_type, normalized = resolve_indicator(value.strip(), indicator_type)
    except ValueError:
        return _feedback_error(request, "Invalid indicator value or type.", 400)

    if resolved_type != indicator_type:
        return _feedback_error(request, "Indicator value does not match type.", 400)

    threat = await lookup_indicator(normalized, resolved_type)
    if not threat.get("in_database"):
        return _feedback_error(request, "Indicator not in database.", 400)

    if observed_verdict != threat.get("verdict"):
        return _feedback_error(request, "Observed verdict does not match current lookup.", 400)

    note_clean = note.strip() if note and note.strip() else None

    try:
        await database.insert_feedback(
            normalized,
            resolved_type,
            observed_verdict,
            expected_verdict,
            note=note_clean,
        )
    except aiosqlite.IntegrityError:
        return _feedback_error(request, "Indicator not in database.", 400)
    except Exception:
        logging.exception("feedback insert failed for %s", normalized)
        return _feedback_error(request, "Could not save feedback.", 400)

    sources = await database.get_indicator_sources(normalized, resolved_type)
    seen: set[str] = set()
    for src in sources:
        name = src["source"]
        if name not in seen:
            seen.add(name)
            background_tasks.add_task(database.recompute_feed_accuracy, name)

    return templates.TemplateResponse(
        request,
        "partials/feedback_thanks.html",
        {"request": request, "value": normalized},
    )


@app.post("/api/intel-search", response_class=HTMLResponse, tags=["Lookup"], include_in_schema=False)
@limiter.limit("20/minute", exempt_when=_admin_rate_exempt)
async def intel_search(
    request: Request,
    q: str = Form(..., max_length=256),
    tag: str = Form(default="", max_length=64),
    csrf_token: str = Form(..., max_length=128),
):
    """Search collected intel narratives (admin session or dev THREATSCOPE_ADMIN)."""
    denied = _require_admin_route(request)
    if denied:
        return denied
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session. Refresh the page and try again.", 403)

    query = q.strip()
    if len(query) < 2:
        return _html_error(request, "Enter at least 2 characters to search intel.", 400)

    tag_filter = tag.strip().lower() or None
    results, expansion_meta = await search_intel_with_ai(
        query,
        tag=tag_filter,
        limit=40,
        client=request.app.state.http,
    )

    return templates.TemplateResponse(
        request,
        "partials/intel_results.html",
        {
            "request": request,
            "query": query,
            "tag": tag_filter or "",
            "results": results,
            "expansion_meta": expansion_meta,
            "csrf_token": csrf_token,
        },
    )


@app.get("/api/feed-accuracy", response_class=HTMLResponse, tags=["Lookup"], include_in_schema=False)
async def feed_accuracy_view(request: Request):
    """Admin HTML table of per-feed analyst accuracy."""
    denied = _require_admin_route(request)
    if denied:
        return denied
    rows = await database.list_feed_accuracy()

    def _fp_rate(row: dict) -> float:
        total = row["true_positive"] + row["false_positive"]
        if total == 0:
            return -1.0
        return row["false_positive"] / total

    rows.sort(key=_fp_rate, reverse=True)
    return templates.TemplateResponse(
        request,
        "partials/feed_accuracy.html",
        {"request": request, "rows": rows},
    )


@app.post("/api/lab-scan", response_class=HTMLResponse, tags=["Lookup"])
@limiter.limit(settings.lab_scan_rate_limit, exempt_when=_admin_rate_exempt)
async def lab_scan(
    request: Request,
    target: str = Form(..., max_length=512),
    target_type: IndicatorType = Form(..., alias="type"),
    csrf_token: str = Form(..., max_length=128),
):
    """Enqueue opt-in nmap/ping lab scan for IP or domain (requires scan_worker)."""
    if not settings.effective_lab_scan_enabled:
        return _html_error(
            request,
            "Lab scanning is disabled. Set LAB_SCAN_ENABLED=1 and run scripts/scan_worker.py.",
            403,
        )
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session. Refresh the page and try again.", 403)

    if target_type not in ("ipv4", "ipv6", "domain"):
        return _html_error(request, "Lab scan is only available for IP addresses and domains.", 400)

    try:
        resolved_type, normalized = resolve_indicator(target.strip(), target_type)
    except ValueError:
        return _html_error(request, f"Invalid {type_label(target_type)}.", 400)

    try:
        scan_host, resolved_ip = resolve_scan_target(normalized, resolved_type)
        validate_scan_allowed(scan_host)
    except ValueError as exc:
        return _html_error(request, str(exc), 400)

    job_id = str(uuid.uuid4())
    await database.create_scan_job(
        job_id,
        target=normalized,
        target_type=resolved_type,
        resolved_ip=resolved_ip,
    )

    return templates.TemplateResponse(
        request,
        "partials/scan_job.html",
        {
            "request": request,
            "job": {"status": "queued", "target": normalized, "target_type": resolved_type},
            "job_id": job_id,
            "polling": True,
        },
    )


@app.get("/api/scan-job/{job_id}", response_class=HTMLResponse, tags=["Lookup"])
@limiter.limit("120/minute", exempt_when=_admin_rate_exempt)
async def scan_job_status(request: Request, job_id: str):
    """HTMX poll endpoint for lab scan job status."""
    job = await database.get_scan_job(job_id)
    if job is None:
        return _html_error(request, "Scan job not found.", 404)

    status = job["status"]
    if status in ("queued", "running"):
        return templates.TemplateResponse(
            request,
            "partials/scan_job.html",
            {
                "request": request,
                "job": job,
                "job_id": job_id,
                "polling": True,
            },
        )

    if status == "failed":
        return templates.TemplateResponse(
            request,
            "partials/scan_job.html",
            {
                "request": request,
                "job": job,
                "job_id": job_id,
                "polling": False,
                "error": job.get("error_text") or "Lab scan failed",
            },
        )

    report = job.get("report") or {}
    threat = await lookup_indicator(
        job["target"],
        job["target_type"],
        http_client=request.app.state.http,
    )
    meta = threat.setdefault("meta", {})
    meta["lab_scan"] = report
    summary = await generate_threat_summary(threat, request.app.state.http)
    escalation = indicator_escalation_context(threat)
    report_text = build_indicator_report_text(threat, summary, escalation)

    return templates.TemplateResponse(
        request,
        "partials/scan_result.html",
        {
            "request": request,
            "threat": threat,
            "summary": summary,
            "report": report,
            "job": job,
            "job_id": job_id,
            "escalation": escalation,
            "csrf_token": request.cookies.get(CSRF_COOKIE) or generate_csrf_token(secret_key),
            "lab_scan_enabled": settings.effective_lab_scan_enabled,
            "report_text": report_text,
        },
    )


# Backward compatibility
@app.post("/api/ip", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit(settings.effective_rate_limit, exempt_when=_admin_rate_exempt)
async def lookup_ip_legacy(
    request: Request,
    q: str = Form(..., max_length=512),
    csrf_token: str = Form(..., max_length=128),
):
    return await lookup(request, q=q, indicator_type="ipv4", csrf_token=csrf_token)


def _truthy_form(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@app.post("/api/analyze-file", response_class=HTMLResponse, tags=["Analysis"])
@limiter.limit(settings.effective_file_upload_rate_limit, exempt_when=_admin_rate_exempt)
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(..., max_length=128),
    run_dynamic: str | None = Form(None),
):
    """
    Static analysis for .exe (PE) and .apk files (parse-only in web process).
    Optional dynamic analysis runs in an isolated sandbox via sandbox_worker.py.
    """
    if not _verify_csrf(request, csrf_token):
        return _html_error(request, "Invalid or expired session. Refresh the page and try again.", 403)

    want_dynamic = _truthy_form(run_dynamic) and _allow_dynamic_sandbox(request)
    if want_dynamic and settings.sandbox_backend == "off":
        return _html_error(
            request,
            "Dynamic sandbox analysis is disabled. Set SANDBOX_BACKEND=mock (or auto) in .env.",
            400,
        )

    try:
        data, safe_name, ext = await read_upload_file(file, settings.max_upload_bytes)
    except FileUploadError as exc:
        return _html_error(request, str(exc), 400)

    _, sample_path = store_sample(data)

    try:
        analysis = await asyncio.to_thread(analyze_bytes, data, safe_name, ext)
        threat = await build_file_threat_report(analysis)
        await database.upsert_file_sample(
            analysis.hashes["sha256"],
            size_bytes=analysis.size_bytes,
            file_kind=analysis.file_kind,
            yara_match_count=int((analysis.meta or {}).get("yara_match_count") or 0),
        )
        if _should_record_lookup_history(request):
            await database.record_lookup_history(
                analysis.hashes["sha256"],
                "file",
                verdict=threat.get("verdict"),
                risk_score=threat.get("risk_score"),
                in_database=bool(threat.get("in_database")),
            )
    except Exception:
        logging.getLogger("threatscope").exception("Static analysis failed")
        return _html_error(request, "Static analysis failed for this file.", 422)
    finally:
        await file.close()

    job_id: str | None = None
    job_backend: str | None = None

    if want_dynamic:
        try:
            job_backend = await resolve_backend(ext, settings)
            job_id = str(uuid.uuid4())
            write_sample(job_id, data, file_hash=analysis.hashes["sha256"])
            await database.create_analysis_job(
                job_id,
                file_hash=analysis.hashes["sha256"],
                filename=safe_name,
                file_kind=analysis.file_kind,
                backend=job_backend,
                static_threat=threat,
            )
            threat = dict(threat)
            meta = dict(threat.get("meta") or {})
            meta["analysis_mode"] = "static+dynamic_pending"
            meta["sandbox_backend"] = job_backend
            meta["analysis_job_id"] = job_id
            threat["meta"] = meta
        except ValueError as exc:
            return _html_error(request, str(exc), 400)

    summary, escalation, report_text = await _prepare_file_result(
        threat,
        sample_path=sample_path,
        client=request.app.state.http,
    )

    job_row = None
    if job_id:
        job_row = {"id": job_id, "backend": job_backend, "status": "queued"}

    return templates.TemplateResponse(
        request,
        "partials/file_result.html",
        {
            "request": request,
            "threat": threat,
            "summary": summary,
            "job_id": job_id,
            "job": job_row,
            "polling": bool(job_id),
            "escalation": escalation,
            "report_text": report_text,
        },
    )


@app.get("/api/analysis-job/{job_id}", response_class=HTMLResponse, tags=["Analysis"])
@limiter.limit("120/minute", exempt_when=_admin_rate_exempt)
async def analysis_job_status(request: Request, job_id: str):
    """HTMX poll endpoint for dynamic sandbox job status and merged results."""
    job = await database.get_analysis_job(job_id)
    if job is None:
        return _html_error(request, "Analysis job not found.", 404)

    status = job["status"]
    if status in ("queued", "running"):
        return templates.TemplateResponse(
            request,
            "partials/analysis_job.html",
            {
                "request": request,
                "job": job,
                "job_id": job_id,
                "polling": True,
            },
        )

    if status == "failed":
        return templates.TemplateResponse(
            request,
            "partials/analysis_job.html",
            {
                "request": request,
                "job": job,
                "job_id": job_id,
                "polling": False,
                "error": job.get("error_text") or "Dynamic analysis failed",
            },
        )

    report = job.get("report") or {}
    threat = report.get("threat")
    if not threat:
        static = job.get("static_threat") or {}
        dynamic_data = report.get("dynamic")
        if dynamic_data:
            threat = merge_dynamic_into_threat(
                static,
                DynamicReport.from_dict(dynamic_data),
            )
        else:
            threat = static

    file_hash = job.get("file_hash") or (threat.get("hashes") or {}).get("sha256")
    sample_path = None
    if file_hash:
        try:
            from services.sample_store import sample_path_for_hash

            sample_path = sample_path_for_hash(file_hash)
        except ValueError:
            pass

    summary, escalation, report_text = await _prepare_file_result(
        threat,
        sample_path=sample_path,
        client=request.app.state.http,
    )

    return templates.TemplateResponse(
        request,
        "partials/file_result.html",
        {
            "request": request,
            "threat": threat,
            "summary": summary,
            "job_id": None,
            "job_backend": job.get("backend"),
            "escalation": escalation,
            "report_text": report_text,
        },
    )
