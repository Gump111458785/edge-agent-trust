from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
import os
from pathlib import Path
from time import time
from typing import Annotated, Callable
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import TypeAdapter

from .authorization import ApprovalVerifier, Rejected, TokenVerifier, operation_digest
from .db import connect, create_session, find_session, write_transaction
from .executor import Executor, restrict_action
from .schemas import Area, BookingId, BookingToolResult, DemoLogin, ExecuteRequest, Identifier, GrantProposal

bearer = HTTPBearer(auto_error=False)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
SessionHeader = Annotated[str | None, Header(alias='X-Session-Token', max_length=256)]


def secret_equal(left: str, right: str) -> bool:
    return compare_digest(sha256(left.encode()).digest(), sha256(right.encode()).digest())


def require_service(credentials: HTTPAuthorizationCredentials | None, expected: str) -> None:
    if credentials is None or not secret_equal(credentials.credentials, expected):
        raise Rejected('SERVICE_AUTH_REQUIRED', 401)


def database_path() -> Path:
    return Path(os.environ.get('ROLE_A_DB', 'business/data/role-a.sqlite3'))


def required_secret(name: str) -> str:
    value = os.environ.get(name, '')
    if len(value) < 24:
        raise ValueError(f'{name} requires a secret of at least 24 characters')
    return value


def make_app(title: str) -> FastAPI:
    app = FastAPI(title=title, version='1.0.0')

    @app.exception_handler(Rejected)
    async def handle_rejection(request: Request, exc: Rejected):
        return JSONResponse({'status': 'rejected', 'reason_code': exc.code}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def handle_bad_request(request: Request, exc: RequestValidationError):
        return JSONResponse({'status': 'rejected', 'reason_code': 'INVALID_REQUEST'}, status_code=422)

    @app.get('/health', include_in_schema=False)
    def health():
        return {'status': 'ok'}

    return app


def create_business_app(path: Path | None = None, facts_key: str | None = None,
                        clock: Callable[[], int] = lambda: int(time()),
                        tool_base_url: str | None = None) -> FastAPI:
    path = path or database_path()
    facts_key = facts_key or required_secret('ROLE_A_FACTS_KEY')
    tool_base_url = tool_base_url or os.environ.get('ROLE_A_TOOL_BASE_URL')
    if tool_base_url:
        public = urlsplit(tool_base_url)
        if public.scheme != 'https' or not public.hostname or public.query or public.fragment or public.username:
            raise ValueError('ROLE_A_TOOL_BASE_URL must be an HTTPS service base URL')
    app = make_app('Edge Agent Trust — Business Read API')

    def authenticated_session(conn, credentials: HTTPAuthorizationCredentials | None):
        token = credentials.credentials if credentials else ''
        session = find_session(conn, token, clock()) if token and len(token) <= 256 else None
        if session is None:
            raise Rejected('SESSION_REQUIRED', 401)
        return session

    @app.get('/booking', operation_id='query_booking', response_model=BookingToolResult,
             response_model_exclude_none=True, summary='查询当前测试会话所属的校园预约')
    def query_booking(booking_id: Annotated[BookingId, Query(description='预约编号，例如 BK-1042')],
                      credentials: Credentials):
        with connect(path, readonly=True) as conn:
            session = authenticated_session(conn, credentials)
            row = conn.execute('SELECT * FROM bookings WHERE booking_id = ? AND visitor_id = ?',
                               (booking_id, session['visitor_id'])).fetchone()
            if row is None:
                raise Rejected('BOOKING_NOT_FOUND', 404)
            status = row['status']
            if status == 'confirmed' and row['end_at'] <= clock():
                status = 'expired'
            result = {'booking_id': booking_id, 'status': status, 'building': '智慧楼',
                      'zone': '访客区' if row['area'] == 'visitor_area' else '机房'}
            if booking_id == 'BK-1042':
                result['fixture'] = 'demo-7H2Q'
            return result

    @app.get('/access-status', operation_id='get_access_status')
    def access_status(area: Area, credentials: Credentials):
        with connect(path, readonly=True) as conn:
            session = authenticated_session(conn, credentials)
            grant = conn.execute('''SELECT grant_id, valid_until FROM access_grants
                                  WHERE visitor_id = ? AND area = ? AND valid_until > ?''',
                                 (session['visitor_id'], area, clock())).fetchone()
            return {'area': area, 'active': grant is not None,
                    'valid_until': grant['valid_until'] if grant else None}

    @app.get('/internal/bookings/{booking_id}')
    def booking_fact(booking_id: BookingId, credentials: Credentials):
        require_service(credentials, facts_key)
        with connect(path, readonly=True) as conn:
            row = conn.execute('SELECT * FROM bookings WHERE booking_id = ?', (booking_id,)).fetchone()
        if row is None:
            raise Rejected('BOOKING_NOT_FOUND', 404)
        result = dict(row)
        for field in ('start_at', 'end_at'):
            result[field] = datetime.fromtimestamp(row[field], tz=timezone.utc).isoformat().replace('+00:00', 'Z')
        return result

    @app.get('/internal/session')
    def session_fact(credentials: Credentials, session_token: SessionHeader = None):
        require_service(credentials, facts_key)
        with connect(path, readonly=True) as conn:
            session = find_session(conn, session_token, clock()) if session_token else None
        if session is None:
            raise Rejected('SESSION_REQUIRED', 401)
        return dict(session)

    @app.get('/tool-openapi.json', include_in_schema=False)
    def tool_openapi():
        spec = app.openapi()
        return {'openapi': spec['openapi'], 'info': spec['info'],
                'servers': [{'url': tool_base_url or 'http://127.0.0.1:8000'}],
                'paths': {'/booking': spec['paths']['/booking']},
                'components': spec['components']}

    return app


def create_executor_app(executor: Executor | None = None, service_key: str | None = None,
                        demo_credentials: dict[str, str] | None = None) -> FastAPI:
    if executor is None:
        issuer = os.environ.get('ROLE_A_ISSUER', 'role-d')
        audience = os.environ.get('ROLE_A_AUDIENCE', 'role-a-executor')
        key_id = os.environ.get('ROLE_A_KEY_ID', 'role-d-v1')
        profile = os.environ.get('ROLE_A_PROFILE', 'evidence')
        if profile not in {'token', 'evidence'}:
            raise ValueError('ROLE_A_PROFILE must be token or evidence')
        key = load_pem_public_key(Path(os.environ['ROLE_A_D_PUBLIC_KEY']).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError('ROLE_A_D_PUBLIC_KEY must contain an Ed25519 public key')
        approvals = ApprovalVerifier()
        if config := os.environ.get('ROLE_B_FABRIC_CONFIG'):
            from role_b.approval import FabricApprovalSource

            approvals = ApprovalVerifier(source=FabricApprovalSource.from_config(Path(config)))
        executor = Executor(database_path(), TokenVerifier(issuer, audience, {key_id: key}),
                            approvals=approvals,
                            evidence_required=profile == 'evidence',
                            confirmation_required=os.environ.get('ROLE_A_REQUIRE_CONFIRMATION') == '1',
                            policy_version=os.environ.get('ROLE_A_POLICY_VERSION', 'policy-v1'),
                            tool_manifest_version=os.environ.get('ROLE_A_TOOL_VERSION', 'tools-v1'))
    service_key = service_key or required_secret('ROLE_A_EXECUTOR_KEY')
    if demo_credentials is None and os.environ.get('ROLE_A_DEMO_CREDENTIALS'):
        demo_credentials = TypeAdapter(dict[str, str]).validate_json(os.environ['ROLE_A_DEMO_CREDENTIALS'], strict=True)
        if any(len(value) < 24 for value in demo_credentials.values()):
            raise ValueError('Demo credentials require at least 24 characters each')
    app = make_app('Edge Agent Trust — Internal Executor')

    if demo_credentials:
        @app.post('/auth/demo-login')
        def demo_login(request: DemoLogin, credentials: Credentials):
            require_service(credentials, service_key)
            expected = demo_credentials.get(request.visitor_id)
            if expected is None or not secret_equal(request.credential, expected):
                raise Rejected('DEMO_LOGIN_REJECTED', 401)
            with write_transaction(executor.path) as conn:
                visitor = conn.execute("SELECT 1 FROM visitors WHERE visitor_id = ? AND status = 'active'",
                                       (request.visitor_id,)).fetchone()
                if visitor is None:
                    raise Rejected('DEMO_LOGIN_REJECTED', 401)
                return create_session(conn, request.visitor_id, executor.clock())

    @app.put('/internal/executor/confirmations/{operation_id}')
    def confirm(operation_id: Identifier, proposal: GrantProposal, credentials: Credentials,
                session_token: SessionHeader = None):
        require_service(credentials, service_key)
        restrict_action(proposal.action, proposal.args)
        now = executor.clock()
        with write_transaction(executor.path) as conn:
            session = find_session(conn, session_token, now) if session_token else None
            if session is None:
                raise Rejected('SESSION_REQUIRED', 401)
            digest = operation_digest(operation_id, proposal.action, session['visitor_id'], proposal.args)
            conn.execute(
                'INSERT INTO grant_confirmations VALUES (?, ?, ?, ?, ?) ON CONFLICT(operation_id) DO NOTHING',
                (operation_id, session['session_id'], digest, now, min(now + 300, session['expires_at'])),
            )
            row = conn.execute('SELECT * FROM grant_confirmations WHERE operation_id = ?', (operation_id,)).fetchone()
            if (row['session_id'], row['digest']) != (session['session_id'], digest) or row['expires_at'] <= now:
                raise Rejected('CONFIRMATION_CONFLICT', 409)
        return {'operation_id': operation_id, 'status': 'confirmed'}

    @app.post('/internal/executor/access-grants')
    def execute(request: ExecuteRequest, credentials: Credentials, session_token: SessionHeader = None):
        require_service(credentials, service_key)
        try:
            return executor.execute(request, session_token)
        except Rejected as exc:
            return JSONResponse({'operation_id': request.operation_id, 'status': 'rejected',
                                 'reason_code': exc.code}, status_code=exc.status)

    @app.get('/internal/executor/operations/{operation_id}')
    def operation_records(operation_id: Identifier, credentials: Credentials):
        require_service(credentials, service_key)
        with connect(executor.path, readonly=True) as conn:
            rows = conn.execute('''SELECT operation_id, action, status, reason_code, grant_id, recorded_at
                                   FROM execution_records WHERE operation_id = ? ORDER BY attempt_id''',
                                (operation_id,)).fetchall()
        if not rows:
            raise Rejected('OPERATION_NOT_FOUND', 404)
        return {'attempts': [dict(row) for row in rows]}

    return app
