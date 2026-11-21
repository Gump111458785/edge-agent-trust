"""Cloud tool for preparing a request and a separate visitor confirmation page."""
import base64
from contextlib import asynccontextmanager
from hashlib import sha256
from hmac import compare_digest, digest
from html import escape
import os
from time import time
from uuid import uuid4

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import Field, ValidationError

from business.app.authorization import Rejected, operation_digest
from business.app.main import Credentials, make_app, require_service, required_secret
from business.app.schemas import GrantProposal, Identifier, StrictModel
from business.app.executor import restrict_action
from gateway.main import service_url
from gateway.service import FactsClient


class Pending(GrantProposal):
    operation_id: Identifier
    session_id: Identifier
    approval_ref: str | None
    expires_at: int


class Confirmation(StrictModel):
    proposal: str = Field(max_length=2048)
    session_token: str = Field(min_length=1, max_length=256)


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def open_pending(value: str, key: bytes, now: int) -> Pending:
    try:
        payload, signature = value.split('.')
        if not compare_digest(encode(digest(key, payload.encode(), sha256)), signature):
            raise ValueError('signature')
        pending = Pending.model_validate_json(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    except (ValueError, ValidationError) as exc:
        raise Rejected('INVALID_PROPOSAL') from exc
    if now >= pending.expires_at:
        raise Rejected('PROPOSAL_EXPIRED', 410)
    return pending


def downstream(response: httpx.Response) -> dict:
    try:
        body = response.json()
        if response.is_success and isinstance(body, dict):
            return body
        if response.status_code in (401, 403, 404, 409, 410, 422, 503):
            code = body.get('reason_code') if isinstance(body, dict) else None
            if isinstance(code, str) and code.isascii() and code.isidentifier():
                raise Rejected(code, response.status_code)
    except ValueError:
        pass
    raise Rejected('SERVICE_UNAVAILABLE', 503)


def create_edge(facts: FactsClient, gateway: httpx.Client, executor: httpx.Client, *,
                public_url: str, tool_key: str, proposal_key: bytes, demo_session: str,
                gateway_key: str, executor_key: str, clock=lambda: int(time())) -> FastAPI:
    app = make_app('Campus access demonstration')

    @app.middleware('http')
    async def protect_response(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'self'; connect-src 'self'; "
            "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(httpx.RequestError)
    async def service_unavailable(request, exc):
        return JSONResponse({'status': 'rejected', 'reason_code': 'SERVICE_UNAVAILABLE'}, status_code=503)

    @app.post('/proposals', operation_id='prepare_access_request')
    def propose(proposal: GrantProposal, credentials: Credentials):
        require_service(credentials, tool_key)
        restricted = restrict_action(proposal.action, proposal.args)
        session = facts.session(demo_session)
        booking = facts.booking(proposal.args.booking_id)
        if booking.visitor_id != session.visitor_id:
            raise Rejected('BOOKING_NOT_FOUND', 404)
        operation_id = uuid4().hex
        approval = operation_digest(operation_id, proposal.action, session.visitor_id, proposal.args) if restricted else None
        pending = Pending(**proposal.model_dump(), operation_id=operation_id, approval_ref=approval,
                          session_id=session.session_id, expires_at=min(session.expires_at, clock() + 900))
        payload = encode(pending.model_dump_json().encode())
        signed = f'{payload}.{encode(digest(proposal_key, payload.encode(), sha256))}'
        return {'status': 'awaiting_visitor_confirmation', 'operation_id': operation_id,
                'approval_ref': approval, 'confirmation_url': f'{public_url}/review/{signed}'}

    @app.get('/tool-openapi.json', include_in_schema=False)
    def tool_openapi():
        spec = app.openapi()
        return {'openapi': spec['openapi'], 'info': spec['info'], 'servers': [{'url': public_url}],
                'paths': {'/proposals': spec['paths']['/proposals']}, 'components': spec['components']}

    @app.get('/review/{proposal}', response_class=HTMLResponse, include_in_schema=False)
    def review(proposal: str):
        pending = open_pending(proposal, proposal_key, clock())
        booking = escape(pending.args.booking_id)
        area = '机房' if pending.args.area == 'server_room' else '访客区'
        return f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>确认虚拟通行申请</title><h1>确认虚拟通行申请</h1>
<p>预约 {booking} · {area} · {pending.args.valid_minutes} 分钟。</p>
<p>只查询预约时，可关闭此页。确认会尝试开通虚拟通行权限。</p>
<form id="confirmation"><label>访客会话
<input id="session" required type="password" maxlength="256" autocomplete="off"></label>
<button type="submit">确认开通上述权限</button></form>
<p id="result" role="status"></p><script src="/confirmation.js" defer></script></html>"""

    @app.get('/confirmation.js', include_in_schema=False)
    def script():
        return Response("""
const form = document.getElementById('confirmation');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const field = document.getElementById('session');
  const result = document.getElementById('result');
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    const reply = await fetch('/confirm', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({proposal: location.pathname.split('/').pop(), session_token: field.value})
    });
    const body = await reply.json();
    result.textContent = body.status === 'executed' ? '已开通虚拟权限。' :
      '本次请求未返回开通成功。状态：' + (body.reason_code || body.status || reply.status);
    if (body.status === 'executed') field.value = '';
  } catch {
    result.textContent = '连接中断。可在此页重试同一笔申请。';
  } finally {
    button.disabled = false;
  }
});
""", media_type='text/javascript')

    @app.post('/confirm', include_in_schema=False)
    def confirm(request: Request, confirmation: Confirmation):
        if request.headers.get('origin') != public_url:
            raise Rejected('CONFIRMATION_ORIGIN_REQUIRED')
        pending = open_pending(confirmation.proposal, proposal_key, clock())
        session_token = confirmation.session_token
        session = facts.session(session_token)
        if session.session_id != pending.session_id:
            raise Rejected('SESSION_MISMATCH')
        operation = pending.operation_id
        proposal = GrantProposal(action=pending.action, args=pending.args).model_dump(mode='json')
        executor_headers = {'Authorization': f'Bearer {executor_key}', 'X-Session-Token': session_token}
        previous = executor.get(f'/internal/executor/operations/{operation}', headers=executor_headers)
        if previous.status_code != 404:
            for attempt in downstream(previous)['attempts']:
                if attempt['status'] == 'executed':
                    return {'operation_id': operation, 'status': 'executed', 'grant_id': attempt['grant_id']}
        downstream(executor.put(f'/internal/executor/confirmations/{operation}', json=proposal,
                                headers=executor_headers))
        gateway_headers = {'Authorization': f'Bearer {gateway_key}', 'X-Session-Token': session_token}
        authorization = downstream(gateway.post('/authorize', headers=gateway_headers, json={
            **proposal, 'operation_id': operation, 'approval_ref': pending.approval_ref,
        }))
        result = executor.post('/internal/executor/access-grants', headers=executor_headers, json=authorization)
        if result.status_code == 409 and result.json().get('reason_code') == 'AUTHORIZATION_REPLAY':
            for attempt in downstream(executor.get(f'/internal/executor/operations/{operation}',
                                                   headers=executor_headers))['attempts']:
                if attempt['status'] == 'executed':
                    return {'operation_id': operation, 'status': 'executed', 'grant_id': attempt['grant_id']}
        return downstream(result)

    return app


def create_app():
    public_url = service_url(os.environ['ROLE_E_PUBLIC_URL'])
    tool_key = required_secret('ROLE_E_TOOL_KEY')
    proposal_key = required_secret('ROLE_E_PROPOSAL_KEY')
    gateway_key = required_secret('ROLE_D_SERVICE_KEY')
    executor_key = required_secret('ROLE_A_EXECUTOR_KEY')
    facts_key = required_secret('ROLE_A_FACTS_KEY')
    session = required_secret('ROLE_E_DEMO_SESSION')
    if len({tool_key, proposal_key, gateway_key, executor_key, facts_key, session}) != 6:
        raise ValueError('Use distinct service keys and visitor credentials')
    urls = [service_url(os.environ.get(name, f'http://127.0.0.1:{port}'))
            for name, port in [('ROLE_D_FACTS_URL', 8000), ('ROLE_D_EXECUTOR_URL', 8001),
                               ('ROLE_E_GATEWAY_URL', 8002)]]
    facts, executor, gateway = [httpx.Client(base_url=url, timeout=90, trust_env=False) for url in urls]
    app = create_edge(FactsClient(facts, facts_key), gateway, executor, public_url=public_url,
                      tool_key=tool_key, proposal_key=proposal_key.encode(), demo_session=session,
                      gateway_key=gateway_key, executor_key=executor_key)

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            for client in (facts, executor, gateway):
                client.close()

    app.router.lifespan_context = lifespan
    return app
