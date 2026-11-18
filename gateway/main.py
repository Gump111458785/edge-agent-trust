from contextlib import asynccontextmanager
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import Depends

from business.app.main import (Credentials, SessionHeader, make_app, require_service,
                               required_secret)
from business.app.schemas import ExecuteRequest
from trusted_release.handoff import open_store

from .service import DecisionLog, FactsClient, Gateway, Proposal


def create_gateway_app(gateway: Gateway, service_key: str):
    if len(service_key) < 24:
        raise ValueError('Gateway service key requires at least 24 characters')
    app = make_app('Edge Agent Trust - Role D Gateway')

    def authenticate(credentials: Credentials):
        require_service(credentials, service_key)

    @app.post('/authorize', response_model=ExecuteRequest, dependencies=[Depends(authenticate)])
    def authorize(proposal: Proposal, session_token: SessionHeader = None):
        return gateway.authorize(proposal, session_token)

    @app.middleware('http')
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        return response

    return app


def service_url(value: str) -> str:
    url = urlsplit(value)
    # Plain HTTP is limited to local development. Use HTTPS for remote services.
    if (url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in {'', '/'}
            or (url.scheme == 'http' and url.hostname not in {'localhost', '127.0.0.1', '::1'})):
        raise ValueError('Service URL must be an HTTPS origin or local HTTP origin')
    _ = url.port
    return value.rstrip('/')


def create_app():
    facts_url = service_url(os.environ.get('ROLE_D_FACTS_URL', 'http://127.0.0.1:8000'))
    executor_url = service_url(os.environ.get('ROLE_D_EXECUTOR_URL', 'http://127.0.0.1:8001'))
    key = load_pem_private_key(Path(os.environ['ROLE_D_PRIVATE_KEY']).read_bytes(), password=None)
    store = open_store(Path(os.environ['ROLE_C_TRUST_CONFIG']))
    facts_key = required_secret('ROLE_A_FACTS_KEY')
    service_key = required_secret('ROLE_D_SERVICE_KEY')
    client = httpx.Client(base_url=facts_url, timeout=5, trust_env=False)
    try:
        gateway = Gateway(
            FactsClient(client, facts_key), store, key,
            DecisionLog(Path(os.environ.get('ROLE_D_AUDIT_DB', 'gateway/data/decisions.sqlite3'))),
            executor_url + '/internal/executor/access-grants',
            issuer=os.environ.get('ROLE_A_ISSUER', 'role-d'),
            audience=os.environ.get('ROLE_A_AUDIENCE', 'role-a-executor'),
            key_id=os.environ.get('ROLE_A_KEY_ID', 'role-d-v1'),
            policy_id=os.environ.get('ROLE_C_POLICY_ID', 'campus-policy'),
            tools_id=os.environ.get('ROLE_C_TOOLS_ID', 'campus-tools'),
            lifetime_seconds=int(os.environ.get('ROLE_D_TOKEN_TTL', '60')))
        app = create_gateway_app(gateway, service_key)
    except BaseException:
        client.close()
        raise

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            client.close()

    app.router.lifespan_context = lifespan
    return app
