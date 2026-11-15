"""Dify-facing entrance for the synthetic Role A booking service."""

from pathlib import Path
from secrets import token_urlsafe

from fastapi import Request

from .main import create_business_app


def create_public_booking_app(path: Path | None = None, tool_base_url: str | None = None):
    app = create_business_app(path=path, facts_key=token_urlsafe(32), tool_base_url=tool_base_url)
    paths = {'/booking', '/tool-openapi.json'}
    app.router.routes[:] = [route for route in app.router.routes
                            if route.path in paths and route.methods == {'GET'}]
    app.router.redirect_slashes = False

    @app.middleware('http')
    async def do_not_cache(request: Request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        return response

    return app
