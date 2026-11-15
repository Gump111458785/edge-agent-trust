"""Start a temporary HTTPS demo of the real SQLite booking query."""

import json
from pathlib import Path
import re
from shutil import which
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from time import monotonic, sleep, time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

import uvicorn

from .db import create_session, initialize, seed, write_transaction
from .public_booking import create_public_booking_app


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


https_client = build_opener(RejectRedirects())


def tunnel_url(tunnel: subprocess.Popen, log: Path) -> str:
    deadline = monotonic() + 25
    while tunnel.poll() is None and monotonic() < deadline:
        match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com\b', log.read_text())
        if match:
            return match[0]
        sleep(0.25)
    raise RuntimeError(f'Cloudflare did not issue a hostname.\n{log.read_text()[-2200:]}')


def request(url: str, *, token: str | None = None, method: str = 'GET') -> tuple[int, bytes]:
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    try:
        with https_client.open(Request(url, headers=headers, method=method), timeout=4) as response:
            return response.status, response.read(65536)
    except HTTPError as exc:
        with exc:
            return exc.code, exc.read(65536)


def verify(url: str, token: str) -> None:
    booking = f'{url}/booking?booking_id=BK-1042'
    deadline = monotonic() + 30
    failure = 'no HTTPS response'
    while monotonic() < deadline:
        try:
            status, body = request(f'{url}/tool-openapi.json')
            if status == 200:
                spec = json.loads(body)
                if (spec.get('servers') != [{'url': url}] or set(spec.get('paths', {})) != {'/booking'}
                        or spec['paths']['/booking'].get('get', {}).get('operationId') != 'query_booking'):
                    raise RuntimeError('Public OpenAPI schema does not match the booking tool')
                break
            failure = f'HTTP {status}'
        except (URLError, TimeoutError) as exc:
            failure = str(exc)
        sleep(0.5)
    else:
        raise RuntimeError(f'Public HTTPS endpoint did not become reachable ({failure})')

    if request(booking)[0] != 401:
        raise RuntimeError('Booking endpoint did not require a session')
    status, body = request(booking, token=token)
    if status != 200 or json.loads(body).get('status') != 'confirmed':
        raise RuntimeError('Booking endpoint did not return the seeded SQLite booking')
    if request(f'{url}/booking?booking_id=BK-1043', token=token)[0] != 404:
        raise RuntimeError('Booking endpoint did not enforce visitor scope')
    if (request(f'{url}/internal/bookings/BK-1042')[0] != 404
            or request(f'{url}/internal/executor/access-grants', method='POST')[0] != 404):
        raise RuntimeError('An internal service route is reachable through the tunnel')


def main() -> None:
    cloudflared = which('cloudflared')
    if cloudflared is None:
        raise SystemExit('Install cloudflared before starting the HTTPS demo.')
    with TemporaryDirectory(prefix='role-a-https-') as directory, socket.socket() as listener:
        directory = Path(directory)
        database = directory / 'campus.sqlite3'
        initialize(database)
        now = int(time())
        seed(database, now)
        with write_transaction(database) as conn:
            session = create_session(conn, 'V001', now)
        token_file = directory / 'booking-token'
        token_file.touch(mode=0o600)
        token_file.write_text(session['session_token'] + '\n')
        listener.bind(('127.0.0.1', 0))
        origin = f'http://127.0.0.1:{listener.getsockname()[1]}'
        log = directory / 'cloudflared.log'
        cmd = [cloudflared, 'tunnel', '--no-autoupdate', '--url', origin]
        with log.open('w') as output, subprocess.Popen(cmd, stdout=output, stderr=subprocess.STDOUT) as tunnel:
            try:
                url = tunnel_url(tunnel, log)
                app = create_public_booking_app(database, url)
                config = uvicorn.Config(app, log_level='warning', access_log=False,
                                        proxy_headers=False, ws='none')
                server = uvicorn.Server(config)
                worker = Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
                worker.start()
                try:
                    verify(url, session['session_token'])
                    print(f'A HTTPS 地址 {url}\nDify 工具定义 {url}/tool-openapi.json\n'
                          f'临时 Bearer 会话文件（仅本机） {token_file}\n'
                          '临时会话有效期 1 小时。保持此终端运行，按 Ctrl+C 停止。', flush=True)
                    tunnel.wait()
                    raise RuntimeError('Cloudflare tunnel stopped.')
                finally:
                    server.should_exit = True
                    worker.join(timeout=5)
            finally:
                if tunnel.poll() is None:
                    tunnel.terminate()
                    try:
                        tunnel.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        tunnel.kill()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
