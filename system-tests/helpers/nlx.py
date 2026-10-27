import base64
import hashlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from natlab.connection import Connection
from natlab.process import ProcessExecError

from helpers.utils import request_json, wait_until

NAME = "nlx-01"
IP = "10.0.100.51"
ENS_PORT = 993
ENS_ADDRESS = f"{IP}:{ENS_PORT}"
WIREGUARD_ENDPOINT = f"{IP}:1023"
PUBLIC_KEY = "csmoelQgK1QvyE5+XmZnXaPNt/zCgk84BG6BwfcmOFE="
SSH_PASSWORD = "root"
CERT_PATH = "/etc/ca-certificates/server-cert.pem.test"

INFO_API = f"http://{IP}:6969/api/v1"
INFO_TOKEN = "nat-lab-ens-info-api-secret-0123"
MAINTENANCE_STATE = "MAINTENANCE"
NS_SERVICE = "nlx-ns"

FAKEFM_API = f"http://{IP}:7777"

LOGS = [
    "/var/log/nlx-ns.log",
    "/var/log/nlx-radius.log",
    "/var/log/fakefm.log",
    "/var/log/dynamic_api_fakefm.log",
]

SERVICE_TIMEOUT = 10
ACTIVE = "active"


log = logging.getLogger(__name__)


class FakeFmMode(Enum):
    ACCEPT_ANY = "fakefm.service"
    DYNAMIC_API = "fakefm_dynamic_api.service"


async def _certificates(conn: Connection) -> list[x509.Certificate]:
    process = await conn.create_process(["cat", CERT_PATH]).execute()
    return x509.load_pem_x509_certificates(process.get_stdout().encode())


async def root_certificate(conn: Connection) -> str:
    for cert in await _certificates(conn):
        if cert.issuer != cert.subject:
            continue

        return base64.b64encode(cert.public_bytes(Encoding.DER)).decode()

    raise ValueError(f"No root certificate in {CERT_PATH}")


async def fingerprint(conn: Connection) -> str:
    leaf, *_ = await _certificates(conn)
    return hashlib.sha256(leaf.public_bytes(Encoding.DER)).hexdigest()


async def _service_state(conn: Connection, service: str) -> str:
    try:
        process = await conn.create_process(
            ["systemctl", "is-active", service]
        ).execute()
        return process.get_stdout().strip()
    except ProcessExecError as e:
        return e.stdout.strip()


async def wait_active(conn: Connection, service: str) -> None:
    async def active() -> bool:
        return await _service_state(conn, service) == ACTIVE

    await wait_until(active, SERVICE_TIMEOUT, f"[{conn.name}] {service} active")


async def _set_maintenance(endpoint: str) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {INFO_TOKEN}"}
    return await request_json(f"{INFO_API}/maintenance/{endpoint}", headers=headers)


async def _restarts(conn: Connection) -> int:
    process = await conn.create_process(
        ["systemctl", "show", "-p", "NRestarts", "--value", NS_SERVICE]
    ).execute()
    return int(process.get_stdout())


async def _wait_restart(conn: Connection, restarts: int) -> None:
    async def restarted() -> bool:
        return await _restarts(conn) > restarts

    await wait_until(restarted, SERVICE_TIMEOUT, f"[{conn.name}] {NS_SERVICE} restart")
    await wait_active(conn, NS_SERVICE)


@asynccontextmanager
async def maintenance(conn: Connection) -> AsyncIterator[None]:
    data = await _set_maintenance("on")

    try:
        assert data.get("state") == MAINTENANCE_STATE, data
        log.info("maintenance on")
        yield
    finally:
        restarts = await _restarts(conn)
        await _set_maintenance("off")
        await _wait_restart(conn, restarts)
        log.info("maintenance off")


async def _switch_fakefm(conn: Connection, old: FakeFmMode, new: FakeFmMode) -> None:
    try:
        await conn.create_process(["systemctl", "stop", old.value]).execute()
    finally:
        await conn.create_process(["systemctl", "start", new.value]).execute()

    await wait_active(conn, new.value)
    log.info("fakefm %s", new.name)


@asynccontextmanager
async def fakefm(conn: Connection, mode: FakeFmMode) -> AsyncIterator[None]:
    try:
        await _switch_fakefm(conn, FakeFmMode.ACCEPT_ANY, mode)
        yield
    finally:
        await _switch_fakefm(conn, mode, FakeFmMode.ACCEPT_ANY)


async def _fakefm_call(endpoint: str) -> None:
    data = await request_json(f"{FAKEFM_API}/{endpoint}")
    assert data.get("success"), data


async def add_allowed_user(username: str, password: str) -> None:
    await _fakefm_call(f"addAllowedUser?username={quote(username)}&password={password}")
    log.info("user %s allowed, key %s", username, password)


async def set_users_limits(limit: int) -> None:
    await _fakefm_call(f"setUsersLimits?limit={limit}")
    log.info("users limit %d", limit)


async def download_logs(conn: Connection, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for path in LOGS:
        await conn.download(path, str(directory))
