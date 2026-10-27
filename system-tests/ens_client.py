import asyncio
import logging
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Any

import Pyro5.api
from natlab.connection import DockerConnection

from helpers import nlx
from helpers.utils import wait_until
from helpers.wireguard import Key

MOUNT = os.environ.get("NATLAB_CONSUMER_MOUNT", "/libens")
REMOTE = f"{MOUNT}/system-tests/remote/ens_remote.py"
LOG_DIR = "/tmp"
PORT_PREFIX = "ens-port:"
STARTUP_TIMEOUT = 30
STOP_TIMEOUT = 10
EVENT_TIMEOUT = 30
QUIET_SECONDS = 5

log = logging.getLogger(__name__)


class EventType(Enum):
    NOTIFY = "notify"
    DISCONNECTED = "disconnected"


class PqMode(Enum):
    ONLY = "only"
    ALLOWED = "allowed"


class NotificationKind(Enum):
    CONNECTION_LIMIT_REACHED = "CONNECTION_LIMIT_REACHED"
    SERVER_MAINTENANCE = "SERVER_MAINTENANCE"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    SUPERSEDED = "SUPERSEDED"


async def _save_logs(
    conn: DockerConnection, log_file: str, stderr: list[str], path: Path
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    await conn.download(log_file, str(path))

    with path.open("a") as f:
        f.write(f"--- stderr ---\n{''.join(stderr)}")


class EnsClient:
    def __init__(self, conn: DockerConnection, uri: str) -> None:
        self._conn = conn
        self._uri = uri

    @property
    def conn(self) -> DockerConnection:
        return self._conn

    @classmethod
    @asynccontextmanager
    async def start(
        cls, conn: DockerConnection, log_path: Path
    ) -> AsyncIterator["EnsClient"]:
        port: asyncio.Future[str] = asyncio.get_running_loop().create_future()

        async def on_stdout(stdout: str) -> None:
            for line in stdout.splitlines():
                if line.startswith(PORT_PREFIX) and not port.done():
                    port.set_result(line.removeprefix(PORT_PREFIX))

        stderr: list[str] = []

        async def on_stderr(output: str) -> None:
            stderr.append(output)

        object_name = uuid.uuid4().hex
        log_file = f"{LOG_DIR}/ens_remote_{object_name}.log"
        _, ip = await conn.get_ip_address()
        process = conn.create_process(["python3", REMOTE, object_name, ip, log_file])

        try:
            async with process.run(
                stdout_callback=on_stdout, stderr_callback=on_stderr
            ) as running:
                remote_port = await asyncio.wait_for(port, STARTUP_TIMEOUT)
                client = cls(conn, f"PYRO:{object_name}@{ip}:{remote_port}")
                yield client

                await client._call("stop")
                await asyncio.wait_for(running.is_done(), STOP_TIMEOUT)
        finally:
            await _save_logs(conn, log_file, stderr, log_path)

    async def _call(self, method: str, *args: Any) -> Any:
        def call() -> Any:
            with Pyro5.api.Proxy(self._uri) as proxy:
                return getattr(proxy, method)(*args)

        return await asyncio.to_thread(call)

    async def connect(
        self,
        key: Key,
        root_certificate: str,
        pq_mode: PqMode = PqMode.ONLY,
        keepalive_seconds: int | None = None,
    ) -> int:
        connection_id = await self._call(
            "connect",
            nlx.ENS_ADDRESS,
            key.private,
            nlx.PUBLIC_KEY,
            root_certificate,
            pq_mode.value,
            keepalive_seconds,
        )
        log.info("[%s] connection %d started", self._conn.name, connection_id)
        return connection_id

    async def shutdown(self, connection_id: int) -> None:
        await self._call("shutdown", connection_id)
        log.info("[%s] connection %d shut down", self._conn.name, connection_id)

    async def _next_event(
        self, connection_id: int, timeout: float
    ) -> dict[str, Any] | None:
        return await self._call("next_event", connection_id, timeout)

    async def wait_event(
        self, connection_id: int, event_type: EventType
    ) -> dict[str, Any]:
        event = await self._next_event(connection_id, EVENT_TIMEOUT)
        assert event is not None, f"no {event_type.value} within {EVENT_TIMEOUT}s"
        assert (
            event["type"] == event_type.value
        ), f"expected {event_type.value}, got {event}"
        log.info("[%s] connection %d got %s", self._conn.name, connection_id, event)
        return event

    async def assert_no_event(self, connection_id: int) -> None:
        event = await self._next_event(connection_id, QUIET_SECONDS)
        assert event is None, f"expected no event, got {event}"

    async def wait_log(self, text: str) -> None:
        async def logged() -> bool:
            return await self._call("has_log", text)

        await wait_until(logged, EVENT_TIMEOUT, f"[{self._conn.name}] log {text!r}")
        log.info("[%s] logged %s", self._conn.name, text)
