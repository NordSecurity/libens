import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path

import pytest
from natlab.connection import SshConnection
from natlab.lab import Lab

from ens_client import EnsClient
from helpers import nlx

LOGS_DIR = "natlab-logs"

logging.Formatter.converter = time.gmtime


def _logs_dir(config: pytest.Config) -> Path:
    state = config.getoption("--lab-state")
    root = Path(state).resolve().parent if state else config.rootpath
    return root / LOGS_DIR


def _nlx_connection() -> AbstractAsyncContextManager[SshConnection]:
    return SshConnection.new_connection(
        nlx.IP, name=nlx.NAME, password=nlx.SSH_PASSWORD
    )


async def _download_nlx_logs(directory: Path) -> None:
    async with _nlx_connection() as conn:
        await nlx.download_logs(conn, directory)


@pytest.fixture(scope="session", autouse=True)
def nlx_logs(request, lab):
    yield
    asyncio.run(_download_nlx_logs(_logs_dir(request.config) / nlx.NAME))


@pytest.fixture
async def nlx_conn():
    async with _nlx_connection() as conn:
        yield conn


@pytest.fixture
async def root_certificate(nlx_conn):
    return await nlx.root_certificate(nlx_conn)


@pytest.fixture
async def fingerprint(nlx_conn):
    return await nlx.fingerprint(nlx_conn)


@asynccontextmanager
async def _ens_client(
    request: pytest.FixtureRequest, lab: Lab, name: str
) -> AsyncIterator[EnsClient]:
    path = _logs_dir(request.config) / request.node.name / f"{name}.log"
    async with lab.connection(name) as conn:
        async with EnsClient.start(conn, path) as client:
            yield client


@pytest.fixture
async def ens_client_01(request, lab):
    async with _ens_client(request, lab, "cone-client-01") as client:
        yield client


@pytest.fixture
async def ens_client_02(request, lab):
    async with _ens_client(request, lab, "cone-client-02") as client:
        yield client
