import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from natlab.connection import Connection

log = logging.getLogger(__name__)


def _rule(port: int) -> list[str]:
    return [
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-j",
        "REJECT",
        "--reject-with",
        "tcp-reset",
    ]


@asynccontextmanager
async def block_tcp(conn: Connection, port: int) -> AsyncIterator[None]:
    await conn.create_process(["iptables", "-I", *_rule(port)]).execute()
    log.info("[%s] tcp %d blocked", conn.name, port)

    try:
        yield
    finally:
        await conn.create_process(["iptables", "-D", *_rule(port)]).execute()
        log.info("[%s] tcp %d unblocked", conn.name, port)
