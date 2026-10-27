import base64
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from natlab.connection import Connection

from helpers import nlx
from helpers.utils import wait_until

IFACE = "ens"
KEY_FILE = f"/tmp/{IFACE}.key"
WIREGUARD_GO = "/opt/bin/wireguard-go"
ALLOWED_IPS = "10.5.0.1/32"
KEEPALIVE_SECONDS = 1
NO_HANDSHAKE = "0"
HANDSHAKE_TIMEOUT = 30

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Key:
    private: str
    public: str


def new_key() -> Key:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return Key(
        base64.b64encode(private_raw).decode(),
        base64.b64encode(public_raw).decode(),
    )


async def _configure(conn: Connection, key: Key) -> None:
    await conn.create_process(
        ["sh", "-c", f"echo {key.private} > {KEY_FILE}"]
    ).execute()

    try:
        await conn.create_process(
            [
                "wg", "set", IFACE,
                "private-key", KEY_FILE,
                "peer", nlx.PUBLIC_KEY,
                "endpoint", nlx.WIREGUARD_ENDPOINT,
                "allowed-ips", ALLOWED_IPS,
                "persistent-keepalive", str(KEEPALIVE_SECONDS),
            ]
        ).execute()  # fmt: skip
    finally:
        await conn.create_process(["rm", KEY_FILE]).execute()


@asynccontextmanager
async def handshake(conn: Connection, key: Key) -> AsyncIterator[None]:
    await conn.create_process([WIREGUARD_GO, IFACE]).execute()

    try:
        await conn.create_process(["ip", "link", "set", IFACE, "up"]).execute()
        await _configure(conn, key)
        log.info("[%s] wireguard up, key %s", conn.name, key.public)
        yield
    finally:
        await conn.create_process(["ip", "link", "del", IFACE]).execute()
        log.info("[%s] wireguard down", conn.name)


async def wait_handshake(conn: Connection) -> None:
    async def done() -> bool:
        process = await conn.create_process(
            ["wg", "show", IFACE, "latest-handshakes"]
        ).execute()
        _, latest = process.get_stdout().split()
        return latest != NO_HANDSHAKE

    await wait_until(done, HANDSHAKE_TIMEOUT, f"[{conn.name}] wireguard handshake")
    log.info("[%s] handshake done", conn.name)
