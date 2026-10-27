import base64
import datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ens_client import EventType, NotificationKind, PqMode
from helpers import nlx
from helpers.firewall import block_tcp
from helpers.wireguard import handshake, new_key, wait_handshake

KEEPALIVE_SECONDS = 2
STREAM_DROPPED = "ConnectionReset"
USER = "ens_test_user"
UNKNOWN_CA = "unknown test ca"


def _assert_notification_kind(event: dict[str, Any], kind: NotificationKind) -> None:
    assert event["kind"] == kind.value, f"expected {kind.value}, got {event}"


def _unknown_root_certificate() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, UNKNOWN_CA)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode()


@pytest.mark.parametrize("pq_mode", list(PqMode))
async def test_maintenance(
    nlx_conn, ens_client_01, root_certificate, fingerprint, pq_mode
):
    """
    Check client gets maintenance notification from ENS, with and without PQ only

    Steps:
        1. Do wireguard handshake with nlx server from client 1
        2. Connect to ENS with the same key
        3. Wait until TLS session with nlx server is established
        4. Put nlx server into maintenance
        5. Check client gets SERVER_MAINTENANCE notification
    """
    key = new_key()

    async with handshake(ens_client_01.conn, key):
        await wait_handshake(ens_client_01.conn)
        connection_id = await ens_client_01.connect(key, root_certificate, pq_mode)
        await ens_client_01.wait_log(fingerprint)

        async with nlx.maintenance(nlx_conn):
            event = await ens_client_01.wait_event(connection_id, EventType.NOTIFY)

    _assert_notification_kind(event, NotificationKind.SERVER_MAINTENANCE)


async def test_unauthenticated(nlx_conn, ens_client_01, root_certificate):
    """
    Check client gets unauthenticated notification when its key is not allowed

    Steps:
        1. Switch fakefm to dynamic api mode, where no user is allowed
        2. Do wireguard handshake with nlx server from client 1
        3. Connect to ENS with the same key
        4. Check client gets UNAUTHENTICATED notification
    """
    key = new_key()

    async with nlx.fakefm(nlx_conn, nlx.FakeFmMode.DYNAMIC_API):
        async with handshake(ens_client_01.conn, key):
            connection_id = await ens_client_01.connect(key, root_certificate)
            event = await ens_client_01.wait_event(connection_id, EventType.NOTIFY)

    _assert_notification_kind(event, NotificationKind.UNAUTHENTICATED)


async def test_connection_limit_reached(
    nlx_conn, ens_client_01, ens_client_02, root_certificate, fingerprint
):
    """
    Check client gets connection limit notification when user has too many connections

    Steps:
        1. Switch fakefm to dynamic api mode and set connection limit to 1
        2. Allow first key for the user
        3. Do wireguard handshake and connect to ENS with first key from client 1
        4. Allow second key for the same user
        5. Do wireguard handshake and connect to ENS with second key from client 2
        6. Check client 2 gets CONNECTION_LIMIT_REACHED notification
    """
    first, second = new_key(), new_key()

    async with nlx.fakefm(nlx_conn, nlx.FakeFmMode.DYNAMIC_API):
        await nlx.set_users_limits(1)

        await nlx.add_allowed_user(USER, first.public)
        async with handshake(ens_client_01.conn, first):
            await wait_handshake(ens_client_01.conn)
            await ens_client_01.connect(first, root_certificate)
            await ens_client_01.wait_log(fingerprint)

            await nlx.add_allowed_user(USER, second.public)
            async with handshake(ens_client_02.conn, second):
                connection_id = await ens_client_02.connect(second, root_certificate)
                event = await ens_client_02.wait_event(connection_id, EventType.NOTIFY)

    _assert_notification_kind(event, NotificationKind.CONNECTION_LIMIT_REACHED)


async def test_fakefm_restored(nlx_conn):
    """
    Check fakefm is switched back to default mode when test fails

    Steps:
        1. Switch fakefm to dynamic api mode
        2. Raise error
        3. Check default fakefm service is active again
    """
    with pytest.raises(RuntimeError):
        async with nlx.fakefm(nlx_conn, nlx.FakeFmMode.DYNAMIC_API):
            raise RuntimeError

    await nlx.wait_active(nlx_conn, nlx.FakeFmMode.ACCEPT_ANY.value)


async def test_superseded(ens_client_01, ens_client_02, root_certificate, fingerprint):
    """
    Check client gets superseded notification when the same key connects from another place

    Steps:
        1. Do wireguard handshake and connect to ENS from client 1
        2. Do wireguard handshake and connect to ENS with the same key from client 2
        3. Check client 1 gets SUPERSEDED notification
    """
    key = new_key()

    async with handshake(ens_client_01.conn, key):
        await wait_handshake(ens_client_01.conn)
        connection_id = await ens_client_01.connect(key, root_certificate)
        await ens_client_01.wait_log(fingerprint)

        async with handshake(ens_client_02.conn, key):
            await wait_handshake(ens_client_02.conn)
            await ens_client_02.connect(key, root_certificate)
            await ens_client_02.wait_log(fingerprint)

            event = await ens_client_01.wait_event(connection_id, EventType.NOTIFY)

    _assert_notification_kind(event, NotificationKind.SUPERSEDED)


async def test_wrong_root_certificate(ens_client_01):
    """
    Check client stops when server certificate is not signed by given root certificate

    Steps:
        1. Do wireguard handshake with nlx server from client 1
        2. Connect to ENS with root certificate of unknown CA
        3. Check client gets disconnected
        4. Check no more events come
    """
    key = new_key()

    async with handshake(ens_client_01.conn, key):
        await wait_handshake(ens_client_01.conn)
        connection_id = await ens_client_01.connect(key, _unknown_root_certificate())

        await ens_client_01.wait_event(connection_id, EventType.DISCONNECTED)
        await ens_client_01.assert_no_event(connection_id)


async def test_ens_unreachable(nlx_conn, ens_client_01, root_certificate, fingerprint):
    """
    Check client connects to ENS once it becomes reachable

    Steps:
        1. Do wireguard handshake with nlx server from client 1
        2. Block ENS port on client 1
        3. Connect to ENS
        4. Check no events come while port is blocked
        5. Unblock ENS port
        6. Wait until TLS session with nlx server is established
        7. Put nlx server into maintenance
        8. Check client gets SERVER_MAINTENANCE notification
    """
    key = new_key()

    async with handshake(ens_client_01.conn, key):
        await wait_handshake(ens_client_01.conn)

        async with block_tcp(ens_client_01.conn, nlx.ENS_PORT):
            connection_id = await ens_client_01.connect(key, root_certificate)
            await ens_client_01.assert_no_event(connection_id)

        await ens_client_01.wait_log(fingerprint)

        async with nlx.maintenance(nlx_conn):
            event = await ens_client_01.wait_event(connection_id, EventType.NOTIFY)

    _assert_notification_kind(event, NotificationKind.SERVER_MAINTENANCE)


async def test_ens_reconnect(nlx_conn, ens_client_01, root_certificate, fingerprint):
    """
    Check client reconnects to ENS after connection is lost

    Steps:
        1. Do wireguard handshake with nlx server from client 1
        2. Connect to ENS with short keepalive
        3. Wait until TLS session with nlx server is established
        4. Block ENS port on client 1
        5. Wait until client detects lost connection
        6. Unblock ENS port
        7. Put nlx server into maintenance
        8. Check client gets SERVER_MAINTENANCE notification
    """
    key = new_key()

    async with handshake(ens_client_01.conn, key):
        await wait_handshake(ens_client_01.conn)
        connection_id = await ens_client_01.connect(
            key, root_certificate, keepalive_seconds=KEEPALIVE_SECONDS
        )
        await ens_client_01.wait_log(fingerprint)

        async with block_tcp(ens_client_01.conn, nlx.ENS_PORT):
            await ens_client_01.wait_log(STREAM_DROPPED)

        async with nlx.maintenance(nlx_conn):
            event = await ens_client_01.wait_event(connection_id, EventType.NOTIFY)

    _assert_notification_kind(event, NotificationKind.SERVER_MAINTENANCE)


async def test_shutdown(ens_client_01, root_certificate, fingerprint):
    """
    Check client gets disconnected with shutdown reason after shutting down connection

    Steps:
        1. Do wireguard handshake with nlx server from client 1
        2. Connect to ENS with the same key
        3. Wait until TLS session with nlx server is established
        4. Shut down the connection
        5. Check client gets disconnected with shutdown reason
        6. Check no more events come
    """
    key = new_key()

    async with handshake(ens_client_01.conn, key):
        await wait_handshake(ens_client_01.conn)
        connection_id = await ens_client_01.connect(key, root_certificate)
        await ens_client_01.wait_log(fingerprint)

        await ens_client_01.shutdown(connection_id)
        event = await ens_client_01.wait_event(connection_id, EventType.DISCONNECTED)
        await ens_client_01.assert_no_event(connection_id)

    assert event["reason"] == "shutdown", f"expected shutdown, got {event}"
