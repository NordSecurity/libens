import base64
import datetime
import functools
import itertools
import queue
import sys
import threading

import ens
import Pyro5.api
import Pyro5.server

APP_VERSION = "libens-system-tests"
PORT_PREFIX = "ens-port:"
BACKOFF_INITIAL_SECONDS = 1
BACKOFF_MAXIMAL_SECONDS = 2
PQ_ONLY = "only"


def plain_errors(method):
    @functools.wraps(method)
    def wrap(*args):
        try:
            return method(*args)
        except ens.EnsError as e:
            raise RuntimeError(repr(e)) from None

    return wrap


class Events(ens.ErrorNotificationCallback):
    def __init__(self):
        self._queue = queue.Queue()

    def notify(self, notification):
        self._queue.put(
            {
                "type": "notify",
                "kind": type(notification.kind).__name__.rsplit(".", 1)[-1],
                "additional_info": notification.additional_info,
            }
        )

    def disconnected(self, reason):
        self._queue.put({"type": "disconnected", "reason": reason})

    def next(self, timeout):
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None


class Logs(ens.LogCallback):
    def __init__(self, path):
        self._file = open(path, "a", encoding="utf-8")
        self._lines = []
        self._lock = threading.Lock()

    def log(self, log_level, message):
        now = datetime.datetime.now(datetime.timezone.utc)  # noqa: UP017
        time = now.isoformat(" ", "milliseconds")
        line = f"{time} {log_level.name} {message}"
        with self._lock:
            self._lines.append(line)
            self._file.write(line + "\n")
            self._file.flush()

    def has_text(self, text):
        with self._lock:
            return any(text in line for line in self._lines)


@Pyro5.api.expose
class EnsRemote:
    def __init__(self, daemon, logs):
        self._daemon = daemon
        self._logs = logs
        self._connection_ids = itertools.count()
        self._sessions = {}

    @plain_errors
    def connect(  # noqa: PLR0913
        self,
        address,
        private_key,
        server_public_key,
        root_certificate,
        pq_mode,
        keepalive_seconds,
    ):
        keys = ens.Keys(
            local_private_key=base64.b64decode(private_key),
            vpn_public_key=base64.b64decode(server_public_key),
            kind=ens.KeyKind.NORD_LYNX,
        )

        config = ens.Config()
        config.set_allow_only_pq(pq_mode == PQ_ONLY)
        config.set_root_certificate_override(base64.b64decode(root_certificate))
        config.set_backoff_initial(BACKOFF_INITIAL_SECONDS)
        config.set_backoff_maximal(BACKOFF_MAXIMAL_SECONDS)

        if keepalive_seconds is not None:
            config.set_keepalive_interval(keepalive_seconds)
            config.set_keepalive_timeout(keepalive_seconds)

        events = Events()
        connection = ens.connect(
            address, None, ens.Authentication.WITH_KEYS(keys), events, config
        )

        connection_id = next(self._connection_ids)
        self._sessions[connection_id] = (connection, events)
        return connection_id

    @plain_errors
    def shutdown(self, connection_id):
        connection, _ = self._sessions[connection_id]
        connection.shutdown()

    @Pyro5.api.oneway
    def stop(self):
        for connection, _ in self._sessions.values():
            connection.shutdown()

        ens.deinit()
        self._daemon.shutdown()

    def next_event(self, connection_id, timeout):
        _, events = self._sessions[connection_id]
        return events.next(timeout)

    def has_log(self, text):
        return self._logs.has_text(text)


def main():
    object_name, bind_ip, log_file = sys.argv[1:4]

    logs = Logs(log_file)
    ens.set_log_callback(ens.LogLevel.DEBUG, logs)
    ens.init(APP_VERSION)

    with Pyro5.server.Daemon(host=bind_ip, port=0) as daemon:
        daemon.register(EnsRemote(daemon, logs), object_name)
        _, port = daemon.sock.getsockname()
        print(f"{PORT_PREFIX}{port}", flush=True)
        daemon.requestLoop()


if __name__ == "__main__":
    main()
