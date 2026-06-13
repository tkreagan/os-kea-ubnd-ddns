# SPDX-License-Identifier: BSD-2-Clause
"""
Paramiko-based SSH session — supports both password and key-based auth.

Adapted from tests/integration/conftest.py:SSHSession — same behaviour but
no pytest dependency, so it can be used in standalone scripts.
"""
from __future__ import annotations

import pathlib
import time
from typing import Union


class SSHSession:
    """
    SSH session via paramiko, supporting password or key-file auth.

    Key auth (NOPASSWD sudo):
        s = SSHSession("host", "del", key_file="~/.ssh/del_rgn.cm.private")
        out = s.sudo("cat /etc/shadow")  # uses sudo -n (no password)

    Password auth:
        s = SSHSession("host", "user", password="pass")
        out = s.sudo("cmd")             # injects password via stdin

    Other methods:
        s.run("cmd")                    # no privilege escalation
        s.script("python3", "code")     # feed code over stdin
        s.sftp_put("/local", "/remote")
        s.close()
    """

    def __init__(self, host: str, user: str, password: str = "",
                 sudo_password: str | None = None, timeout: int = 15,
                 key_file: str | None = None):
        import paramiko
        import socket
        self.host = host
        self.user = user
        self.password = password
        self.sudo_password = sudo_password or password
        self._key_auth = bool(key_file)

        # Resolve all IPs for the hostname; try each in order so a stale DNS
        # entry doesn't cause a 15-second hang before the good IP is tried.
        try:
            addrs = [ai[4][0] for ai in socket.getaddrinfo(
                host, 22, socket.AF_INET, socket.SOCK_STREAM)]
            # Deduplicate while preserving order
            seen: set[str] = set()
            addrs = [a for a in addrs if not (a in seen or seen.add(a))]  # type: ignore[func-returns-value]
        except Exception:
            addrs = [host]

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        last_exc: Exception | None = None
        for addr in addrs:
            try:
                if key_file:
                    expanded = str(pathlib.Path(key_file).expanduser())
                    self._client.connect(
                        addr, username=user,
                        key_filename=expanded,
                        look_for_keys=False, allow_agent=False,
                        timeout=timeout,
                    )
                else:
                    self._client.connect(
                        addr, username=user, password=password,
                        look_for_keys=False, allow_agent=False,
                        timeout=timeout,
                    )
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                # Reset for next attempt
                self._client = paramiko.SSHClient()
                self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if last_exc is not None:
            raise last_exc

        # Keep-alive so the connection survives slow operations and test pauses.
        transport = self._client.get_transport()
        if transport:
            transport.set_keepalive(30)

    # ------------------------------------------------------------------
    # Core execution
    # ------------------------------------------------------------------

    def run(self, cmd: str, check: bool = True, timeout: int = 60) -> str:
        """Run cmd without privilege escalation. Return stdout."""
        import threading

        result_holder: list = []
        exc_holder: list = []
        done = threading.Event()

        def _worker():
            ch = None
            try:
                _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
                ch = stdout.channel
                # Drain stdout and stderr concurrently to avoid the pipe-deadlock
                # that occurs when sequential reads block each other's pipe buffers.
                out_chunks: list[bytes] = []
                err_chunks: list[bytes] = []
                while True:
                    if ch.recv_ready():
                        data = ch.recv(65536)
                        if data:
                            out_chunks.append(data)
                        continue
                    if ch.recv_stderr_ready():
                        data = ch.recv_stderr(65536)
                        if data:
                            err_chunks.append(data)
                        continue
                    if (ch.exit_status_ready()
                            and not ch.recv_ready()
                            and not ch.recv_stderr_ready()):
                        break
                    time.sleep(0.02)
                rc = ch.recv_exit_status()
                out = b"".join(out_chunks).decode(errors="replace").strip()
                err = b"".join(err_chunks).decode(errors="replace").strip()
                result_holder[:] = [out, err, rc]
            except Exception as exc:
                exc_holder[:] = [exc]
            finally:
                try:
                    if ch is not None:
                        ch.close()
                except Exception:
                    pass
                done.set()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        if not done.wait(timeout=timeout + 5):
            raise TimeoutError(
                f"[{self.host}] command timed out after {timeout + 5}s: {cmd[:80]!r}"
            )

        if exc_holder:
            raise exc_holder[0]

        out, err, rc = result_holder
        if check and rc != 0:
            raise RuntimeError(
                f"[{self.host}] Command failed (rc={rc}):\n"
                f"  cmd: {cmd!r}\n"
                f"  out: {out[:800]}\n"
                f"  err: {err[:800]}"
            )
        return out

    def sudo(self, cmd: str, check: bool = True, timeout: int = 60) -> str:
        """Run cmd with sudo.

        Key-auth sessions use 'sudo -n' (NOPASSWD assumed).
        Password sessions inject password via stdin.
        """
        if self._key_auth:
            full = f"sudo -n sh -c {cmd!r}"
        else:
            full = (
                f"echo {self.sudo_password!r} | "
                f"sudo -S -p '' sh -c {cmd!r}"
            )
        return self.run(full, check=check, timeout=timeout)

    # Convenience: calling the session object invokes sudo
    def __call__(self, cmd: str, check: bool = True, timeout: int = 60) -> str:
        return self.sudo(cmd, check=check, timeout=timeout)

    def script(self, interpreter: str, code: str, timeout: int = 30) -> str:
        """
        Feed `code` to `interpreter` over stdin — avoids all shell quoting.
        E.g. session.script("python3", "import os; print(os.uname())")
        """
        channel = self._client.get_transport().open_session()
        channel.settimeout(timeout)
        channel.exec_command(interpreter)
        channel.sendall(code.encode())
        channel.shutdown_write()
        out = b""
        err = b""
        while True:
            if channel.recv_ready():
                chunk = channel.recv(65536)
                if chunk:
                    out += chunk
                    continue
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                if chunk:
                    err += chunk
                    continue
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.05)
        rc = channel.recv_exit_status()
        channel.close()
        result = out.decode(errors="replace").strip()
        err_str = err.decode(errors="replace").strip()
        if rc != 0:
            raise RuntimeError(
                f"[{self.host}] Script failed (rc={rc}): {result[:400]}"
                + (f"\n  stderr: {err_str[:400]}" if err_str else "")
            )
        return result

    def sudo_script(self, interpreter: str, code: str, timeout: int = 30) -> str:
        """Run `code` via `sudo interpreter`, feeding over stdin."""
        channel = self._client.get_transport().open_session()
        channel.settimeout(timeout)
        if self._key_auth:
            channel.exec_command(f"sudo -n {interpreter}")
        else:
            channel.exec_command(
                f"echo {self.sudo_password!r} | sudo -S -p '' {interpreter}"
            )
        channel.sendall(code.encode())
        channel.shutdown_write()
        out = b""
        while True:
            chunk = channel.recv(65536)
            if not chunk:
                break
            out += chunk
        rc = channel.recv_exit_status()
        channel.close()
        result = out.decode(errors="replace").strip()
        if rc != 0:
            raise RuntimeError(
                f"[{self.host}] Sudo script failed (rc={rc}): {result[:400]}"
            )
        return result

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    def sftp_put(self, local: Union[pathlib.Path, str], remote: str) -> None:
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local), remote)
        finally:
            sftp.close()

    def sftp_get(self, remote: str, local: Union[pathlib.Path, str]) -> None:
        sftp = self._client.open_sftp()
        try:
            sftp.get(remote, str(local))
        finally:
            sftp.close()

    def sftp_read(self, remote: str) -> bytes:
        """Read a remote file entirely into memory."""
        sftp = self._client.open_sftp()
        try:
            with sftp.open(remote, "rb") as f:
                return f.read()
        finally:
            sftp.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SSHSession":
        return self

    def __exit__(self, *_) -> None:
        self.close()
