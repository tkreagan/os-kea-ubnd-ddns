# SPDX-License-Identifier: BSD-2-Clause
"""
Paramiko-based SSH session with password auth.

Adapted from tests/integration/conftest.py:SSHSession — same behaviour but
no pytest dependency, so it can be used in standalone scripts.
"""
from __future__ import annotations

import pathlib
import time
from typing import Union


class SSHSession:
    """
    Password-based SSH session via paramiko.

    Usage:
        s = SSHSession("host", "user", "pass")
        out = s.run("ls /tmp")           # no privilege escalation
        out = s.sudo("cat /etc/shadow")  # wraps with sudo via stdin password
        out = s.script("python3", "import sys; print(sys.version)")
        s.sftp_put("/tmp/local.txt", "/tmp/remote.txt")
        s.close()
    """

    def __init__(self, host: str, user: str, password: str,
                 sudo_password: str | None = None, timeout: int = 15):
        import paramiko
        self.host = host
        self.user = user
        self.password = password
        self.sudo_password = sudo_password or password

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            host, username=user, password=password,
            look_for_keys=False, allow_agent=False,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Core execution
    # ------------------------------------------------------------------

    def run(self, cmd: str, check: bool = True, timeout: int = 60) -> str:
        """Run cmd without privilege escalation. Return stdout."""
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        rc = stdout.channel.recv_exit_status()
        if check and rc != 0:
            raise RuntimeError(
                f"[{self.host}] Command failed (rc={rc}):\n"
                f"  cmd: {cmd!r}\n"
                f"  out: {out[:800]}\n"
                f"  err: {err[:800]}"
            )
        return out

    def sudo(self, cmd: str, check: bool = True, timeout: int = 60) -> str:
        """Run cmd with sudo, supplying password via stdin."""
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
