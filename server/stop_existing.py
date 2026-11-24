"""Stop known collectors that conflict with the requested Linux bind address."""

import ipaddress
import os
import re
import select
import signal
import subprocess
import sys
from pathlib import Path

KNOWN_COLLECTORS = {"attestor-server", "confido-server"}


def endpoint(value):
    host, port = value.rsplit(":", 1)
    host = host.strip("[]")
    address = None if host == "*" else ipaddress.ip_address(host)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    port = int(port)
    if not 0 <= port <= 65535:
        raise ValueError("Invalid port")
    return address, port


def conflicts(wanted, bound):
    a, port = endpoint(wanted)
    b, other_port = endpoint(bound)
    return port == other_port and (
        a is None or b is None or a.is_unspecified or b.is_unspecified or a == b
    )


def listeners(address):
    _, port = endpoint(address)
    if port == 0:  # The kernel selects a free ephemeral port.
        return set()
    output = subprocess.check_output(
        ["ss", "-H", "-ltnp", f"sport = :{port}"], text=True
    )
    result = set()
    for row in output.splitlines():
        fields = row.split()
        if len(fields) < 5 or not conflicts(address, fields[3]):
            continue
        owners = re.findall(r"pid=(\d+)", row)
        if not owners:
            raise RuntimeError(f"Cannot identify listener on {fields[3]}; run as root")
        result.update(map(int, owners))
    return result


def executable(pid):
    return os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")


def service(pid):
    cgroup = Path(f"/proc/{pid}/cgroup").read_text()
    match = re.search(r"/system\.slice/([^/\n]+\.service)(?:/|$)", cgroup, re.MULTILINE)
    if not match:
        return None
    unit = match[1]
    main_pid = subprocess.check_output(
        ["systemctl", "show", "--property=MainPID", "--value", unit], text=True
    ).strip()
    # Do not stop a shared supervisor such as sshd or a login session.
    return unit if main_pid == str(pid) else None


def stop(address):
    processes = []
    try:
        for pid in sorted(listeners(address)):
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            processes.append((pid, fd))
            if select.select([fd], [], [], 0)[0]:
                continue
            if Path(executable(pid)).name not in KNOWN_COLLECTORS:
                raise RuntimeError(
                    f"Port is occupied by an unrelated process {pid}; refusing to stop it"
                )
        for pid, fd in processes:
            if select.select([fd], [], [], 0)[0]:
                continue
            # Recheck ownership before asking systemd to stop a service.
            if Path(executable(pid)).name not in KNOWN_COLLECTORS:
                raise RuntimeError(
                    f"Process {pid} changed executable; refusing to stop it"
                )
            unit = service(pid)
            if unit:
                print(
                    f"Stopping {unit} (collector {pid}) on {address}", flush=True
                )
                subprocess.run(["systemctl", "stop", unit], check=True, timeout=20)
            else:
                print(f"Stopping collector {pid} on {address}", flush=True)
                signal.pidfd_send_signal(fd, signal.SIGTERM)
            if not select.select([fd], [], [], 5)[0]:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
                if not select.select([fd], [], [], 2)[0]:
                    raise RuntimeError(f"Process {pid} did not exit")
        if listeners(address):
            raise RuntimeError(
                f"A listener remains or restarted on {address}; refusing to start another server"
            )
    finally:
        for _, fd in processes:
            os.close(fd)


if __name__ == "__main__":
    try:
        stop(sys.argv[1])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Cannot free server address: {error}", file=sys.stderr)
        sys.exit(1)
