#!/usr/bin/env python3
"""Headless BSD development guests. Host dependencies: Python 3, QEMU, SSH, rsync."""

import argparse
import contextlib
import fcntl
import functools
import gzip
import hashlib
import http.server
import ipaddress
import json
import lzma
import os
import re
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SYSTEMS = ("freebsd", "netbsd", "openbsd")
STATE = (
    Path(
        os.environ.get(
            "TRIPPY_VM_HOME", Path.home() / "Library/Application Support/trippy-bsd"
        )
    )
    .expanduser()
    .resolve()
)


def run(args, **kw):
    return subprocess.run([str(a) for a in args], check=True, **kw)


def output(args):
    return run(args, stdout=subprocess.PIPE, text=True).stdout.strip()


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode()


def latest(html, pattern):
    versions = re.findall(pattern, html)
    if not versions:
        raise RuntimeError("No stable release found in official directory")
    return max(set(versions), key=lambda v: tuple(map(int, v.split("."))))


def release(osname):
    if osname == "freebsd":
        version = latest(
            fetch("https://download.freebsd.org/releases/VM-IMAGES/"),
            r'href="(\d+\.\d+)-RELEASE/',
        )
        base = f"https://download.freebsd.org/releases/VM-IMAGES/{version}-RELEASE/amd64/Latest/"
        name = f"FreeBSD-{version}-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
        manifest, algorithm = "CHECKSUM.SHA256", "sha256"
    elif osname == "netbsd":
        version = latest(
            fetch("https://cdn.netbsd.org/pub/NetBSD/"), r'href="NetBSD-(\d+\.\d+)/'
        )
        base = f"https://cdn.netbsd.org/pub/NetBSD/images/{version}/"
        name = f"NetBSD-{version}-amd64-live.img.gz"
        manifest, algorithm = "SHA512", "sha512"
    else:
        version = latest(
            fetch("https://cdn.openbsd.org/pub/OpenBSD/"), r'href="(\d+\.\d+)/'
        )
        base = f"https://cdn.openbsd.org/pub/OpenBSD/{version}/amd64/"
        name = f"install{version.replace('.', '')}.iso"
        manifest, algorithm = "SHA256", "sha256"
    digest = checksum(fetch(base + manifest), name, algorithm)
    return {
        "os": osname,
        "version": version,
        "url": base + name,
        "digest": digest,
        "algorithm": algorithm,
        "provisioning": 1,
    }


def checksum(manifest, name, algorithm):
    match = re.search(
        r"^" + algorithm.upper() + r" \(" + re.escape(name) + r"\) = ([0-9a-f]+)$",
        manifest,
        re.MULTILINE,
    )
    if not match or len(match[1]) != hashlib.new(algorithm).digest_size * 2:
        raise RuntimeError(f"Missing or invalid checksum for {name}")
    return match[1]


def verified(path, meta):
    h = hashlib.new(meta["algorithm"])
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest() == meta["digest"]


def acquire(meta):
    cache = STATE / "downloads"
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / Path(urllib.parse.urlparse(meta["url"]).path).name
    if dest.exists() and verified(dest, meta):
        return dest
    partial = dest.with_suffix(dest.suffix + ".part")
    print(f"Downloading {meta['url']}", flush=True)
    # curl resumes interrupted downloads. A checksum failure discards the partial.
    run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--retry",
            "3",
            "--continue-at",
            "-",
            "--output",
            partial,
            meta["url"],
        ]
    )
    if not verified(partial, meta):
        partial.unlink()
        raise RuntimeError("Image checksum mismatch; discarded download")
    partial.replace(dest)
    return dest


def executable(name, env=None):
    candidate = os.environ.get(env or "") or shutil.which(name)
    if not candidate:
        candidate = f"/usr/local/opt/qemu/bin/{name}"
    if not Path(candidate).is_file():
        raise RuntimeError(f"{name} not found; install QEMU or set {env}")
    return str(Path(candidate).resolve())


def write_json(path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(path)


class QMP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.stream = self.sock.makefile("rwb", buffering=0)
        self.stream.readline()
        self.call("qmp_capabilities")

    def call(self, command, arguments=None):
        self.stream.write(
            (
                json.dumps({"execute": command, "arguments": arguments or {}}) + "\n"
            ).encode()
        )
        while True:
            value = json.loads(self.stream.readline())
            if "error" in value:
                raise RuntimeError(str(value["error"]))
            if "return" in value:
                return value["return"]

    def close(self):
        self.stream.close()
        self.sock.close()

    def type(self, text):
        names = {" ": "spc", "\n": "ret", ".": "dot", "-": "minus", "/": "slash"}
        for char in text:
            key = names.get(char, char)
            self.call("human-monitor-command", {"command-line": f"sendkey {key} 30"})
            time.sleep(0.06)


class Serial:
    def __init__(self, path, logfile):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(str(path))
        # QEMU writes console.log; keep protocol captures separate to avoid
        # interleaving two writers into the same file.
        self.log = logfile.with_suffix(".transcript.log").open("ab")
        self.buffer = ""

    def send(self, text):
        self.sock.sendall(text.encode())

    def expect(self, pattern, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            match = re.search(pattern, self.buffer, re.IGNORECASE)
            if match:
                self.buffer = self.buffer[match.end() :]
                return match[0]
            if select.select([self.sock], [], [], 1)[0]:
                data = self.sock.recv(65536)
                if not data:
                    raise RuntimeError("Serial console closed")
                self.log.write(data)
                self.log.flush()
                self.buffer = (self.buffer + data.decode(errors="replace"))[-100000:]
        raise RuntimeError(
            f"Console timeout waiting for {pattern!r}; inspect console.log"
        )

    def close(self):
        self.log.close()
        self.sock.close()


class Guest:
    def __init__(self, name):
        self.name = name
        self.dir = STATE / name
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.port = 2222 + SYSTEMS.index(name)
        # macOS limits Unix socket paths to 104 bytes; hash the state directory.
        tag = hashlib.sha256(str(self.dir).encode()).hexdigest()[:12]
        self.runtime = Path(tempfile.gettempdir()) / f"trippy-bsd-{os.getuid()}-{tag}"
        self.runtime.mkdir(mode=0o700, exist_ok=True)
        if self.runtime.stat().st_uid != os.getuid():
            raise RuntimeError("Runtime directory belongs to another user")
        self.meta = (
            json.loads((self.dir / "image.json").read_text())
            if (self.dir / "image.json").exists()
            else None
        )

    @contextlib.contextmanager
    def lock(self):
        with (self.dir / "lock").open("w") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError(
                    f"{self.name}: another operation is running"
                ) from None
            yield

    def alive(self):
        try:
            q = QMP(self.runtime / "qmp")
            q.call("query-status")
            q.close()
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    def ssh(self, command=None, capture=False, tty=False, check=True):
        args = [
            "ssh",
            "-i",
            str(self.dir / "key"),
            "-p",
            str(self.port),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=30",
            "-o",
            f"UserKnownHostsFile={self.dir / 'known_hosts'}",
            "-o",
            "StrictHostKeyChecking=accept-new",
        ]
        if tty:
            args.append("-t")
        args.append("trippy@127.0.0.1")
        if command:
            args.append(command)
        return subprocess.run(
            args,
            check=check,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True,
        )

    def admin(self, command, **kw):
        return self.ssh(
            ("doas" if self.name == "openbsd" else "sudo")
            + " sh -c "
            + shlex.quote(command),
            **kw,
        )

    def prepare(self):
        if not self.meta:
            self.meta = release(self.name)
            write_json(self.dir / "image.json", self.meta)
        image = acquire(self.meta)
        if not (self.dir / "key").exists():
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.dir / "key"])
        if not (self.dir / "disk.qcow2").exists():
            qimg = executable("qemu-img", "QEMU_IMG")
            tmp = self.dir / "disk.partial.qcow2"
            if self.name == "openbsd":
                run([qimg, "create", "-f", "qcow2", tmp, "64G"])
            else:
                raw = self.dir / "unpacked"
                opener = lzma.open if self.name == "freebsd" else gzip.open
                with opener(image, "rb") as src, raw.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 8 * 1024 * 1024)
                run(
                    [
                        qimg,
                        "convert",
                        "-f",
                        "qcow2" if self.name == "freebsd" else "raw",
                        "-O",
                        "qcow2",
                        raw,
                        tmp,
                    ]
                )
                run([qimg, "resize", tmp, "64G"])
                raw.unlink()
            tmp.replace(self.dir / "disk.qcow2")
        return image

    def seed(self):
        seed = self.dir / "seed"
        seed.mkdir(exist_ok=True)
        key = (self.dir / "key.pub").read_text().strip()
        script = (HERE / "provision.sh").read_text()
        # Bootstrap creates SSH access before package installation, enabling retries.
        bootstrap = f"""#!/bin/sh
set -eu
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
mkdir -p /root/.ssh
printf '%s\\n' {shlex.quote(key)} > /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
printf '\\nPermitRootLogin prohibit-password\\nPasswordAuthentication no\\n' >> /etc/ssh/sshd_config
"""
        if self.name == "netbsd":
            bootstrap += """echo 'consdev com0' > /boot.cfg
printf 'timeout=1\\nmenu=Boot normally:boot\\n' >> /boot.cfg
/etc/rc.d/sshd restart
"""
        bootstrap += script.replace("key=$1", "key=" + shlex.quote(key), 1)
        (seed / "bootstrap.sh").write_text(bootstrap)
        (seed / "meta-data").write_text(
            f"instance-id: trippy-{self.name}\nlocal-hostname: trippy-{self.name}\n"
        )
        (seed / "user-data").write_text(bootstrap)
        iso = self.dir / "seed.iso"
        iso.unlink(missing_ok=True)
        run(
            [
                "hdiutil",
                "makehybrid",
                "-iso",
                "-joliet",
                "-default-volume-name",
                "cidata",
                "-o",
                iso,
                seed,
            ],
            stdout=subprocess.DEVNULL,
        )
        return iso

    def launch(self, args, install=False, image=None, seed=None):
        if self.alive():
            raise RuntimeError("Guest already running")
        for name in ("qmp", "serial", "pid"):
            (self.runtime / name).unlink(missing_ok=True)
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", self.port))
        qemu = executable("qemu-system-x86_64", "QEMU_BIN")
        print(output([qemu, "--version"]).splitlines()[0], flush=True)
        backend = output([qemu, "-netdev", "help"])
        if not args.management_only and not install and "vmnet-bridged" not in backend:
            raise RuntimeError("QEMU lacks vmnet-bridged")
        # No guest needs SMBus; avoid OpenBSD stalling while probing ICH9 I2C.
        command = [
            qemu,
            "-machine",
            "q35,smbus=off",
            "-accel",
            args.accel,
            "-cpu",
            args.cpu or ("host" if args.accel == "hvf" else "max"),
            "-smp",
            str(args.cpus),
            "-m",
            str(args.memory),
            "-display",
            "none",
            "-qmp",
            f"unix:{self.runtime}/qmp,server=on,wait=off",
            "-chardev",
            f"socket,id=console,path={self.runtime}/serial,server=on,wait=off,logfile={str(self.dir / 'console.log').replace(',', ',,')},logappend=on",
            "-serial",
            "chardev:console",
            "-pidfile",
            str(self.runtime / "pid"),
            "-drive",
            f"file={str(self.dir / 'disk.qcow2').replace(',', ',,')},format=qcow2,if=virtio",
            "-netdev",
            f"user,id=mgmt,ipv6=off,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device",
            f"virtio-net-pci,netdev=mgmt,mac=52:54:00:74:{SYSTEMS.index(self.name):02x}:01",
        ]
        bridge = None
        if not install and not args.management_only:
            bridge = args.bridge or self.bridge()
            if not re.fullmatch(r"en\d+", bridge):
                raise RuntimeError("Bridge must be a physical enN interface")
            command += [
                "-netdev",
                f"vmnet-bridged,id=probe,ifname={bridge}",
                "-device",
                f"virtio-net-pci,netdev=probe,mac=52:54:00:74:{SYSTEMS.index(self.name):02x}:02",
            ]
            command += ["-run-with", f"user={os.getuid()}:{os.getgid()}"]
        if seed:
            command += [
                "-drive",
                f"file={str(seed).replace(',', ',,')},format=raw,media=cdrom,readonly=on",
            ]
        if install and self.name == "openbsd":
            command += ["-cdrom", str(image), "-boot", "once=d"]
        log = (self.dir / "qemu.log").open("ab")
        # Detach before exec so no hypervisor state crosses a daemonization fork.
        if bridge:
            # Authenticate on the caller's terminal before backgrounding. nohup
            # keeps QEMU alive when that terminal closes; no shell runs as root.
            run(
                ["sudo", "-b", "--", "/usr/bin/nohup"] + command, stdout=log, stderr=log
            )
            child = None
        else:
            child = subprocess.Popen(
                command,
                stdout=log,
                stderr=log,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        write_json(
            self.dir / "runtime.json",
            {
                "management_only": args.management_only or install,
                "bridge": bridge,
                "accel": args.accel,
                "cpu": args.cpu,
                "cpus": args.cpus,
                "memory": args.memory,
            },
        )
        deadline = time.monotonic() + 30
        while not all(
            (self.runtime / name).exists() for name in ("qmp", "serial", "pid")
        ):
            if child is not None and child.poll() is not None:
                raise RuntimeError(
                    f"QEMU exited: {(self.dir / 'qemu.log').read_text()[-3000:]}"
                )
            if time.monotonic() > deadline:
                raise RuntimeError("QEMU launch timed out; inspect qemu.log")
            time.sleep(0.2)
        if bridge:
            run(
                [
                    "sudo",
                    "--",
                    "chown",
                    f"{os.getuid()}:{os.getgid()}",
                    self.runtime / "qmp",
                    self.runtime / "serial",
                    self.runtime / "pid",
                ]
            )
        log.close()

    @staticmethod
    def bridge():
        text = output(["/sbin/route", "-n", "get", "default"])
        match = re.search(r"interface: (\S+)", text)
        if not match or not re.fullmatch(r"en\d+", match[1]):
            raise RuntimeError(
                "Cannot identify physical default interface; supply --bridge en0 (VPN routes may obscure it)"
            )
        return match[1]

    def install(self, args, image, seed):
        self.launch(args, install=True, image=image, seed=seed)
        if self.name == "freebsd":
            (self.dir / "os-installed").touch()
        serial = Serial(self.runtime / "serial", self.dir / "console.log")
        qmp = QMP(self.runtime / "qmp")
        try:
            if self.name in ("netbsd", "openbsd"):
                # Interrupt the VGA bootloader, then switch to serial. Repeated
                # interruption keys cover firmware startup; all later IO matches prompts.
                for _ in range(30):
                    qmp.call(
                        "human-monitor-command", {"command-line": "sendkey spc 20"}
                    )
                    time.sleep(0.1)
                qmp.type(
                    "\n3\nconsdev com0\n" if self.name == "netbsd" else "set tty com0\n"
                )
                qmp.close()
                serial.expect(r"(>|boot>)", 30)
                serial.send("boot\n")
            else:
                qmp.close()
            if self.name == "netbsd":
                serial.expect(r"login:", 300)
                serial.send("root\n")
                serial.expect(r"(?m)^[^\r\n]*# ")
                (self.dir / "os-installed").touch()
                serial.send("mount -t cd9660 /dev/cd0a /mnt && sh /mnt/bootstrap.sh\n")
            elif self.name == "openbsd":
                serial.expect(r"\(I\)nstall.*\(A\)utoinstall", 300)
                serial.send("a\n")
                # HTTP serves only non-secret installer answers, bound to loopback.
                with self.install_server() as url:
                    serial.expect(r"(response file|URL).*[:?]", 120)
                    serial.send(url + "\n")
                    serial.expect(r"(CONGRATULATIONS|installation.*success)", 1800)
                    (self.dir / "os-installed").touch()
                # Installed system has key-only root access; provision packages via SSH.
                self.wait_root(300)
                with (self.dir / "seed/bootstrap.sh").open("rb") as script:
                    subprocess.run(self.root_ssh() + ["sh"], stdin=script, check=True)
            if self.name != "openbsd":
                result = serial.expect(r"TRIPPY_PROVISION_(COMPLETE|FAILED)", 3600)
                if result.endswith("FAILED"):
                    raise RuntimeError(
                        "Guest provisioning failed; inspect console.log, then rerun up to retry"
                    )
        finally:
            qmp.close()
            serial.close()
        self.wait(300)
        (self.dir / "installed").touch()
        self.stop()

    def root_ssh(self):
        return [
            "ssh",
            "-i",
            str(self.dir / "key"),
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=30",
            "-o",
            f"UserKnownHostsFile={self.dir / 'known_hosts'}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "root@127.0.0.1",
        ]

    def wait_root(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise RuntimeError("Guest exited before root SSH readiness")
            if (
                subprocess.run(
                    self.root_ssh() + ["true"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode
                == 0
            ):
                return
            time.sleep(2)
        raise RuntimeError("Root SSH did not become ready")

    @contextlib.contextmanager
    def install_server(self):
        key = (self.dir / "key.pub").read_text().strip()
        version = self.meta["version"]
        answers = f"""System hostname = trippy-openbsd
Password for root = *************
Public ssh key for root account = {key}
Start sshd(8) by default = yes
Allow root ssh login = prohibit-password
Which network interface = vio0
IPv4 address for vio0 = dhcp
IPv6 address for vio0 = none
Which network interface = done
DNS domain name = local
Setup a user = no
What timezone = UTC
Which disk is the root disk = sd0
Use (W)hole disk MBR, whole disk (G)PT or (E)dit = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a
Location of sets = http
HTTP Server = cdn.openbsd.org
Server directory = pub/OpenBSD/{version}/amd64
Set name(s) = -game* -x* +xbase*
Location of sets = done
Change the default console to com0 = yes
Which speed should com0 use = 115200
"""
        web = self.dir / "http"
        web.mkdir(exist_ok=True)
        (web / "install.conf").write_text(answers)
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(web)
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://10.0.2.2:{server.server_port}/install.conf"
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def wait(self, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise RuntimeError(
                    "Guest exited before SSH readiness; inspect qemu.log"
                )
            result = self.ssh(
                "test -f /var/db/trippy-provisioned", capture=True, check=False
            )
            if result.returncode == 0:
                return
            time.sleep(2)
        raise RuntimeError(
            "Guest readiness timed out; inspect console.log and qemu.log"
        )

    def stop(self, force=False):
        if not self.alive():
            return
        try:
            self.admin("shutdown -p now", capture=True, check=False)
        except OSError:
            pass
        deadline = time.monotonic() + 60
        while self.alive() and time.monotonic() < deadline:
            time.sleep(1)
        if self.alive():
            if not force:
                raise RuntimeError(
                    "Graceful shutdown timed out; use stop --force to power off"
                )
            q = QMP(self.runtime / "qmp")
            q.call("quit")
            q.close()

    def sync(self):
        self.ssh("mkdir -p ~/src/trippy")
        # Git defines ignored/untracked behavior; skip tracked files deleted locally.
        files = subprocess.check_output(
            [
                "git",
                "-C",
                str(REPO),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ]
        )
        names = sorted(
            {
                p
                for p in files.split(b"\0")
                if p
                and (
                    (REPO / os.fsdecode(p)).exists()
                    or (REPO / os.fsdecode(p)).is_symlink()
                )
            }
        )
        # Stage the selected tree so rsync --delete can remove files no longer present.
        with tempfile.TemporaryDirectory(prefix="trippy-sync-") as temp:
            staging = Path(temp)
            for raw in names:
                relative = Path(os.fsdecode(raw))
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError("Unsafe source path")
                src, dst = REPO / relative, staging / relative
                dst.parent.mkdir(parents=True, exist_ok=True)
                if src.is_symlink():
                    dst.symlink_to(os.readlink(src))
                elif src.is_file():
                    try:
                        os.link(src, dst)
                    except OSError:
                        shutil.copy2(src, dst)
            transport = shlex.join(
                [
                    "ssh",
                    "-i",
                    str(self.dir / "key"),
                    "-p",
                    str(self.port),
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    f"UserKnownHostsFile={self.dir / 'known_hosts'}",
                    "-o",
                    "StrictHostKeyChecking=yes",
                ]
            )
            run(
                [
                    "rsync",
                    "-rlpt",
                    "--checksum",
                    "--delete",
                    "-e",
                    transport,
                    str(staging) + "/",
                    "trippy@127.0.0.1:src/trippy/",
                ]
            )
        required = re.search(
            r'rust-version\s*=\s*"([^"]+)"', (REPO / "Cargo.toml").read_text()
        )[1]
        actual = self.ssh(". ~/.profile; rustc --version", capture=True).stdout
        match = re.search(r"rustc (\d+)\.(\d+)\.(\d+)", actual)
        if not match or tuple(map(int, match.groups())) < tuple(
            map(int, (required + ".0").split(".")[:3])
        ):
            raise RuntimeError(
                f"Guest compiler {actual.strip()} is below required Rust {required}"
            )
        print(f"{self.name}: source synced; {actual.strip()}", flush=True)

    def configure_network(self, management_only):
        if management_only:
            if self.name == "freebsd":
                config = 'sysrc defaultrouter=10.0.2.2 ifconfig_vtnet0="inet 10.0.2.15 netmask 255.255.255.0"\n'
            elif self.name == "netbsd":
                config = "printf 'interface vioif0\\nstatic ip_address=10.0.2.15/24\\nstatic routers=10.0.2.2\\nstatic domain_name_servers=10.0.2.3\\nnoipv6\\n' > /etc/dhcpcd.conf\n"
            else:
                config = "echo 'inet 10.0.2.15 255.255.255.0' > /etc/hostname.vio0\necho 10.0.2.2 > /etc/mygate\n"
                config += "route delete -inet default -priority 2 || true\n"
            self.admin(
                config
                + "printf 'nameserver 10.0.2.3\\n' > /etc/resolv.conf\n"
                + "route delete -inet default || true\nroute add -inet default 10.0.2.2 || true"
            )
            print(
                "Management-only diagnostic mode: probe networking is NOT validated.",
                flush=True,
            )
            return
        if self.name == "freebsd":
            command = """service dhclient stop vtnet0 || true
sysrc ifconfig_vtnet0="inet 10.0.2.15 netmask 255.255.255.0" ifconfig_vtnet1=SYNCDHCP ifconfig_vtnet1_ipv6="inet6 accept_rtadv" rtsold_enable=YES defaultrouter=NO
ifconfig vtnet0 inet 10.0.2.15 netmask 255.255.255.0
route delete default || true
ifconfig vtnet1 up
service dhclient restart vtnet1
service rtsold restart
"""
        elif self.name == "netbsd":
            command = """printf 'interface vioif0\nstatic ip_address=10.0.2.15/24\nnogateway\nnoipv6\ninterface vioif1\n' > /etc/dhcpcd.conf
route delete default || true
/etc/rc.d/dhcpcd restart </dev/null >/var/log/trippy-network.log 2>&1
"""
        else:
            command = """echo 'inet 10.0.2.15 255.255.255.0' > /etc/hostname.vio0
rm -f /etc/mygate
printf 'inet autoconf\ninet6 autoconf\n' > /etc/hostname.vio1
sh /etc/netstart vio0
route delete -inet default -priority 2 || true
route delete default || true
sh /etc/netstart vio1
dhcpleasectl -w 30 vio1
"""
        self.admin(command)
        nic = {"freebsd": "vtnet1", "netbsd": "vioif1", "openbsd": "vio1"}[self.name]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            route = self.admin("route -n get 1.1.1.1", capture=True, check=False)
            if not route.returncode and re.search(
                r"interface:\s*" + nic + r"\b", route.stdout
            ):
                return
            time.sleep(1)
        raise RuntimeError(
            "Bridged IPv4 route is not ready; inspect doctor/console. Management SSH remains available."
        )

    def netbsd_underlay(self):
        """Keep IPv4 available to the NetBSD Tailscale transport itself.

        Its package installs an IPv4 TUN default without a transport bypass.
        Preserve native IPv4 and use the exit node for public IPv6.
        """
        if self.name != "netbsd":
            return
        result = self.admin("route -n get 1.1.1.1", capture=True, check=False)
        gateway = re.search(r"gateway:\s*([0-9.]+)", result.stdout)
        saved = self.dir / "native-ipv4-gateway"
        if gateway and not re.search(r"interface:\s*tun", result.stdout):
            ipaddress.IPv4Address(gateway[1])
            saved.write_text(gateway[1])
            return
        runtime = json.loads((self.dir / "runtime.json").read_text())
        value = (
            "10.0.2.2"
            if runtime["management_only"]
            else saved.read_text().strip()
            if saved.exists()
            else None
        )
        if value is None:
            raise RuntimeError(
                "No native IPv4 gateway recorded; restart NetBSD before selecting an exit node"
            )
        ipaddress.IPv4Address(value)
        self.admin(
            "route delete -inet default || true\nroute add -inet default " + value
        )
        saved.write_text(value)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "command",
        choices=(
            "up",
            "shell",
            "sync",
            "status",
            "doctor",
            "console",
            "stop",
            "tailscale",
            "recreate",
        ),
    )
    p.add_argument("guest", nargs="?", choices=SYSTEMS)
    p.add_argument("action", nargs="?", choices=("login", "exit-node", "direct"))
    p.add_argument("node", nargs="?")
    p.add_argument("--bridge", help="Physical vmnet bridge interface, e.g. en0")
    p.add_argument(
        "--management-only",
        action="store_true",
        help="Explicit diagnostic mode without raw probe networking",
    )
    p.add_argument("--accel", choices=("hvf", "tcg"), default="hvf")
    p.add_argument(
        "--cpu", help="Override the QEMU CPU model for compatibility diagnostics"
    )
    p.add_argument("--memory", type=int, default=4096, help="Guest memory in MiB")
    p.add_argument("--cpus", type=int, default=2)
    p.add_argument("--force", action="store_true", help="Allow forced power off")
    p.add_argument("--latest", action="store_true", help="Required for recreate")
    return p


def main():
    args = parser().parse_args()
    os.umask(0o077)
    if args.command == "status":
        for name in SYSTEMS:
            if (STATE / name).exists():
                guest = Guest(name)
                runtime = (
                    json.loads((guest.dir / "runtime.json").read_text())
                    if (guest.dir / "runtime.json").exists()
                    else {}
                )
                print(
                    name,
                    "running" if guest.alive() else "stopped",
                    guest.meta and guest.meta["version"],
                    runtime,
                )
        return
    if not args.guest:
        raise RuntimeError("A guest name is required")
    guest = Guest(args.guest)
    if args.command == "console":
        serial = Serial(guest.runtime / "serial", guest.dir / "console.log")
        print(
            "Connected to serial console. Ctrl-] disconnects. For an interactive shell use vm shell."
        )
        import termios
        import tty

        old = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                ready, _, _ = select.select([sys.stdin, serial.sock], [], [])
                if sys.stdin in ready:
                    data = os.read(sys.stdin.fileno(), 1024)
                    if b"\x1d" in data or not data:
                        break
                    serial.sock.sendall(data)
                if serial.sock in ready:
                    data = serial.sock.recv(65536)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
            serial.close()
        return
    # A long-lived shell or browser login must not prevent source sync.
    guard = (
        guest.lock()
        if args.command in {"up", "sync", "stop", "recreate"}
        else contextlib.nullcontext()
    )
    with guard:
        if args.command == "up":
            if guest.alive() and (guest.dir / "installed").exists():
                runtime = json.loads((guest.dir / "runtime.json").read_text())
                if runtime["management_only"] != args.management_only or (
                    args.bridge and runtime["bridge"] != args.bridge
                ):
                    raise RuntimeError(
                        "Running guest has a different network mode; stop it before changing modes"
                    )
                for setting in ("accel", "cpu", "cpus", "memory"):
                    if setting in runtime and runtime[setting] != getattr(
                        args, setting
                    ):
                        raise RuntimeError(
                            f"Running guest has different {setting}; stop it before changing hardware"
                        )
            if (
                not (guest.dir / "installed").exists()
                and (guest.dir / "os-installed").exists()
            ):
                if not guest.alive():
                    diagnostic = argparse.Namespace(**vars(args))
                    diagnostic.management_only = True
                    guest.launch(diagnostic)
                guest.wait_root(300)
                guest.seed()
                with (guest.dir / "seed/bootstrap.sh").open("rb") as script:
                    subprocess.run(guest.root_ssh() + ["sh"], stdin=script, check=True)
                guest.wait()
                (guest.dir / "installed").touch()
                guest.stop()
            elif guest.alive() and not (guest.dir / "installed").exists():
                raise RuntimeError(
                    "Installation is incomplete; inspect console, or stop --force and rerun up"
                )
            if not guest.alive():
                image = guest.prepare()
                if not (guest.dir / "installed").exists():
                    seed = guest.seed()
                    guest.install(args, image, seed)
                guest.launch(args)
                guest.wait()
                guest.configure_network(args.management_only)
            guest.netbsd_underlay()
            guest.sync()
            print(f"Ready: {HERE / 'vm'} shell {args.guest}")
        elif args.command == "recreate":
            if not args.latest:
                raise RuntimeError(
                    "Use recreate --latest to explicitly replace the guest"
                )
            if guest.alive():
                raise RuntimeError("Stop the guest before recreating it")
            if (
                input(
                    f"Delete {args.guest} disk, caches and Tailscale identity? Type its name: "
                )
                != args.guest
            ):
                raise RuntimeError("Cancelled")
            # Rename first so the active lock remains attached to the old directory.
            archive = guest.dir.with_name(
                guest.name + "-retired-" + str(time.time_ns())
            )
            guest.dir.rename(archive)
            shutil.rmtree(archive)
            print("Guest removed. Run up to acquire the latest release.")
        elif args.command == "stop":
            guest.stop(args.force)
        elif args.command == "sync":
            guest.sync()
        elif args.command == "shell":
            guest.ssh('cd ~/src/trippy && exec "$SHELL" -l', tty=True)
        elif args.command == "doctor":
            guest.ssh(
                ". ~/.profile; uname -a; rustc --version; df -h; ifconfig; netstat -rn; cat /etc/resolv.conf"
            )
            guest.admin("tailscale status; tailscale netcheck")
            guest.ssh(
                "ping -c 2 1.1.1.1; curl --connect-timeout 10 -4 https://icanhazip.com; curl --connect-timeout 10 -6 https://icanhazip.com",
                check=False,
            )
        elif args.command == "tailscale":
            if args.action == "login":
                guest.admin("tailscale up --accept-dns=false", tty=True)
            elif args.action == "exit-node" and args.node:
                guest.netbsd_underlay()
                guest.admin(
                    "tailscale set --exit-node="
                    + shlex.quote(args.node)
                    + " --exit-node-allow-lan-access=true"
                )
                guest.netbsd_underlay()
            elif args.action == "direct":
                guest.admin("tailscale set --exit-node=''")
                guest.netbsd_underlay()
            else:
                raise RuntimeError(
                    "Use tailscale GUEST login | exit-node NODE | direct"
                )


if __name__ == "__main__":
    try:
        main()
    except (
        RuntimeError,
        OSError,
        subprocess.CalledProcessError,
        KeyboardInterrupt,
    ) as error:
        print(f"vm: {error}", file=sys.stderr)
        sys.exit(1)
