"""Run isolated hardware-backed acceptance without replacing public listeners.

Requires compatible verifier and transport wheels, a running Attestor on loopback,
its certificate directory, Nginx and sudo. The downstream responder is synthetic:
no inference runs. This script does not start or stop Attestor.
"""

import argparse
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import patch

# This optional cross-repository test uses the sibling client checkout.
ROOT = Path(__file__).resolve().parents[2] / "confidential-ai-example"
PORTS = (18443, 18444, 14000)
CASES = (("match", 18443), ("mismatch", 18444))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestor-url", default="http://127.0.0.1:18001")
    parser.add_argument("--certificate-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--container", help="Also exercise this frozen client image")
    parser.add_argument(
        "--match-verifier-policy",
        type=Path,
        default=ROOT / "profiles/verifier-match.json",
    )
    parser.add_argument(
        "--mismatch-verifier-policy",
        type=Path,
        default=ROOT / "profiles/verifier-mismatch.json",
    )
    return parser.parse_args()


def read_verifier_policies(args):
    paths = {
        "match": args.match_verifier_policy,
        "mismatch": args.mismatch_verifier_policy,
    }
    policy_bytes = {name: path.read_bytes() for name, path in paths.items()}
    policies = {name: json.loads(data) for name, data in policy_bytes.items()}
    for name, policy in policies.items():
        if (
            policy.get("schema_version") != 2
            or policy.get("profile") != "azure-snp-vtpm-ima/1"
        ):
            raise ValueError(f"Invalid {name} verifier policy")
    if policies["match"]["platform"] != policies["mismatch"]["platform"]:
        raise ValueError("Stage policies must use the same platform enrollment")
    if policies["match"]["reference"] == policies["mismatch"]["reference"]:
        raise ValueError("Stage policies must use different references")
    return policy_bytes


def prepare_stage(output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    stage = output.resolve()
    for port in PORTS:
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                raise RuntimeError(f"Port {port} already in use")
    policies = stage / "profiles"
    policies.mkdir()
    return stage, policies


def check_attestor(url, certificates):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Attestor URL must be an HTTP loopback origin with an explicit port")
    for filename in ("certificate.pem", "private_key.pem"):
        if not (certificates / filename).is_file():
            raise ValueError(f"Attestor certificate directory lacks {filename}")
    connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=5)
    try:
        connection.request("HEAD", "/tee-report")
        response = connection.getresponse()
        response.read()
        if response.status != 204:
            raise RuntimeError(f"Attestor HEAD /tee-report returned HTTP {response.status}")
    finally:
        connection.close()
    return f"http://127.0.0.1:{parsed.port}"


def wait_port(port, process=None):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"Staging process exited {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Listener {port} did not start")


def synthetic_responder(captures):
    class Responder(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(size)
            captures.append(
                {
                    "path": self.path,
                    "authorization_present": bool(self.headers.get("Authorization")),
                }
            )
            body = json.dumps(
                {
                    "id": "synthetic-stage",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": "llama-default",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "Synthetic downstream accepted the admitted request.",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    responder = ThreadingHTTPServer(("127.0.0.1", 14000), Responder)
    threading.Thread(target=responder.serve_forever, daemon=True).start()
    return responder


def start_process(stage, processes, command, log):
    with (stage / log).open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
    processes.append(process)
    return process


def write_stage_policies(policies, policy_bytes):
    for name, tls_port in CASES:
        policy = json.loads((ROOT / "profiles" / f"{name}.json").read_text())
        policy["origin"] = f"https://localhost:{tls_port}"
        (policies / f"{name}.json").write_text(json.dumps(policy, indent=2))
        (policies / policy["verifier_policy"]).write_bytes(policy_bytes[name])


def nginx_config(stage, certificates, attestor_url):
    config = """worker_processes 1;
pid PATH/nginx.pid;
error_log PATH/nginx-error.log;
events {worker_connections 64;}
http {
  map $http_authorization $has_auth {default 1; "" 0;}
  log_format stage '$server_port $request_method $uri $status auth=$has_auth';
  access_log PATH/nginx-access.log stage;
""".replace("PATH", str(stage))
    for _, tls_port in CASES:
        config += f"""server {{
 listen 127.0.0.1:{tls_port} ssl;
 server_name localhost;
 ssl_certificate {certificates}/certificate.pem;
 ssl_certificate_key {certificates}/private_key.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 location = /tee-report {{client_max_body_size 1k;proxy_read_timeout 25s;proxy_pass {attestor_url}/tee-report;}}
 location = /aTLS {{return 404;}}
 location /v1/ {{proxy_pass http://127.0.0.1:14000;}}
}}
"""
    return config + "}\n"


def start_proxy(stage, certificates, attestor_url, processes):
    (stage / "nginx.conf").write_text(nginx_config(stage, certificates, attestor_url))
    proxy = start_process(
        stage,
        processes,
        [
            "sudo",
            "-n",
            "nginx",
            "-c",
            str(stage / "nginx.conf"),
            "-p",
            str(stage),
            "-g",
            "daemon off;",
        ],
        "nginx-stdout.log",
    )
    wait_port(18443, proxy)
    wait_port(18444, proxy)


def load_chat_demo(stage, policies):
    os.environ["CONFIDO_POLICY_DIR"] = str(policies)
    os.environ["CONFIDO_RUN_DIR"] = str(stage / "runs")
    # Sentinel credentials only, never production credentials/provider keys.
    os.environ["CONFIDO_USERNAME"] = "stage-only"
    os.environ["CONFIDO_PASSWORD"] = "stage-only-sentinel"
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location(
        "chat_demo", ROOT / "confai-promter.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def connect(policy, path, collection, admission):
    run = collection.collect_and_verify(policy)
    result, archive = run.result, run.archive
    assert result["status"] == "verified", (
        "Transport case must start with verified evidence"
    )
    admission.save_private(path, archive)
    session = admission.authenticate(policy, result, run=run)
    run.consume(policy, result)
    return session


def check_installed_wheels(chat_demo, captures, results):
    for name, expected in (("match", True), ("mismatch", False)):
        before = len(captures)
        with patch("builtins.input", return_value=""):
            client = chat_demo.setup_client(name)
        assert (client is not None) == expected, (name, "unexpected admission")
        assert len(captures) == before, "Application request was sent during appraisal"
        if client:
            reply = client.chat.completions.create(
                model="llama-default",
                messages=[{"role": "user", "content": "Synthetic admission test."}],
            )
            assert reply.choices[0].message.content.startswith("Synthetic")
            client.close()
        observed = len(captures) - before
        assert observed == int(expected)
        results.append(
            {
                "id": f"installed_wheel_{name}",
                "expected_admitted": expected,
                "observed_admitted": client is not None,
                "application_requests": observed,
            }
        )


def check_origin_scope(stage, policies, collection, admission, captures, results):
    # A shared certificate cannot transfer admission to another origin.
    policy = collection.load_policy(policies / "match.json")
    admitted = connect(policy, stage / "scope-test.json", collection, admission)
    before = len(captures)
    for origin in (
        "https://localhost:18444",
        "http://localhost:18443",
        "https://127.0.0.1:18443",
    ):
        try:
            admitted.request(
                "POST",
                origin + "/v1/chat/completions",
                [("authorization", "stage-only-sentinel")],
                b"{}",
            )
        except RuntimeError as error:
            assert "outside" in str(error)
        else:
            raise AssertionError("Cross-origin request accepted")
    assert len(captures) == before
    results.append(
        {
            "id": "origin_scope_shared_certificate",
            "rejected_targets": 3,
            "application_requests": 0,
        }
    )

    # Fresh real evidence is insufficient when the TLS name is wrong.
    bad = dict(policy, origin="https://127.0.0.1:18443")
    try:
        connect(bad, stage / "wrong-host.json", collection, admission)
    except (RuntimeError, ValueError):
        pass
    else:
        raise AssertionError("Wrong TLS hostname admitted")
    results.append(
        {
            "id": "wrong_tls_hostname",
            "observed": "https_authentication_failed",
            "application_requests": 0,
        }
    )


def check_container(image, stage, captures, results):
    if not image:
        return
    # The container uses the same isolated public contract and new wheel.
    before = len(captures)
    for name, expected in (("match", True), ("mismatch", False)):
        command = [
            "sudo",
            "-n",
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-e",
            "CONFIDO_POLICY_DIR=/stage/profiles",
            "-e",
            "CONFIDO_RUN_DIR=/stage/container-runs",
            "-e",
            "CONFIDO_USERNAME=stage-only",
            "-e",
            "CONFIDO_PASSWORD=stage-only-sentinel",
            "-v",
            f"{stage}:/stage",
            image,
            "python3",
            "scripts/container_acceptance.py",
            name,
            str(expected).lower(),
        ]
        subprocess.run(command, check=True)
    assert len(captures) - before == 1
    results.append(
        {
            "id": "container_pair",
            "match_requests": 1,
            "mismatch_requests": 0,
            "image": image,
        }
    )


def check_appraisal_credentials(stage, results):
    access = (stage / "nginx-access.log").read_text().splitlines()
    assert not any("auth=1" in line and "/tee-report " in line for line in access)
    results.append(
        {
            "id": "no_credentials_during_appraisal",
            "report_requests": sum("/tee-report " in line for line in access),
            "credential_bearing_report_requests": 0,
        }
    )


def write_report(stage, started, results, captures):
    report = {
        "started_at": started,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "tests": results,
        "downstream": "synthetic OpenAI-compatible responder; no inference evaluated",
        "hardware": "live VM TPM collector and AMD-endorsed SNP evidence",
        "requests": captures,
    }
    (stage / "acceptance.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def stop_processes(processes):
    for process in reversed(processes):
        if process.poll() is None:
            subprocess.run(
                ["sudo", "-n", "kill", "-TERM", str(process.pid)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                subprocess.run(
                    ["sudo", "-n", "kill", "-KILL", str(process.pid)], check=False
                )


def confirm_ports_closed():
    for port in PORTS:
        for _ in range(20):
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"Staging listener {port} survived cleanup")


def cleanup(stage, responder, processes):
    if (stage / "nginx.pid").exists():
        subprocess.run(
            [
                "sudo",
                "-n",
                "nginx",
                "-s",
                "quit",
                "-c",
                str(stage / "nginx.conf"),
                "-p",
                str(stage),
            ],
            check=False,
        )
    responder.shutdown()
    responder.server_close()
    stop_processes(processes)
    confirm_ports_closed()
    subprocess.run(
        ["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(stage)],
        check=True,
    )
    for path in stage.rglob("*"):
        if path.is_file():
            path.chmod(0o600)


def main():
    args = parse_args()
    certificates = args.certificate_dir.resolve()
    attestor_url = check_attestor(args.attestor_url, certificates)
    verifier_policy_bytes = read_verifier_policies(args)
    stage, policies = prepare_stage(args.out)
    captures = []
    responder = synthetic_responder(captures)
    processes = []
    results = []
    started = datetime.now(timezone.utc).isoformat()

    try:
        write_stage_policies(policies, verifier_policy_bytes)
        start_proxy(stage, certificates, attestor_url, processes)
        chat_demo = load_chat_demo(stage, policies)
        from demo import admission, collection

        check_installed_wheels(chat_demo, captures, results)
        check_origin_scope(stage, policies, collection, admission, captures, results)
        check_container(args.container, stage, captures, results)
        check_appraisal_credentials(stage, results)
        write_report(stage, started, results, captures)
    finally:
        cleanup(stage, responder, processes)


if __name__ == "__main__":
    main()
