"""Exercise real Filebeat and Elasticsearch using only this repository's synthetic fixture.

Creates a new private work directory and fresh loopback-only Elasticsearch node.
No existing cluster, credentials, arbitrary endpoint, or customer file is accepted.
Requires trusted 8.19.6 archives supplied by the operator; never downloads software.
"""

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid


VERSION = "8.19.6"
INDEX = "postgres-audit-guard-lab"
REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "integrations" / "elastic"

class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise RuntimeError("HTTP redirects are forbidden in the isolated lab")


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def normalized(document):
    """Filebeat serializes its timestamp in UTC; preserve every other field exactly."""
    result = deepcopy(document)
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
        result["@timestamp"],
    )
    require(match is not None, "Timestamp is outside the comparison contract")
    base, fraction, offset = match.groups()
    instant = datetime.fromisoformat(base + offset.replace("Z", "+00:00"))
    result["@timestamp"] = (
        instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        + "." + (fraction or "").ljust(9, "0") + "Z"
    )
    return result


def available_ports(count):
    held = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            held.append(listener)
        return [listener.getsockname()[1] for listener in held]
    finally:
        for listener in held:
            listener.close()


def request(base, method, path, body=None, expected=(200,)):
    # URLs are constructed exclusively from ports chosen by this harness.
    data = None if body is None else json_bytes(body)
    query = urllib.request.Request(
        base + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with HTTP.open(query, timeout=5) as response:
            status, payload = response.status, response.read(4 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        status, payload = error.code, error.read(4 * 1024 * 1024 + 1)
    require(status in expected, f"Unexpected HTTP status {status} during {method}")
    require(len(payload) <= 4 * 1024 * 1024, "HTTP response exceeds lab limit")
    return status, json.loads(payload)


def wait_for(check, processes, label, timeout=90):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        require(all(p.poll() is None for p in processes), f"Owned process exited during {label}")
        try:
            result = check()
            if result:
                return result
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Timed out during {label}; inspect private work-directory logs")


def stop(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=15)


def cleanup(processes, handles):
    errors = []
    for process in reversed(processes):
        try:
            stop(process)
        except Exception as error:
            errors.append(type(error).__name__)
    for handle in handles:
        try:
            handle.close()
        except Exception as error:
            errors.append(type(error).__name__)
    require(not errors and all(process.poll() is not None for process in processes),
            "Owned lab process cleanup failed: " + ", ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elasticsearch-home", type=Path, required=True)
    parser.add_argument("--filebeat-home", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    require(os.name == "posix", "Lab process isolation is supported on macOS/Linux only")
    require(os.geteuid() != 0, "Run this isolated lab as a non-root user")
    es_home, fb_home = args.elasticsearch_home.resolve(), args.filebeat_home.resolve()
    binary, work = args.binary.resolve(), args.work_dir.resolve()
    require(binary.is_file(), "Build the Rust executable first")
    require((es_home / "bin/elasticsearch").is_file(), "Elasticsearch archive is missing")
    require((fb_home / "filebeat").is_file(), "Filebeat archive is missing")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)
    home = work / "home"
    home.mkdir()
    # Inherited connection settings, JVM flags, credentials and proxy variables are absent.
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C", "LC_ALL": "C"}
    processes, handles, bound_ports = [], [], []
    result = None

    def run(command, **kwargs):
        return subprocess.run(command, env=env, capture_output=True, timeout=30, **kwargs)

    def start(command, name, child_env):
        log = (work / (name + ".log")).open("wb")
        handles.append(log)
        child = subprocess.Popen(
            command, cwd=work, env=child_env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        processes.append(child)
        return child

    try:
        version_check = run([str(fb_home / "filebeat"), "version"])
        require(version_check.returncode == 0 and VERSION in version_check.stdout.decode(),
                "The lab requires Filebeat " + VERSION)
        export = work / "export.ndjson"
        exported = run([str(binary), "export-ecs", "--input", str(REPO / "examples/postgres15-local.jsonl"), "--output", str(export)])
        require(exported.returncode == 0, "Synthetic ECS export failed")
        spool = work / "ready.ndjson"
        prepared = run([str(binary), "prepare-elastic", "--input", str(export), "--output", str(spool)])
        require(prepared.returncode == 0, "ECS preparation failed")
        preparation = json.loads(prepared.stdout)
        spool_bytes = spool.read_bytes()
        docs = [json.loads(line) for line in spool_bytes.splitlines()]
        expected_docs = {doc["event"]["id"]: normalized(doc) for doc in docs}
        require(len(docs) == 8 and len(expected_docs) == 8, "Synthetic fixture must produce eight distinct alerts")
        invalids = []
        for name, change in [
            ("unexpected-field", lambda doc: doc.update(message="SYNTHETIC-PRIVATE-PROBE")),
            ("invalid-id", lambda doc: doc["event"].update(id="invalid")),
            ("unsupported-outcome", lambda doc: doc["event"].update(outcome="success")),
            ("raw-sql-flag", lambda doc: doc["postgres_audit_guard"].update(raw_sql_included=True)),
        ]:
            doc = deepcopy(docs[0])
            change(doc)
            invalids.append((name, spool_bytes + json_bytes(doc) + b"\n"))
        invalids += [("malformed-json", spool_bytes + b"{\n"),
                     ("duplicate-json-key", spool_bytes + b'{"event":{},"event":{}}\n')]
        rejected_exports = []
        for name, payload in invalids:
            source, destination = work / (name + ".ndjson"), work / (name + "-ready.ndjson")
            source.write_bytes(payload)
            check = run([str(binary), "prepare-elastic", "--input", str(source), "--output", str(destination)])
            require(check.returncode != 0 and not destination.exists(), "Invalid export was published: " + name)
            require(b"SYNTHETIC-PRIVATE-PROBE" not in check.stderr, "Preparation error leaked fixture content")
            rejected_exports.append(name)

        es_conf = work / "es-config"
        es_conf.mkdir()
        for filename in ("jvm.options", "log4j2.properties"):
            shutil.copyfile(es_home / "config" / filename, es_conf / filename)
        (es_conf / "jvm.options.d").mkdir()
        http_port, transport_port = available_ports(2)
        bound_ports.extend((http_port, transport_port))
        cluster_name = "pag-lab-" + uuid.uuid4().hex
        settings = {
            "cluster.name": cluster_name, "node.name": "pag-synthetic-node",
            "discovery.type": "single-node", "network.host": "127.0.0.1",
            "http.port": http_port, "transport.port": transport_port,
            "path.data": str(work / "es-data"), "path.logs": str(work / "es-logs"),
            "xpack.security.enabled": False, "xpack.security.autoconfiguration.enabled": False,
            "xpack.license.self_generated.type": "basic", "xpack.ml.enabled": False,
            "ingest.geoip.downloader.enabled": False, "xpack.watcher.enabled": False,
            "action.auto_create_index": False,
        }
        (es_conf / "elasticsearch.yml").write_text(json.dumps(settings))
        es_env = dict(env, ES_PATH_CONF=str(es_conf), ES_JAVA_OPTS="-Xms512m -Xmx512m -XX:ActiveProcessorCount=2")
        es = start([str(es_home / "bin/elasticsearch")], "elasticsearch", es_env)
        endpoint = f"http://127.0.0.1:{http_port}"

        def identify():
            _, response = request(endpoint, "GET", "/")
            require(response.get("cluster_name") == cluster_name, "Endpoint identity mismatch; no mutation permitted")
            require(response.get("version", {}).get("number") == VERSION, "Elasticsearch version mismatch")
            return response

        identity = wait_for(identify, [es], "owned Elasticsearch startup", timeout=180)
        def license_ready():
            status, response = request(endpoint, "GET", "/_license", expected=(200, 404))
            return response if status == 200 and "license" in response else None

        license_info = wait_for(license_ready, [es], "basic license initialization")
        require(license_info["license"]["type"] == "basic", "Lab must use basic license")
        request(endpoint, "PUT", "/_ingest/pipeline/postgres-audit-guard-v1", json.loads((CONFIG / "pipeline.json").read_text()))
        request(endpoint, "PUT", "/" + INDEX, json.loads((CONFIG / "index.json").read_text()))

        def snapshot():
            request(endpoint, "POST", "/" + INDEX + "/_refresh")
            _, response = request(endpoint, "POST", "/" + INDEX + "/_search", {"size": 100, "version": True, "query": {"match_all": {}}})
            hits = response["hits"]["hits"]
            require(len(hits) == response["hits"]["total"]["value"], "Unexpected document count")
            return {hit["_id"]: {"source": normalized(hit["_source"]), "version": hit["_version"]} for hit in hits}

        def assert_snapshot(value, version):
            return len(value) == len(expected_docs) and all(
                key in value and value[key]["source"] == doc and value[key]["version"] == version
                for key, doc in expected_docs.items()
            )

        def start_filebeat(name, registry, source):
            port = available_ports(1)[0]
            bound_ports.append(port)
            fb_env = dict(env, PAG_INPUT=str(source), PAG_ENDPOINT=endpoint, PAG_MONITOR_PORT=str(port))
            command = [str(fb_home / "filebeat"), "-e", "-c", str(CONFIG / "filebeat.yml"),
                       "--path.home", str(fb_home), "--path.config", str(CONFIG), "--path.data", str(registry), "--path.logs", str(work / (name + "-logs"))]
            process = start(command, name, fb_env)
            monitor = f"http://127.0.0.1:{port}"

            def stats():
                _, response = request(monitor, "GET", "/stats")
                return response

            return process, stats

        stages = []

        def stage(name, registry, expected_acks, expected_duplicates, append=False, source=None):
            process, stats = start_filebeat(name, registry, source or spool)
            if append:
                with spool.open("ab") as stream:
                    stream.write(spool_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())

            def complete():
                state = stats()
                events = state.get("libbeat", {}).get("output", {}).get("events", {})
                require(events.get("dropped", 0) == 0, "Filebeat dropped events; inspect private logs")
                acked = events.get("acked", 0)
                duplicates = events.get("duplicates", 0)
                if acked < expected_acks or duplicates < expected_duplicates:
                    return None
                value = snapshot()
                return (state, value) if assert_snapshot(value, 1) else None

            metrics, value = wait_for(complete, [es, process], name, timeout=90)
            stop(process)
            output_events = metrics["libbeat"]["output"]["events"]
            require(output_events.get("failed", 0) == 0 and output_events.get("dropped", 0) == 0,
                    "Filebeat reported dropped or failed events")
            require(output_events.get("acked", 0) == expected_acks, "Unexpected acknowledgements; possible duplicate replay")
            require(output_events.get("duplicates", 0) == expected_duplicates, "Unexpected duplicate conflict count")
            require(assert_snapshot(snapshot(), 1), "Final index state differs after Filebeat shutdown")
            stages.append({"stage": name, "documents": len(value), "version_per_document": 1,
                           "acknowledged_creates": output_events.get("acked", 0),
                           "observed_duplicate_conflicts": output_events.get("duplicates", 0), "sources_match": True})

        registry = work / "filebeat-state"
        stage("initial-ingest", registry, 8, 0)
        require((registry / "registry").is_dir(), "Filebeat registry was not persisted")
        stage("persistent-registry-append", registry, 0, 8, append=True)
        stage("fresh-registry-replay", work / "replay-state", 0, 16)

        # Valid shape/derived ID alone cannot attest the metadata's truth. This
        # separate batch passes preparation but must not replace the first event.
        conflict = deepcopy(docs[0])
        conflict["@timestamp"] = "2026-11-01T00:00:00Z"
        conflict_input, conflict_ready = work / "conflict-source.ndjson", work / "conflict-ready.ndjson"
        conflict_input.write_bytes(json_bytes(conflict) + b"\n")
        conflicting = run([str(binary), "prepare-elastic", "--input", str(conflict_input), "--output", str(conflict_ready)])
        require(conflicting.returncode == 0, "Standalone conflict probe must pass shape validation")
        stage("same-id-changed-payload", work / "conflict-state", 0, 1, source=conflict_ready)

        before = snapshot()
        rejected_sink = []
        for name, change in [
            ("unknown-field", lambda doc: doc.update(message="SYNTHETIC-PRIVATE-PROBE")),
            ("invalid-timestamp", lambda doc: doc.update({"@timestamp": "not-a-date"})),
            ("missing-required-field", lambda doc: doc["rule"].pop("name")),
            ("unsupported-outcome", lambda doc: doc["event"].update(outcome="success")),
            ("raw-sql-flag", lambda doc: doc["postgres_audit_guard"].update(raw_sql_included=True)),
            ("document-id-mismatch", lambda doc: doc["event"].update(id="0" * 64)),
        ]:
            doc = deepcopy(docs[0])
            key = doc["event"]["id"]
            change(doc)
            status, response = request(endpoint, "PUT", "/" + INDEX + "/_doc/" + key, doc, expected=(400,))
            require("error" in response, "Expected explicit sink rejection")
            require(snapshot() == before, "Rejected document changed stored data")
            rejected_sink.append({"case": name, "http_status": status})

        # Same-ID altered content is not allowed to replace a previously indexed alert.
        key = conflict["event"]["id"]
        status, _ = request(endpoint, "PUT", "/" + INDEX + "/_create/" + key, conflict, expected=(409,))
        require(snapshot() == before, "Create-only duplicate replaced stored content")

        sources = {key: value["source"] for key, value in sorted(before.items())}
        result = {
            "schema": "elastic-lab-result/v1", "elasticsearch_version": identity["version"]["number"],
            "filebeat_version": VERSION, "license": "basic", "fixture": "examples/postgres15-local.jsonl",
            "fixture_sha256": hashlib.sha256((REPO / "examples/postgres15-local.jsonl").read_bytes()).hexdigest(),
            "prepared_export": preparation, "stages": stages,
            "prepare_rejections": rejected_exports, "sink_rejections": rejected_sink,
            "altered_same_id_create_rejected": status == 409,
            "documents": len(sources), "outcomes": dict(Counter(doc["event"]["outcome"] for doc in sources.values())),
            "indexed_sources_sha256": hashlib.sha256(json_bytes(sources)).hexdigest(),
            "scope": "Real local Filebeat/Elasticsearch integration over original synthetic PostgreSQL records; deterministic rules, not AI inference.",
            "limitations": [
                "Loopback-only trusted-host lab has no TLS, authentication or tenant isolation; not a production deployment.",
                "One fixed index; replay across index rotation or policy versions is not deduplicated.",
                "Create-only Filebeat output preserves existing IDs. A 409 duplicate cannot distinguish identical replay from conflicting same-ID content; no cross-batch conflict registry is provided.",
                "A privileged direct API writer can still update or delete indexed data; index authorization and external evidence anchors are operator responsibilities.",
                "The Rust preflight checks hash-derived IDs; the sink checks shape and ID equality, not source-byte authenticity.",
                "Index documents are minimized derivatives; sealed evidence and human-review case snapshots remain separate.",
            ],
        }
    finally:
        cleanup(processes, handles)
        if result is not None:
            for port in bound_ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(1)
                    require(probe.connect_ex(("127.0.0.1", port)) != 0,
                            "A lab-selected loopback port is still listening after cleanup")
            result["owned_processes_stopped"] = True
            result["selected_loopback_ports_closed"] = True
            (work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
