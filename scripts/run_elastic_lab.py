"""Exercise real Filebeat and Elasticsearch using only this repository's synthetic fixture.

Creates a new private work directory and fresh loopback-only Elasticsearch node.
No existing cluster, credentials, arbitrary endpoint, or customer file is accepted.
Requires trusted 8.19.6 archives supplied by the operator; never downloads software.
"""

import argparse
import base64
from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

from elastic_receipts import normalized


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


def request(base, method, path, body=None, expected=(200,), *, opener=None, authorization=None):
    # URLs are constructed exclusively from ports chosen by this harness.
    data = None if body is None else json_bytes(body)
    headers = {"Content-Type": "application/json"}
    if authorization is not None:
        headers["Authorization"] = authorization
    query = urllib.request.Request(
        base + path, data=data, method=method,
        headers=headers,
    )
    try:
        with (opener or HTTP).open(query, timeout=20 if method == "PUT" else 5) as response:
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
    import elastic_ack_fault
    import elastic_lab_tls

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elasticsearch-home", type=Path, required=True)
    parser.add_argument("--filebeat-home", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--tls", action="store_true", help="Use verified TLS and an expiring create-only collector key")
    parser.add_argument("--receipts", action="store_true", help="Exercise durable classification before collection")
    parser.add_argument("--delivery", action="store_true",
                        help="Exercise a bounded Filebeat interruption and recovery with --tls --receipts")
    parser.add_argument("--ack-loss", action="store_true",
                        help="Drop a committed bulk reply on the owned TLS path with --delivery")
    args = parser.parse_args()
    require(not args.ack_loss or args.delivery, "Lost acknowledgement testing requires --delivery")
    require(not args.delivery or (args.tls and args.receipts), "Delivery recovery requires --tls --receipts")
    require(os.name == "posix", "Lab process isolation is supported on macOS/Linux only")
    require(os.geteuid() != 0, "Run this isolated lab as a non-root user")
    es_home, fb_home = args.elasticsearch_home.resolve(), args.filebeat_home.resolve()
    binary, work = args.binary.resolve(), args.work_dir.resolve()
    require(binary.is_file(), "Build the Rust executable first")
    require((es_home / "bin/elasticsearch").is_file(), "Elasticsearch archive is missing")
    require((fb_home / "filebeat").is_file(), "Filebeat archive is missing")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(shutil.disk_usage(work).free > 2 * 1024 ** 3, "Lab requires more than 2 GiB free")
    os.umask(0o077)
    home = work / "home"
    home.mkdir()
    # Inherited connection settings, JVM flags, credentials and proxy variables are absent.
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C", "LC_ALL": "C"}
    processes, handles, bound_ports = [], [], []
    result = None

    def run(command, child_env=env, **kwargs):
        return subprocess.run(command, env=child_env, capture_output=True, timeout=30, **kwargs)

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
        journal_result = None
        if args.receipts:
            journal = [sys.executable, str(REPO / "scripts/elastic_receipts.py"),
                       "--journal", str(work / "receipts.db")]

            def receipt_call(command, *parameters, code=0):
                result = run([*journal, command, *parameters])
                require(result.returncode == code, "Receipt operation failed: " + command)
                return json.loads(result.stdout) if result.stdout else None

            receipt_call("init")
            source_args = ("--input", str(spool), "--binary", str(binary))
            first = receipt_call("submit", "--batch", "initial", *source_args)
            replay = receipt_call("submit", "--batch", "replay", *source_args)
            changed = deepcopy(docs[0])
            changed["@timestamp"] = "2026-11-01T00:00:00Z"
            probe = work / "receipt-conflict.ndjson"
            probe.write_bytes(json_bytes(changed) + b"\n")
            conflict_receipt = receipt_call(
                "submit", "--batch", "conflict", "--input", str(probe), "--binary", str(binary), code=2,
            )
            require(first["counts"] == {"accepted": 8, "replay": 0, "conflict": 0}
                    and replay["counts"] == {"accepted": 0, "replay": 8, "conflict": 0}
                    and conflict_receipt["counts"] == {"accepted": 0, "replay": 0, "conflict": 1},
                    "Unexpected receipt classifications")
            require(receipt_call("receipt", "--batch", "conflict") == conflict_receipt,
                    "Persisted conflict receipt changed after reopening")
            require(receipt_call("submit", "--batch", "initial", *source_args) == first,
                    "Retry after commit changed the original receipt")
            invalid_args = ("--input", str(probe), "--binary", str(binary))
            receipt_call("submit", "--batch", "initial", *invalid_args, code=1)
            require(receipt_call("receipt", "--batch", "initial") == first,
                    "Batch-label collision changed the accepted receipt")
            malformed = work / "invalid-receipt-source.ndjson"
            malformed.write_bytes(spool_bytes + b"{\n")
            receipt_call("submit", "--batch", "invalid", "--input", str(malformed),
                         "--binary", str(binary), code=1)
            receipt_call("receipt", "--batch", "invalid", code=1)
            spool = work / "journal-ready.ndjson"
            staged = receipt_call("materialize", "--batch", "initial", "--output", str(spool))
            require(spool.read_bytes() == spool_bytes, "Journal altered accepted canonical content")
            receipt_call("materialize", "--batch", "replay", "--output", str(spool), code=1)
            require(spool.read_bytes() == spool_bytes, "Materialization overwrote existing output")
            for label in ("replay", "conflict"):
                empty_spool = receipt_call("materialize", "--batch", label,
                                           "--output", str(work / (label + "-empty.ndjson")))
                require(empty_spool["documents"] == 0, "Non-accepted records reached the spool")
            rejected = work / "retained-conflict.ndjson"
            retained = receipt_call("export-conflicts", "--batch", "conflict", "--output", str(rejected))
            require(retained["documents"] == 1 and json.loads(rejected.read_bytes()) == changed,
                    "Conflict content was not retained for review")
            journal_result = {"accepted": staged, "replay": replay["counts"],
                              "conflict_receipt": conflict_receipt, "retained_conflict": retained,
                              "retry_preserved_receipt": True, "batch_label_collision_rejected": True,
                              "malformed_batch_left_no_receipt": True, "existing_output_preserved": True}
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
            # A tiny fixture on a large shared disk still needs its primary allocated.
            "cluster.routing.allocation.disk.watermark.low": "2gb",
            "cluster.routing.allocation.disk.watermark.high": "1gb",
            "cluster.routing.allocation.disk.watermark.flood_stage": "512mb",
        }
        es_env = dict(env, ES_PATH_CONF=str(es_conf), ES_JAVA_OPTS="-Xms512m -Xmx512m -XX:ActiveProcessorCount=2")
        opener = admin = ca = None
        if args.tls:
            ca, security_settings = elastic_lab_tls.certificates(es_conf, run, require)
            settings.update(security_settings)
            opener = elastic_lab_tls.verified_http(ca, NoRedirects)
        (es_conf / "elasticsearch.yml").write_text(json.dumps(settings))
        if args.tls:
            admin = elastic_lab_tls.bootstrap(es_home, es_env, run, require)
        es = start([str(es_home / "bin/elasticsearch")], "elasticsearch", es_env)
        scheme = "https" if args.tls else "http"
        endpoint = f"{scheme}://127.0.0.1:{http_port}"

        def es_request(method, path, body=None, expected=(200,)):
            return request(endpoint, method, path, body, expected, opener=opener, authorization=admin)

        def identify():
            status, response = es_request("GET", "/", expected=(200, 503) if args.tls else (200,))
            if status == 503:
                return None
            require(response.get("cluster_name") == cluster_name, "Endpoint identity mismatch; no mutation permitted")
            require(response.get("version", {}).get("number") == VERSION, "Elasticsearch version mismatch")
            return response

        identity = wait_for(identify, [es], "owned Elasticsearch startup", timeout=180)
        def license_ready():
            status, response = es_request("GET", "/_license", expected=(200, 404))
            return response if status == 200 and "license" in response else None

        license_info = wait_for(license_ready, [es], "basic license initialization")
        require(license_info["license"]["type"] == "basic", "Lab must use basic license")
        es_request("PUT", "/_ingest/pipeline/postgres-audit-guard-v1", json.loads((CONFIG / "pipeline.json").read_text()))
        es_request("PUT", "/" + INDEX, json.loads((CONFIG / "index.json").read_text()))
        collector = None
        if args.tls:
            _, key = es_request("POST", "/_security/api_key", {
                "name": "pag-synthetic-collector", "expiration": "30m",
                "role_descriptors": {"collector": {
                    "cluster": ["monitor"], "indices": [{"names": [INDEX], "privileges": ["create_doc"]}],
                }},
            })
            collector = "ApiKey " + key["encoded"]
            key_info_id = key["id"]
            collector_value = base64.b64decode(key["encoded"]).decode("ascii")

        def collector_request(method, path, body=None, expected=(200,)):
            return request(endpoint, method, path, body, expected, opener=opener, authorization=collector)

        def snapshot():
            es_request("POST", "/" + INDEX + "/_refresh")
            _, response = es_request("POST", "/" + INDEX + "/_search", {"size": 100, "version": True, "query": {"match_all": {}}})
            hits = response["hits"]["hits"]
            require(len(hits) == response["hits"]["total"]["value"], "Unexpected document count")
            return {hit["_id"]: {"source": normalized(hit["_source"]), "version": hit["_version"]} for hit in hits}

        def version_one(documents):
            return {key: {"source": doc, "version": 1} for key, doc in documents.items()}

        def assert_snapshot(value, version):
            return len(value) == len(expected_docs) and all(
                key in value and value[key]["source"] == doc and value[key]["version"] == version
                for key, doc in expected_docs.items()
            )

        def start_filebeat(name, registry, source, fault_port=None):
            port = available_ports(1)[0]
            bound_ports.append(port)
            output = endpoint if fault_port is None else f"https://127.0.0.1:{fault_port}"
            fb_env = dict(env, PAG_INPUT=str(source), PAG_ENDPOINT=output, PAG_MONITOR_PORT=str(port))
            command = [str(fb_home / "filebeat"), "-e", "-c", str(CONFIG / "filebeat.yml"),
                       "--path.home", str(fb_home), "--path.config", str(CONFIG), "--path.data", str(registry), "--path.logs", str(work / (name + "-logs"))]
            if args.tls:
                fb_env["PAG_CA"] = str(ca)
                if not (registry / "filebeat.keystore").is_file():
                    registry.mkdir(exist_ok=True)
                    keystore = [str(fb_home / "filebeat"), "keystore", "-c", str(CONFIG / "filebeat.yml"),
                                "--path.home", str(fb_home), "--path.data", str(registry)]
                    require(run([*keystore, "create"], child_env=fb_env).returncode == 0, "Filebeat keystore creation failed")
                    require(run([*keystore, "add", "PAG_COLLECTOR_KEY", "--stdin"], child_env=fb_env,
                                input=collector_value.encode()).returncode == 0, "Filebeat keystore rejected collector key")
                command += ["-E", "output.elasticsearch.api_key=${PAG_COLLECTOR_KEY}",
                            "-E", "output.elasticsearch.ssl.certificate_authorities=[${PAG_CA}]",
                            "-E", "output.elasticsearch.ssl.verification_mode=full"]
            if fault_port is not None:
                command += ["-E", "output.elasticsearch.compression_level=0"]
            process = start(command, name, fb_env)
            monitor = f"http://127.0.0.1:{port}"

            def stats():
                _, response = request(monitor, "GET", "/stats")
                return response

            return process, stats

        stages = []

        def append_rows(source, payload):
            with source.open("ab") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

        def complete_stage(process, stats, expected_acks, expected_duplicates, expected, name):
            target = version_one(expected)

            def complete():
                state = stats()
                events = state.get("libbeat", {}).get("output", {}).get("events", {})
                require(events.get("dropped", 0) == 0, "Filebeat dropped events; inspect private logs")
                if events.get("acked", 0) < expected_acks or events.get("duplicates", 0) < expected_duplicates:
                    return None
                value = snapshot()
                return (events, value) if value == target else None

            output_events, value = wait_for(complete, [es, process], name, timeout=90)
            require(output_events.get("failed", 0) == 0 and output_events.get("dropped", 0) == 0,
                    "Filebeat reported dropped or failed events")
            require(output_events.get("acked", 0) == expected_acks, "Unexpected acknowledgements; possible duplicate replay")
            require(output_events.get("duplicates", 0) == expected_duplicates, "Unexpected duplicate conflict count")
            return {"stage": name, "documents": len(value), "version_per_document": 1,
                    "acknowledged_creates": expected_acks, "observed_duplicate_conflicts": expected_duplicates,
                    "sources_match": True}

        def stage(name, registry, expected_acks, expected_duplicates, append=False, source=None, expected=None):
            if expected is None:
                expected = expected_docs
            process, stats = start_filebeat(name, registry, source or spool)
            if append:
                append_rows(spool, spool_bytes)

            staged = complete_stage(process, stats, expected_acks, expected_duplicates, expected, name)
            stop(process)
            require(snapshot() == version_one(expected),
                    "Final index state differs after Filebeat shutdown")
            stages.append(staged)

        registry = work / "filebeat-state"
        delivery_result = None
        ack_loss_result = None
        if args.delivery:
            _, reader_key = es_request("POST", "/_security/api_key", {
                "name": "pag-synthetic-reader", "expiration": "30m",
                "role_descriptors": {"reader": {
                    "indices": [{"names": [INDEX], "privileges": ["read"]}],
                }},
            })
            reader = "ApiKey " + reader_key["encoded"]
            batch_args = ("--batch", "initial")
            query = receipt_call("delivery-query", *batch_args)
            require(query == {"ids": sorted(expected_docs)}, "Delivery query differs from accepted fixture")
            mget = "/" + INDEX + "/_mget"

            def observe(label):
                _, payload = request(endpoint, "POST", mget, query, opener=opener, authorization=reader)
                captured = work / (label + "-mget.json")
                captured.write_bytes(json_bytes(payload))
                parameters = (*batch_args, "--observation", label, "--index", INDEX, "--snapshot", str(captured))
                result = receipt_call("observe-delivery", *parameters)
                require(receipt_call("observe-delivery", *parameters) == result
                        and receipt_call("delivery-receipt", "--observation", label) == result,
                        "Observation did not survive retry and database reopening")
                return result

            # Publish only the first half, then abruptly stop the owned collector.
            wave = work / "partial-wave.ndjson"
            wave.write_bytes(b"".join(spool_bytes.splitlines(keepends=True)[:4]))
            partial = {doc["event"]["id"]: normalized(doc) for doc in docs[:4]}
            process, stats = start_filebeat("interrupted-collector", registry, wave)
            interruption = complete_stage(process, stats, 4, 0, partial, "interrupted-collector")
            os.killpg(process.pid, signal.SIGKILL)
            require(process.wait(timeout=15) == -signal.SIGKILL, "Filebeat did not exit from interruption")
            require(snapshot() == version_one(partial), "Index changed after collector interruption")
            before_recovery = observe("after-interruption")
            require(before_recovery["counts"] == {"confirmed": 4, "missing": 4, "mismatch": 0},
                    "Partial delivery observation did not identify the backlog")
            missing = set(expected_docs) - set(partial)
            require({row["document_id"] for row in before_recovery["events"] if row["disposition"] == "missing"}
                    == missing, "Wrong IDs selected for recovery")
            recovery = work / "recovery-wave.ndjson"
            recovery_receipt = receipt_call("recover-missing", "--observation", "after-interruption",
                                            "--output", str(recovery))
            require(recovery_receipt["documents"] == 4 and
                    {json.loads(line)["event"]["id"] for line in recovery.read_bytes().splitlines()} == missing,
                    "Recovery spool does not contain exactly the missing IDs")
            recovery_registry = work / "recovery-state"
            stage("recovery-collector", recovery_registry, 4, 0, source=recovery)
            after_recovery = observe("after-recovery")
            require(after_recovery["counts"] == {"confirmed": 8, "missing": 0, "mismatch": 0},
                    "Recovered payloads did not match the full accepted batch")
            receipt_call("recover-missing", "--observation", "after-interruption",
                         "--output", str(work / "stale-wave.ndjson"), code=1)
            no_work = receipt_call("recover-missing", "--observation", "after-recovery",
                                   "--output", str(work / "empty-recovery.ndjson"))
            require(no_work["documents"] == 0, "Confirmed rows were selected for a retry")

            # A privileged rewrite of an equal payload must still be visible as a mismatch.
            rewritten_id = docs[0]["event"]["id"]
            _, rewrite = es_request("PUT", "/" + INDEX + "/_doc/" + rewritten_id, docs[0])
            require(rewrite["_version"] == 2, "Expected a second document version in the owned lab index")
            after_rewrite = observe("after-privileged-rewrite")
            require(after_rewrite["counts"] == {"confirmed": 7, "missing": 0, "mismatch": 1},
                    "A privileged rewrite was not isolated for review")
            withheld = receipt_call("recover-missing", "--observation", "after-privileged-rewrite",
                                    "--output", str(work / "no-rewrite.ndjson"))
            require(withheld["documents"] == 0, "A mismatched document entered a recovery spool")

            es_request("PUT", "/pag-unrelated", {"settings": {"number_of_replicas": 0}})
            es_request("PUT", "/pag-unrelated/_doc/" + rewritten_id, docs[0], expected=(201,))
            denied = []
            denied_capture = None
            for name, method, path, body in [
                ("collector-mget", "POST", mget, query),
                ("reader-create", "PUT", "/" + INDEX + "/_create/" + docs[0]["event"]["id"], docs[0]),
                ("reader-other-index", "POST", "/pag-unrelated/_mget", query),
            ]:
                status, payload = request(endpoint, method, path, body, expected=(200, 403), opener=opener,
                                          authorization=collector if name == "collector-mget" else reader)
                if status == 403:
                    errors = [payload.get("error", {})]
                else:
                    hits = payload.get("docs", [])
                    require(method == "POST" and [hit.get("_id") for hit in hits] == query["ids"]
                            and all("_source" not in hit and "found" not in hit for hit in hits),
                            "Expected per-document denial: " + name)
                    errors = [hit.get("error", {}) for hit in hits]
                require(all(error.get("type") == "security_exception" for error in errors), "Expected denial: " + name)
                denied.append({"case": name, "http_status": status, "denied_entries": len(errors)})
                if name == "collector-mget":
                    denied_capture = work / "denied-mget.json"
                    denied_capture.write_bytes(json_bytes(payload))
            receipt_call("observe-delivery", *batch_args, "--observation", "denied-probe",
                         "--index", INDEX, "--snapshot", str(denied_capture), code=1)
            receipt_call("delivery-receipt", "--observation", "denied-probe", code=1)
            if args.ack_loss:
                es_request("DELETE", "/" + INDEX)
                es_request("PUT", "/" + INDEX, json.loads((CONFIG / "index.json").read_text()))
                source = work / "ack-loss.ndjson"
                lines = spool_bytes.splitlines(keepends=True)
                source.write_bytes(b"".join(lines[:-1]))
                prefix_offset = source.stat().st_size
                final_id = docs[-1]["event"]["id"]
                prefix = {key: doc for key, doc in expected_docs.items() if key != final_id}
                saved = work / "ack-loss-state"
                stage("ack-loss-prefix", saved, 7, 0, source=source, expected=prefix)
                initial = stages.pop()

                def checkpoint(label, expected_offset):
                    private_ledger = saved / "registry/filebeat/log.json"
                    require(elastic_ack_fault.persisted_offset(saved, source) == expected_offset,
                            "Unexpected persisted cursor at " + label)
                    shutil.copyfile(private_ledger, work / ("ack-loss-" + label + "-registry.jsonl"))
                    return expected_offset

                checkpoint("acknowledged-prefix", prefix_offset)
                proxy = elastic_ack_fault.suppress_bulk_ack(
                    http_port, ca, es_conf / "tls/node.pem", es_conf / "tls/node.key", collector, INDEX, docs[-1],
                )
                with proxy as (fault_port, fault):
                    bound_ports.append(fault_port)
                    process, stats = start_filebeat("ack-loss-collector", saved, source, fault_port=fault_port)
                    append_rows(source, lines[-1])

                    def accepted_without_reply():
                        require(fault.error is None, fault.error)
                        return fault.created

                    upstream = wait_for(accepted_without_reply, [process, es], "owned upstream bulk create")
                    require(snapshot() == version_one(expected_docs), "Accepted bulk did not preserve exact fixture state")
                    checkpoint("before-disconnect", prefix_offset)
                    fault.release.set()

                    def failed_reply():
                        require(fault.error is None, fault.error)
                        output = stats().get("libbeat", {}).get("output", {}).get("events", {})
                        require(output.get("acked", 0) == 0, "Collector acknowledged the withheld reply")
                        return fault.disconnected.is_set() and output.get("failed", 0) > 0

                    wait_for(failed_reply, [process, es], "collector observing lost reply", timeout=20)
                    lost_offset = checkpoint("after-disconnect", prefix_offset)
                    os.killpg(process.pid, signal.SIGKILL)
                    require(process.wait(timeout=15) == -signal.SIGKILL, "Collector did not stop after lost reply")
                before_retry = observe("ack-lost-before-restart")
                require(before_retry["counts"] == {"confirmed": 8, "missing": 0, "mismatch": 0},
                        "Stored documents were not independently confirmed before collector restart")
                empty_retry = receipt_call("recover-missing", "--observation", "ack-lost-before-restart",
                                           "--output", str(work / "ack-lost-no-manual-recovery.ndjson"))
                require(empty_retry["documents"] == 0, "Read-side recovery must not spool committed documents")
                stage("ack-loss-restart", saved, 0, 1, source=source)
                restarted = stages.pop()
                final_offset = checkpoint("after-retry", source.stat().st_size)
                append_rows(source, lines[0])
                stage("ack-loss-offset-control", saved, 0, 1, source=source)
                control = stages.pop()
                probe_offset = checkpoint("after-append", source.stat().st_size)
                ack_loss_result = {
                    "prefix": initial, "upstream_create": upstream, "fault": "tls_disconnect_without_http_response",
                    "collector_reported_output_failure": True, "collector_exit": "SIGKILL",
                    "before_restart": before_retry["counts"], "manual_recovery_documents": empty_retry["documents"],
                    "restart": restarted, "next_restart_append_control": control,
                    "offset_bytes": {"acknowledged_prefix": prefix_offset, "after_lost_reply": lost_offset,
                                     "after_retry": final_offset, "after_append_control": probe_offset},
                }

            es_request("DELETE", "/_security/api_key", {"ids": [reader_key["id"]]})
            revoked, _ = request(endpoint, "POST", mget, query, expected=(401,), opener=opener, authorization=reader)
            delivery_result = {
                "interruption": interruption, "collector_exit": "SIGKILL",
                "after_interruption": before_recovery, "recovery_spool": recovery_receipt,
                "recovery": stages.pop(), "after_recovery": after_recovery,
                "after_privileged_rewrite": after_rewrite, "mismatch_spool_documents": withheld["documents"],
                "followup_spool_documents": no_work["documents"], "stale_observation_rejected": True,
                "authorization_error_left_no_observation": True,
                "reader_index_privileges": ["read"], "denied_operations": denied,
                "revoked_reader_status": revoked,
            }
            # Restore a new fixture index for the independent, pre-existing control sequence.
            es_request("DELETE", "/" + INDEX)
            es_request("PUT", "/" + INDEX, json.loads((CONFIG / "index.json").read_text()))
            registry = work / "filebeat-control-state"
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
            operation = "_create" if args.tls else "_doc"
            status, response = collector_request("PUT", f"/{INDEX}/{operation}/{key}", doc, expected=(400,))
            require("error" in response, "Expected explicit sink rejection")
            require(snapshot() == before, "Rejected document changed stored data")
            rejected_sink.append({"case": name, "http_status": status})
            if args.tls:
                rejected_sink[-1].update({
                    "document_id": key, "body_sha256": hashlib.sha256(json_bytes(doc)).hexdigest(),
                    "error_type": response["error"]["type"],
                })

        # Same-ID altered content is not allowed to replace a previously indexed alert.
        key = conflict["event"]["id"]
        status, _ = collector_request("PUT", "/" + INDEX + "/_create/" + key, conflict, expected=(409,))
        require(snapshot() == before, "Create-only duplicate replaced stored content")

        sources = {key: value["source"] for key, value in sorted(before.items())}
        report = {
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
        if args.tls:
            tls_rejections = elastic_lab_tls.prove_tls_rejection(request, endpoint, opener, require)
            status, _ = request(endpoint, "GET", "/", expected=(401,), opener=opener)
            forbidden = []
            document_path = "/" + INDEX + "/_doc/" + key
            for name, method, path, body in [
                ("overwrite", "PUT", document_path, conflict),
                ("update", "POST", "/" + INDEX + "/_update/" + key, {"doc": conflict}),
                ("delete-document", "DELETE", document_path, None),
                ("read-document", "GET", document_path, None),
                ("delete-index", "DELETE", "/" + INDEX, None),
                ("write-other-index", "PUT", "/pag-unrelated/_create/" + key, conflict),
                ("manage-ingest-pipeline", "PUT", "/_ingest/pipeline/pag-collector-probe", {"processors": []}),
            ]:
                code, response = collector_request(method, path, body, expected=(403,))
                require(response.get("error", {}).get("type") == "security_exception",
                        "Expected a privilege denial for " + name)
                require(snapshot() == before, "Denied operation modified stored alerts")
                forbidden.append({"case": name, "http_status": code, "error_type": "security_exception",
                                  "body_sha256": hashlib.sha256(json_bytes(body)).hexdigest() if body is not None else None})
            es_request("DELETE", "/_security/api_key", {"ids": [key_info_id]})
            revoked, _ = collector_request("GET", "/", expected=(401,))
            report["schema"] = "elastic-lab-result/v2"
            report["security"] = {"http_tls": "verified", "tls_rejections": tls_rejections,
                                  "unauthenticated_status": status, "collector_revoked_status": revoked,
                                  "collector_cluster_privileges": ["monitor"],
                                  "collector_index_privileges": ["create_doc"],
                                  "collector_index": INDEX, "denied_operations": forbidden}
            report["limitations"][0] = "Loopback-only synthetic lab with per-run TLS and authorization; no tenant isolation or production deployment."
        if journal_result is not None:
            report["receipt_journal"] = journal_result
            report["limitations"][2] = (
                "The journal identifies conflicts within its own history. Filebeat's 409 response alone remains ambiguous."
            )
        if delivery_result is not None:
            report["delivery_reconciliation"] = delivery_result
            report["limitations"].append(
                "A matching read is evidence of index state at capture time. It cannot attribute a write or prove exactly-once delivery."
            )
        if ack_loss_result is not None:
            report["lost_acknowledgement"] = ack_loss_result
        result = report
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
