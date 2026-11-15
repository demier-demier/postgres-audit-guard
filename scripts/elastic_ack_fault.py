"""One-shot TLS fault injector for the owned, synthetic Filebeat lab."""

from contextlib import contextmanager
from hmac import compare_digest
from http.client import HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import socket
import ssl
from threading import Event, Thread
from urllib.parse import urlsplit

from elastic_receipts import normalized_bytes, strict_json


MAX_BODY = 32 * 1024
MAX_RESPONSE = 128 * 1024


def expected_create(body, index, fixture):
    """Permit a single create of the expected content in the owned fixture index."""
    try:
        action, source = (strict_json(line) for line in body.strip().split(b"\n"))
        return (action == {"create": {"_id": fixture["event"]["id"], "_index": index}}
                and normalized_bytes(source) == normalized_bytes(fixture))
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


class AckFault:
    def __init__(self):
        self.release = Event()
        self.disconnected = Event()
        self.created = None
        self.error = None


@contextmanager
def suppress_bulk_ack(port, ca, certificate, key, collector, index, fixture):
    """Forward an allowed create, verify its real response, then close without a reply."""
    fault = AckFault()
    document = fixture["event"]["id"]
    upstream_tls = ssl.create_default_context(cafile=str(ca))
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(str(certificate), str(key))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def authorized(self):
            if compare_digest(self.headers.get("Authorization", "").encode("utf-8"), collector.encode("ascii")):
                return True
            self.send_error(403)
            return False

        def upstream(self, method, path, body=None):
            connection = HTTPSConnection("127.0.0.1", port, context=upstream_tls, timeout=8)
            try:
                connection.request(method, path, body, {
                    "Authorization": collector, "Content-Type": "application/x-ndjson",
                })
                response = connection.getresponse()
                data = response.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise ValueError("Oversized upstream response")
                return response.status, data, response.getheader("X-Elastic-Product")
            finally:
                connection.close()

        def do_GET(self):
            if not self.authorized():
                return
            if self.path not in ("/", "/_license?human=false"):
                fault.error = "Unexpected collector startup route"
                self.send_error(404)
                return
            try:
                status, data, product = self.upstream("GET", self.path)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if product == "Elasticsearch":
                    self.send_header("X-Elastic-Product", product)
                self.end_headers()
                self.wfile.write(data)
            except (OSError, ValueError, HTTPException):
                fault.error = "Failed to relay owned node identity"

        def do_POST(self):
            if not self.authorized():
                return
            if urlsplit(self.path).path != "/_bulk":
                self.send_error(404)
                return
            if fault.created is not None or fault.error is not None:
                self.send_error(503)
                return
            lengths = self.headers.get_all("Content-Length") or []
            if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                    or len(lengths[0]) > 5 or not 0 < int(lengths[0]) <= MAX_BODY
                    or "Transfer-Encoding" in self.headers or "Content-Encoding" in self.headers):
                self.send_error(400)
                return
            body = self.rfile.read(int(lengths[0]))
            if len(body) != int(lengths[0]) or not expected_create(body, index, fixture):
                fault.error = "Unexpected synthetic bulk request"
                self.send_error(400)
                return
            try:
                status, data, _ = self.upstream("POST", "/_bulk", body.strip() + b"\n")
                receipt = json.loads(data)
                item, = receipt["items"]
                create = item["create"]
                if (status != 200 or receipt["errors"] is not False or
                        any(create[k] != v for k, v in {
                            "_index": index, "_id": document, "status": 201, "_version": 1, "result": "created",
                        }.items())):
                    raise ValueError("Unexpected create result")
                fault.created = {"document_id": document, "bulk_http_status": status,
                                 "item_status": create["status"], "version": create["_version"]}
                if not fault.release.wait(timeout=20):
                    raise TimeoutError("Fault window expired")
                self.close_connection = True
                # Never send status, headers or a response body for this request.
                self.connection.shutdown(socket.SHUT_RDWR)
                fault.disconnected.set()
            except (OSError, ValueError, KeyError, TypeError, HTTPException):
                fault.error = "Failed to prove or disconnect the owned bulk create"

    class LoopbackServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            try:
                return server_tls.wrap_socket(connection, server_side=True), address
            except OSError:
                connection.close()
                raise

    with LoopbackServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
        worker.start()
        try:
            yield server.server_port, fault
        finally:
            fault.release.set()
            server.shutdown()
            worker.join()


def persisted_offset(registry, source):
    """Read the cursor from the pinned Filebeat 8.19 tiny-run registry format."""
    ledger = registry / "registry" / "filebeat" / "log.json"
    with ledger.open("rb") as stream:
        payload = stream.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ValueError("Pinned registry exceeded lab limit")
    # A trailing partial line can be observed during a live append.
    lines = payload.split(b"\n")[:-1]
    offset = None
    for line in lines:
        value = json.loads(line).get("v", {})
        if value.get("meta", {}).get("source") == str(source):
            offset = (value.get("cursor") or {}).get("offset")
    return offset
