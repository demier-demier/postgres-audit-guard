"""Credentials and verified TLS for the owned synthetic Elastic lab."""

import base64
import secrets
import ssl
import urllib.error
import urllib.request


def certificates(work, run, require):
    """Use a per-run CA and an IP SAN matching the loopback endpoint."""
    tls = work / "tls"
    tls.mkdir()
    config = tls / "openssl.cnf"
    config.write_text("""[req]
distinguished_name = subject
[subject]
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
[node]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = IP:127.0.0.1
""")
    ca, key, cert = tls / "ca.pem", tls / "node.key", tls / "node.pem"
    ca_key, csr = tls / "ca.key", tls / "node.csr"
    commands = [
        ["req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-days", "1", "-subj", "/CN=PAG ephemeral lab CA", "-config", str(config),
         "-extensions", "ca", "-keyout", str(ca_key), "-out", str(ca)],
        ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=PAG lab node",
         "-config", str(config), "-keyout", str(key), "-out", str(csr)],
        ["x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
         "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(config),
         "-extensions", "node", "-out", str(cert)],
    ]
    for command in commands:
        require(run(["openssl", *command]).returncode == 0, "Lab certificate generation failed")
    ca_key.unlink()
    settings = {"xpack.security.enabled": True}
    for channel in ("http", "transport"):
        prefix = "xpack.security." + channel + ".ssl."
        settings.update({
            prefix + "enabled": True, prefix + "key": str(key),
            prefix + "certificate": str(cert), prefix + "certificate_authorities": [str(ca)],
        })
    return ca, settings


def bootstrap(es_home, es_env, run, require):
    password = secrets.token_urlsafe(32)
    command = [str(es_home / "bin/elasticsearch-keystore")]
    require(run([*command, "create"], child_env=es_env).returncode == 0,
            "Elasticsearch keystore creation failed")
    require(run([*command, "add", "-x", "bootstrap.password"], child_env=es_env,
                input=(password + "\n").encode()).returncode == 0,
            "Elasticsearch keystore rejected the bootstrap password")
    return "Basic " + base64.b64encode(("elastic:" + password).encode()).decode()


def verified_http(ca, no_redirects):
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), no_redirects(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
    )


def prove_tls_rejection(request, endpoint, opener, require):
    for address, transport, label in [
        (endpoint, None, "untrusted-ca"),
        (endpoint.replace("127.0.0.1", "localhost"), opener, "hostname-mismatch"),
    ]:
        try:
            request(address, "GET", "/", opener=transport)
        except urllib.error.URLError as error:
            require(isinstance(error.reason, ssl.SSLCertVerificationError),
                    "TLS probe failed for a reason other than certificate verification")
        else:
            raise RuntimeError("Unexpected TLS acceptance: " + label)
    return ["untrusted-ca", "hostname-mismatch"]
