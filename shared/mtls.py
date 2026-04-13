import ssl
import threading

from werkzeug.serving import WSGIRequestHandler, make_server


def build_server_ssl_context(cert_path: str, key_path: str, ca_path: str):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    context.load_verify_locations(cafile=ca_path)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    return context


def extract_common_name(peer_cert: dict) -> str:
    for attributes in peer_cert.get("subject", ()):
        for name, value in attributes:
            if name == "commonName":
                return value
    return ""


class PeerCertRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        peer_cert = None

        if isinstance(self.connection, ssl.SSLSocket):
            try:
                peer_cert = self.connection.getpeercert()
            except (OSError, ValueError):
                peer_cert = None

        environ["mtls.client_verified"] = bool(peer_cert)
        environ["mtls.client_common_name"] = extract_common_name(peer_cert or {})
        return environ


def serve_http_and_mtls(app, http_port: int, https_port: int, ssl_context):
    http_server = make_server(
        "0.0.0.0",
        http_port,
        app,
        threaded=True,
        request_handler=PeerCertRequestHandler,
    )
    https_server = make_server(
        "0.0.0.0",
        https_port,
        app,
        threaded=True,
        request_handler=PeerCertRequestHandler,
        ssl_context=ssl_context,
    )

    thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    thread.start()
    https_server.serve_forever()
