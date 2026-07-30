"""Bounded deterministic mock issuer metadata service."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JWKS = (
    b'{"keys":[{"kty":"EC","crv":"P-256",'
    b'"x":"K7bW8iaM3HtQwoaVnT3HrcQ5mser9cbgGsJj5Ptnao4",'
    b'"y":"Kaxgm7ZEy4s02PeDlNSB2n7TAsl3yn0hBzoADuRvEPg",'
    b'"alg":"ES256","kid":"reference","use":"sig"}]}'
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("cache-control", "max-age=5")
            self.send_header("content-length", str(len(JWKS)))
            self.end_headers()
            self.wfile.write(JWKS)
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        return


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
