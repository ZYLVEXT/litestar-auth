"""Run the demo ASGI app (requires an ASGI server such as uvicorn)."""

from __future__ import annotations


def main() -> None:
    """Serve ``examples.demo_totp.app:app`` on ``127.0.0.1:8000``.

    Raises:
        SystemExit: When ``uvicorn`` is not installed.
    """
    try:
        import uvicorn  # noqa: PLC0415
    except ModuleNotFoundError:
        msg = (
            "Install an ASGI server, for example:\n"
            "  uv add uvicorn\n"
            "Then:\n"
            "  LITESTAR_AUTH_DEMO_TOTP_INSECURE=1 uv run python -m examples.demo_totp\n"
            "Or:\n"
            "  LITESTAR_AUTH_DEMO_TOTP_INSECURE=1 uv run uvicorn examples.demo_totp.app:app "
            "--host 127.0.0.1 --port 8000"
        )
        raise SystemExit(msg) from None

    uvicorn.run(
        "examples.demo_totp.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    main()
