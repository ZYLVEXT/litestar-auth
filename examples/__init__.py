"""Runnable Litestar examples for litestar-auth (not installed with the PyPI package).

Each subdirectory is a small ASGI application you can run with uvicorn after exporting the
documented environment variables.

================================================ ================================================
Package                                          Scenario
================================================ ================================================
``demo_jwt_api_keys``                            Bearer JWT + API keys (``scope_subset_check=False``).
``demo_db_token_refresh``                        Opaque DB access tokens via ``DatabaseTokenAuthConfig`` + refresh.
``demo_cookie_jwt``                              JWT in HttpOnly cookie + Litestar CSRF on unsafe methods.
``demo_api_keys_role_scopes``                    JWT + API keys with relational roles + subset-checked scopes.
``demo_totp``                                    JWT + **TOTP** 2FA (``/auth/2fa/*``: enroll, verify, recovery codes, disable).
``demo_jwt_api_keys_totp``                       JWT + API keys + TOTP (``/2fa/*`` rejects API-key-only callers).
``demo_cookie_jwt_totp``                         Cookie JWT + CSRF + TOTP (browser-oriented; HTTPS in prod).
================================================ ================================================
"""
