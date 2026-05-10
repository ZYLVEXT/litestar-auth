# Plugin and configuration

Public plugin facade and configuration dataclasses exported from `litestar_auth.plugin`, plus shared configuration helpers from `litestar_auth.config`.

`ApiKeyConfig` is the plugin-owned API-key feature switch. When `enabled=True`, it participates in
backend resolution, request-scoped store binding, controller registration, validation, and OpenAPI
security scheme generation. `apiKeyAuth` is registered for the bearer/header API-key transport;
`apiKeyHmacAuth` is registered only when signing support is configured.

::: litestar_auth.plugin

::: litestar_auth.config
