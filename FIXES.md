# Code review fixes

A full read-through of the server, admin UI backend, tools and installer. Every item below has a regression test in
`tests/test_review_fixes.py` or `tests/test_admin.py`; each test was confirmed to fail on the old code.

## Security

| # | Issue | Fix |
|---|---|---|
| S1 | **Login throttle could be bypassed.** uvicorn ran with `forwarded_allow_ips="*"`, so the client address came from the *leftmost* (client-supplied) `X-Forwarded-For` entry. An attacker could rotate it and brute-force the admin password without ever being locked out. | `proxy_headers` is off. The throttle key is the **right-most** `X-Forwarded-For` entry (the one Traefik appends), falling back to the socket peer. |
| S2 | **Stored Zabbix token could be sent to another host.** "Test connection" with a changed URL and an empty token field reused the stored API token against the new URL. | If the URL changes, new credentials must be supplied; the stored ones are only reused for the same server. |
| S3 | **`zabbix_raw_api` ignored the enabled-toolsets setting**, so a disabled toolset (e.g. `hosts`, `alerting`) was still reachable through the escape hatch. | `zabbix_raw_api` now refuses methods whose toolset is not enabled. |
| S4 | **Password change did not end other sessions** (sessions are stateless signed cookies). | The signing key is rotated on password change; the current session is re-issued, all others are invalidated. |
| S5 | **Admin password-change endpoint was not throttled**, allowing current-password guessing from a stolen session. | Shares the login throttle. |
| S6 | **Auth bypass exemption matched by prefix** (`/healthz*`, `/admin*`). No exploitable route existed, but it was one new route away from an unauthenticated path. | Exact match or `prefix + "/"` only. |
| S7 | **Audit-log masking missed common secret fields** (`tls_psk`, `*passphrase`, `snmp_community`, private keys). | Added to the redaction pattern. |
| S8 | CSRF token compared with `==`. | `hmac.compare_digest`. |
| S9 | Token revoke accepted a 1-character fingerprint (could revoke several tokens). | Minimum 8 characters. |
| S10 | In `CONFIRM_WRITES=destructive` mode `*.massupdate` and `*.propagate` (which can replace groups/templates) needed no confirmation. | Treated as destructive. |

## Correctness

| # | Issue | Fix |
|---|---|---|
| C1 | **Response cap not enforced for a single large item**: if the first list item alone exceeded `max_chars` it was returned whole. | The item is clipped and flagged as truncated. |
| C2 | **`get_active_problems(include_suppressed=true)` returned only suppressed problems** (Zabbix semantics: `true` = only suppressed, omitted = both). | The parameter is sent only as `false`; omitted when suppressed problems are wanted. |
| C3 | **Long-window trend queries lost the most recent data**: `limit 5000` is below the 8 760 hourly rows of a year. | Limit raised to 9 000. |
| C4 | **Config saves could overwrite changes made by another process** (e.g. `create-token` via `docker exec`, or the installer) because `update()` started from a stale in-memory copy. | `update()` reloads from disk first. |
| C5 | Dashboard widget references were derived only from the widget spec, so two identical widgets got the **same reference** (breaks widget linking). | References are made unique per dashboard. |
| C6 | Boolean widget fields were sent as JSON `true/false`; Zabbix expects integers. | Converted to `1/0`. |
| C7 | `remove_widget` silently removed **every** widget with the same name. | Refuses when the name is ambiguous. |
| C8 | Admin API returned HTTP 500 on malformed or non-object JSON bodies. | Clean `400` responses. |
| C9 | Clearing the audit-log path in settings kept writing to the old file; handlers were never closed. | Handlers are reset and closed on every path change. |
| C10 | `request_timeout <= 0` was accepted. | Rejected by validation. |
| C11 | Background close of a replaced HTTP client was fire-and-forget (task could be garbage-collected). | A reference is kept until it finishes. |

## Also changed
* Installer prints the tail of the build log when the container build fails.
* Dockerfile builds the virtualenv at its runtime path (`/app`); the previous layout produced an image whose entry point could not start (found by CI).
* Removed a stray wheel file that had been committed.

## Known limitations (deliberately not changed)
* Admin sessions are stateless: *Sign out* clears the browser cookie but cannot revoke a copied cookie (it expires after 8 h, or on password change).
* `search`-based host lookups match substrings; use exact names or `*` wildcards deliberately.
* Reads are retried only on network errors, not on 502/503 from an intermediate proxy.
