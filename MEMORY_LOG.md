# Memory Log

Project: `/Users/johnsteele/code/go-oauth-service`

## Direction

- This service is a first-party app login service, not a Google-style identity provider.
- OAuth2/OIDC is for apps using the login service.
- The Admin UI is the control plane and uses its own server-side session cookie, not OAuth.
- Consent screens are intentionally out of scope for now.

## Architecture Decisions

- Admin UI login uses `admin_session_id`.
- Admin sessions live under `server/ui/adminsession`.
- OAuth auth-flow sessions remain separate in `auth/authflowsession`.
- OAuth2 handlers live in `server/oauth2`.
- UI handlers live in `server/ui`.
- Admin UI uses HTMX/server-rendered fragments, not a JSON Admin API for now.
- A future Admin API may be useful for automation, but it is not needed yet.

## Removed Or Cleaned Up

- Removed `loginsession`.
- Removed `callbackstate`.
- Removed `form_post`.
- Removed the seeded admin OAuth client bootstrap.
- Removed old admin-client config/env hooks.
- Removed dead middleware bits.

## Bootstrap

Bootstrap now creates:

- system tenant
- default super-admin user

Bootstrap no longer creates:

- admin dashboard OAuth client

## Tenant And Admin Behavior

- System tenant domain is blank.
- Tenant domain is derived/read-only in the UI.
- Tenant ID drives the derived domain.
- Tenant IDs allow lowercase letters, numbers, `-`, and `_`.
- Tenant ID availability is checked with HTMX before create.
- Clients menu stays visible for normal tenants.
- Dashboard shows Clients for normal tenant admins.
- Tenants management remains system-tenant/super-admin only.

## Logging

- Log colours were fixed by configuring zerolog console output via `go-colorable`.

## Verification

Use:

```bash
GOCACHE=/private/tmp/go-oauth-service-go-build-cache go test ./...
```

Last known status: passing.
