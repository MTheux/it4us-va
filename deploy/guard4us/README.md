# Guard4US isolated production deployment

This compose project uses port 9445 and its own PostgreSQL volume. It reuses
the existing Let's Encrypt IP certificate directory at `/opt/it4us-va/certbot/conf`
read-only; certificate issuance and renewal remain with the existing service.
The VM firewall and its Azure NSG must both allow inbound TCP 9445 for external
access. Verify `https://172.206.111.166:9445/login` without disabling TLS
certificate validation.

Build `dist/amd64/it4us` with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
-tags embedui -trimpath -o dist/amd64/it4us ./cmd/it4us` after copying
`web/out/` to `server/webui/dist/`. Place `Dockerfile.va`, `start.sh`, `skills/`,
`dist/amd64/it4us`, this compose file as `compose.yaml`, and `nginx.conf` in
`/home/redadmin/guard4us`. Create a mode-0600 `.env` with a unique
`GUARD4US_DB_PASSWORD` and a persistent mode-0600 `jwt.key` outside the image,
then run `docker compose up -d --build` there. Back up the database and JWT key
together: losing the JWT key makes encrypted TOTP secrets unreadable.

The first visit to `/setup` through an SSH tunnel creates the administrator
password. Public requests to `/api/auth/init` are denied by nginx. The first
login starts TOTP enrollment. Keep the recovery codes in a password manager. The
scanner enforces task IP allow rules; no target scan occurs during deployment.

The GMP VT engine and Draxen runtime require separate configuration and
readiness checks before the UI may claim those capabilities are available.

## Microsoft SSO

Register a **single-tenant Web application** in the IT4US Microsoft Entra ID
tenant. Add the exact redirect URI
`https://172.206.111.166:9445/api/auth/entra/callback` (or the final HTTPS
hostname). Define an application role named `Guard4US.Access`, allow users or
groups to receive it, set **assignment required**, and assign only the VA team.
Enforce MFA with the tenant's Conditional Access policy. The callback requires
the exact tenant, audience, nonce and app role; an email domain alone does not
grant access. Entra users are recorded in `auth_users` on first authorized login.

Set these values in the server's mode-0600 `.env` and restart the app. Keep the
client secret out of Git and deployment logs:

```dotenv
GUARD4US_ENTRA_TENANT_ID=<tenant-guid>
GUARD4US_ENTRA_CLIENT_ID=<application-client-guid>
GUARD4US_ENTRA_CLIENT_SECRET=<secret-from-entra>
GUARD4US_ENTRA_REDIRECT_URL=https://172.206.111.166:9445/api/auth/entra/callback
GUARD4US_ENTRA_REQUIRED_ROLE=Guard4US.Access
```

SSO sessions last one hour. Disabling an `auth_users` row blocks its existing
session on the next API request. Removing an Entra assignment blocks new logins;
existing sessions remain valid until they expire unless the local row is disabled.
The local password/TOTP account remains available as a separate break-glass
login until the operator explicitly retires it.
