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
