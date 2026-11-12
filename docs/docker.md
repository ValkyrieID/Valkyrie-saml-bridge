# Docker

The repository has a `Dockerfile` that builds the bridge into a container image, and a `compose.yaml` that runs it behind a Caddy reverse proxy. The bridge runs as a non-root user and serves plain HTTP on port 8080 inside the Compose network only. Caddy terminates TLS on ports 80 and 443 and forwards to the bridge. Caddy is needed because `SAMLBRIDGE_PUBLIC_URL` must be an `https` origin (see [Configuration](/configuration)).

## Compose

`compose.yaml` in the `saml-bridge` directory:

```yaml
services:
  saml-bridge:
    build: .
    image: valkyrie-saml-bridge:local
    restart: unless-stopped
    volumes:
      - saml-bridge-data:/data
    env_file:
      - .env
    environment:
      SAMLBRIDGE_DATABASE: /data/saml-bridge.db

  caddy:
    image: caddy:2
    restart: unless-stopped
    depends_on:
      - saml-bridge
    ports:
      - "80:80"
      - "443:443"
    environment:
      SAMLBRIDGE_HOST: ${SAMLBRIDGE_HOST:?set SAMLBRIDGE_HOST in .env}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config

volumes:
  saml-bridge-data:
  caddy-data:
  caddy-config:
```

Only Caddy publishes ports. The bridge is reachable only from Caddy, over the Compose network.

`Caddyfile` next to `compose.yaml`:

```caddy
# Public origin of the bridge, for example sso.example.test. Caddy gets a certificate for it.
{$SAMLBRIDGE_HOST} {
	reverse_proxy saml-bridge:8080
}
```

Caddy reads the host name from `SAMLBRIDGE_HOST`, which Compose passes in from `.env`. It requests a certificate from Let's Encrypt on first start, so the host name must resolve to this machine and ports 80 and 443 must be reachable from the internet. Caddy redirects plain HTTP to HTTPS.

`.env` next to `compose.yaml`. Keep it out of version control:

```sh
SAMLBRIDGE_HOST=sso.example.test
SAMLBRIDGE_MASTER_KEY=<base64 of 32 random bytes>
SAMLBRIDGE_PUBLIC_URL=https://sso.example.test
SAMLBRIDGE_OIDC_ISSUER=https://oidc.example.test
SAMLBRIDGE_OIDC_CLIENT_ID=<client-id>
SAMLBRIDGE_OIDC_CLIENT_SECRET=<client-secret>
```

`SAMLBRIDGE_PUBLIC_URL` must be `https://` followed by the same host as `SAMLBRIDGE_HOST`. The bridge doesn't check this, so keep them in step.

Generate the master key once with `openssl rand -base64 32`, and keep a copy somewhere safe. The bridge refuses to start without it.

Start it:

```sh
docker compose up -d --build
docker compose logs -f saml-bridge caddy
```

Check the public origin once Caddy has its certificate: `curl -I https://sso.example.test/healthz` should return `200`.


## Settings

The operator passes these variables. The image has no defaults for them, and the container exits at startup with a clear message when one is missing or invalid:

- `SAMLBRIDGE_MASTER_KEY`: base64 of 32 random bytes. Secret.
- `SAMLBRIDGE_OIDC_CLIENT_SECRET`: the bridge's client secret at the OIDC provider. Secret.
- `SAMLBRIDGE_PUBLIC_URL`: the public `https` origin, with no path, query, or fragment.
- `SAMLBRIDGE_OIDC_ISSUER`: the OIDC provider's issuer URL.
- `SAMLBRIDGE_OIDC_CLIENT_ID`: the bridge's client ID at the OIDC provider.

The image sets these defaults. The compose file sets only `SAMLBRIDGE_DATABASE`, which points at the volume:

- `ASPNETCORE_URLS=http://+:8080`: the listen address.
- `ASPNETCORE_ENVIRONMENT=Production`.
- `SAMLBRIDGE_DATABASE=/data/saml-bridge.db`: the SQLite file.

## Admin

- **Database:** SQLite at `/data/saml-bridge.db`, on the named volume `saml-bridge-data`. Migrations run at startup. Apps and signing keys are stored there, so the volume holds all admin state. Back it up.
- **Secrets:** the master key and the client secret come from `.env` or a secret store. They are never part of the image.
- **Settings:** the container reads environment variables only. `appsettings*.json` files and command-line arguments are not read.
- **CLI:** the bridge's CLI is in the image, and an `admin` command on the PATH runs it. The same assembly serves the web host, and the first argument `apps` or `keys` selects the CLI. Run it inside the running container, against the same database the bridge uses:

  ```sh
  docker compose exec saml-bridge admin apps list
  docker compose exec saml-bridge admin apps add --slug payroll --metadata /data/payroll.xml
  ```

  The bridge and the CLI share one SQLite file, so run CLI commands against the volume the bridge uses. Copy metadata files into the volume first, so the CLI can read them from inside the container. See [CLI](/cli) for every command.
- **Health:** `GET /healthz` returns `200` when the process is up.

## Build

The build uses the SDK version in `global.json` (11.0.100), so the analyzers and warnings match the local build. To build the image alone:

```sh
docker build -t valkyrie-saml-bridge:local .
```
