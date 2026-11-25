# mgw-sni-router

Shares the host ports 80 and 443 of a multi-gateway between modules that emulate a device vendor's cloud.

Some devices only talk to their vendor's cloud. To take such a device over, the local DNS server resolves the vendor's hostnames to the gateway, and a module answers in place of the cloud. Only one container can publish host port 80 and 443. This router publishes them and forwards each connection to the module that registered the requested hostname.

## Routing

- **Port 443**: the router reads the server name (SNI) from the TLS ClientHello and forwards the connection unchanged. TLS is not terminated. Certificates and decoding stay in the module.
- **Port 80**: the router reads the `Host` header of the first request and forwards the connection unchanged. All further requests on a keep-alive connection go to the same backend.
- A connection without a server name or `Host` header, or with a name no module registered, goes to the default backend. Without a default backend the router closes it.

The router reads at most 64 KiB and waits at most `PEEK_TIMEOUT` for the name.

## Registration

A module registers its hostnames over the API port (8080). The router does not publish this port on the host. The backend address of a route is the source address of the registration request, so the module does not need to know its own container address.

```
POST /routes
{"hosts": ["syrconnect.de", "maintenance.syrconnect.de"], "http_port": 80, "https_port": 443, "default": true}
```

| Field        | Meaning                                                                                 |
|--------------|-----------------------------------------------------------------------------------------|
| `hosts`      | Hostnames to route to this backend. Matching ignores case and a trailing dot.           |
| `http_port`  | Port of the backend for plain HTTP. `0` takes no HTTP traffic.                          |
| `https_port` | Port of the backend for TLS. `0` takes no TLS traffic.                                  |
| `default`    | Take connections without a known name. Only one backend can hold this.                  |

Responses:

- `200` with the stored route.
- `400` for an invalid body.
- `409` if another backend that still accepts connections holds one of the hosts or the default role.

A route expires after `ROUTE_TTL` (default 90 s). A module renews it by sending the same request again, well within the TTL. A second registration from the same address replaces the first. A module recreated with a new address takes over at once: on a conflict the router connects to the holder's ports, and replaces its route if none answers. A removed module drops out when its route expires.

`GET /routes` lists the current routes. `GET /health` answers `200`.

The registration API has no authentication. Every container on the module network can register hostnames.

## Usage in a module

Depend on the router module and pass its address to the service that registers:

```yaml
dependencies:
  github.com/SENERGY-Platform/mgw-sni-router-module:
    version: <v2.0.0
    requiredServices:
      router:
        - refVar: SNI_ROUTER_URL
          template: "http://{ref}:8080"
          services:
            - my-service
```

## Configuration

Environment variables, or a JSON file passed with `-config`:

| Variable        | Default | Meaning                                         |
|-----------------|---------|-------------------------------------------------|
| `HTTP_PORT`     | `80`    | Listen port for plain HTTP.                     |
| `HTTPS_PORT`    | `443`   | Listen port for TLS.                            |
| `API_PORT`      | `8080`  | Listen port for the registration API.           |
| `ROUTE_TTL`     | `90s`   | Lifetime of a registration.                     |
| `PEEK_TIMEOUT`  | `10s`   | Maximum wait for the server name or Host header.|
| `DIAL_TIMEOUT`  | `5s`    | Timeout for connecting to a backend.            |
| `LOGGER_LEVEL`  | `info`  | `debug` logs every forwarded connection.        |
