# Linear Agent plugin

The Fleet image bundles a generic, disabled-by-default Linear Agent Session worker. It does not contain routes, profile names, workspace names, OAuth bindings, requester allowlists, or webhook secrets.

A deployment that enables the plugin must provide its policy as a read-only data mount at:

```text
/opt/hermes/plugins/linear-agent/linear-agents.json
```

The policy file is deliberately absent from the image. Enabling the plugin without the mount fails closed before OAuth or inbox processing. The runtime accepts only a bounded regular file opened with no symlink following. It must be owned by root or the runtime UID, must not be group/world writable, and when runtime-owned must not be owner-writable. A root-owned `0644` bind mount is therefore readable but not writable by the UID 1000 worker.

The policy entry and profile-local plugin settings must agree exactly on:

- profile and logical agent;
- Linear workspace;
- managed OAuth vault and item binding identifiers;
- profile-local OAuth and Connect paths;
- rollout scope;
- optional requester UUID allowlist.

The protected profile Connect environment must contain `OP_CONNECT_HOST`, `OP_CONNECT_TOKEN`, and `OP_CONNECT_ALLOWED_HOSTS`. The allowlist is a comma-separated set of exact HTTP(S) origins; the configured host must be one of them. This keeps deployment endpoints outside public executable code while retaining fail-closed host approval.

Executable worker code must not be bind-mounted. Code is supplied by the attested Fleet image; deployment repositories supply policy, provisioning and canary operations, and secrets. The image does not ship deployment provisioning or live-canary modules because those encode the operator's container and filesystem topology. See `examples/linear-agent-policy.json` for a synthetic policy shape.
