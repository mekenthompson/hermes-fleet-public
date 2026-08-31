ARG AGENT_IMAGE
ARG ONEPASSWORD_CLI_IMAGE=docker.io/1password/op@sha256:d7d12b409ec699c9fa139d3bdfc80671f744380d39db8c539d9dc6e7e553d3c1
FROM ${ONEPASSWORD_CLI_IMAGE} AS onepassword_cli
FROM ${AGENT_IMAGE}

ARG AGENT_IMAGE
ARG ONEPASSWORD_CLI_IMAGE
ARG FLEET_GIT_SHA=development
ARG FLEET_IMAGE_IDENTITY=local/hermes-fleet
ENV HERMES_FLEET_GIT_SHA=${FLEET_GIT_SHA} \
    HERMES_FLEET_IMAGE_IDENTITY=${FLEET_IMAGE_IDENTITY} \
    HERMES_FLEET_AGENT_IMAGE=${AGENT_IMAGE} \
    HERMES_FLEET_ONEPASSWORD_CLI_IMAGE=${ONEPASSWORD_CLI_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/mekenthompson/hermes-fleet-public" \
      org.opencontainers.image.revision="${FLEET_GIT_SHA}" \
      org.opencontainers.image.base.name="${AGENT_IMAGE}"

COPY --from=onepassword_cli --chmod=0755 /usr/local/bin/op /usr/local/bin/op
RUN test "$(/usr/local/bin/op --version)" = "2.39.0"
COPY scripts/image_ref.py /opt/hermes-fleet/bin/image_ref.py
COPY --chmod=0755 scripts/verify-agent-image-ref.py /opt/hermes-fleet/bin/verify-agent-image-ref
COPY contracts/ /opt/hermes-fleet/contracts/
RUN python3 -c 'import json, os, pathlib; marker = pathlib.Path("/etc/hermes-fleet/image-provenance.json"); marker.parent.mkdir(parents=True, exist_ok=True); marker.write_text(json.dumps({"schema": 1, "deployment_kind": "fleet_child_image", "image": os.environ["HERMES_FLEET_IMAGE_IDENTITY"], "revision": os.environ["HERMES_FLEET_GIT_SHA"], "parent_agent_image": os.environ["HERMES_FLEET_AGENT_IMAGE"], "onepassword_cli_image": os.environ["HERMES_FLEET_ONEPASSWORD_CLI_IMAGE"]}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"); marker.chmod(0o444)'
