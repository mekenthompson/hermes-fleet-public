ARG AGENT_IMAGE
FROM ${AGENT_IMAGE}

ARG AGENT_IMAGE
ARG FLEET_GIT_SHA=development
ARG FLEET_IMAGE_IDENTITY=local/hermes-fleet
ENV HERMES_FLEET_GIT_SHA=${FLEET_GIT_SHA} \
    HERMES_FLEET_IMAGE_IDENTITY=${FLEET_IMAGE_IDENTITY} \
    HERMES_FLEET_AGENT_IMAGE=${AGENT_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/mekenthompson/hermes-fleet-public" \
      org.opencontainers.image.revision="${FLEET_GIT_SHA}" \
      org.opencontainers.image.base.name="${AGENT_IMAGE}"

COPY scripts/image_ref.py /opt/hermes-fleet/bin/image_ref.py
COPY --chmod=0755 scripts/verify-agent-image-ref.py /opt/hermes-fleet/bin/verify-agent-image-ref
COPY contracts/ /opt/hermes-fleet/contracts/
RUN python3 -c 'import json, os, pathlib; marker = pathlib.Path("/etc/hermes-fleet/image-provenance.json"); marker.parent.mkdir(parents=True, exist_ok=True); marker.write_text(json.dumps({"schema": 1, "deployment_kind": "fleet_child_image", "image": os.environ["HERMES_FLEET_IMAGE_IDENTITY"], "revision": os.environ["HERMES_FLEET_GIT_SHA"], "parent_agent_image": os.environ["HERMES_FLEET_AGENT_IMAGE"]}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"); marker.chmod(0o444)'
