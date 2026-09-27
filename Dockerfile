# reaper static analyzer: the full CLI (scan, --triage, --iocs, --rewrite,
# --reachability) without a local Node install. This is not the dynamic
# sandbox in docker/, which runs a sample under the monitoring shim.
#
#   make image
#   docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#     --cap-drop ALL --security-opt no-new-privileges \
#     -v "$PWD:/work:ro" reaper suspicious.html --triage
#
# Base pinned to the same digest as docker/Dockerfile; bump both together.

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist

# The string-array decoder and eval capture spawn isolated workers from
# dist/analyzers/*.cjs; fail the build if the copy step ever regresses.
RUN ls dist/analyzers/stringarray-worker.cjs dist/analyzers/evalscope-worker.cjs

USER node
ENV HOME=/tmp NODE_ENV=production
HEALTHCHECK NONE
WORKDIR /work
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]
