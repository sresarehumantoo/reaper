# Pinned to a specific digest so `docker build` is reproducible and can't
# silently inherit a base-image change. Bump this with intent.
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

# Non-root sandbox user/group
RUN addgroup -g 1001 -S sandbox && \
    adduser  -u 1001 -S -G sandbox sandbox

WORKDIR /sandbox

# Copy monitoring shim as root, then lock permissions
COPY runner.js /sandbox/runner.js
RUN chown root:root /sandbox/runner.js && chmod 444 /sandbox/runner.js

# Drop to non-root for all subsequent layers and at runtime
USER sandbox

# HOME → /tmp because the root FS is read-only at runtime; Node otherwise
# tries ~/.npm and friends and produces noisy ENOENT/EROFS errors that
# obscure real findings.
ENV HOME=/tmp

# Disable any inherited image healthcheck — irrelevant for one-shot runs
# and an avoidable extra surface.
HEALTHCHECK NONE

# Node hardening flags:
#   --max-old-space-size       cap heap at 128 MB
#   --frozen-intrinsics         freeze built-in prototypes; partial defense
#                               against prototype-pollution sandbox escapes
#   --disallow-code-generation-from-strings is intentionally NOT set here
#                               because we WANT to intercept and log
#                               eval/Function before blocking them
ENTRYPOINT ["node", "--max-old-space-size=128", "--frozen-intrinsics", "--require", "/sandbox/runner.js"]
CMD ["/sandbox/target.js"]
