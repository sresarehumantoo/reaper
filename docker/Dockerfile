FROM node:20-alpine

# Minimal base — no extra tooling that could be leveraged post-escape
RUN apk --no-cache upgrade && \
    apk --no-cache add dumb-init

# Non-root sandbox user/group
RUN addgroup -g 1001 -S sandbox && \
    adduser  -u 1001 -S -G sandbox sandbox

WORKDIR /sandbox

# Copy monitoring shim as root, then lock permissions
COPY runner.js /sandbox/runner.js
RUN chown root:root /sandbox/runner.js && chmod 444 /sandbox/runner.js

# Drop to non-root for all subsequent layers and at runtime
USER sandbox

# Node hardening flags:
#   --max-old-space-size      cap heap at 128 MB
#   --disallow-code-generation-from-strings is intentionally NOT set here
#   because we WANT to intercept and log eval/Function before blocking them
ENTRYPOINT ["dumb-init", "--", "node", "--max-old-space-size=128", "--require", "/sandbox/runner.js"]
CMD ["/sandbox/target.js"]
