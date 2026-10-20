# This reviewed public task image is pinned to a manifest, not a floating tag.
FROM jefzda/sweap-images@sha256:aa7fe7a0d2517293b6d689572867a2da18dd702cb418ffa586f758608f491ac6

USER root

# The build runs without network access. Only the task HEAD is fetched into a
# new shallow object database. The original Git database is removed inside the
# derived image's layer before any candidate is allowed to run in this image.
RUN set -eu; \
    test "$(git -C /app rev-parse HEAD)" = d5d1ec775caf2d3c9132122c1243898e99fdb2da; \
    test "$(git -C /app rev-parse HEAD^{tree})" = 17ec485712222c12d9d849069d58d27bad9278e3; \
    test -z "$(git -C /app status --porcelain)"; \
    git init -q /tmp/autoseal-shallow; \
    git -C /tmp/autoseal-shallow fetch -q --no-tags --depth=1 file:///app HEAD; \
    git -C /tmp/autoseal-shallow update-ref refs/heads/task FETCH_HEAD; \
    git -C /tmp/autoseal-shallow symbolic-ref HEAD refs/heads/task; \
    test "$(git -C /tmp/autoseal-shallow rev-parse HEAD)" = d5d1ec775caf2d3c9132122c1243898e99fdb2da; \
    if git -C /tmp/autoseal-shallow cat-file -e 41dfec20bfe9b62cddbbbf621bef2e9aa9685157 2>/dev/null; then exit 9; fi; \
    rm -rf /app/.git; \
    cp -a /tmp/autoseal-shallow/.git /app/.git; \
    rm -rf /tmp/autoseal-shallow; \
    git -C /app reset -q --mixed HEAD; \
    test -z "$(git -C /app status --porcelain)"; \
    test "$(git -C /app rev-list --all --count)" = 1; \
    if git -C /app cat-file -e 41dfec20bfe9b62cddbbbf621bef2e9aa9685157 2>/dev/null; then exit 10; fi
