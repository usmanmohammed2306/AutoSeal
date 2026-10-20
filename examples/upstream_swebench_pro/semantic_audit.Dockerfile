# Build with --network none. The audit is added only to a derived evaluation
# image, not to the candidate-facing image.
ARG TASK_IMAGE=jefzda/sweap-images@sha256:aa7fe7a0d2517293b6d689572867a2da18dd702cb418ffa586f758608f491ac6
FROM ${TASK_IMAGE} AS audit_base
COPY AutoSealDelegatedAuth-audit-test.tsx /app/test/utils/AutoSealDelegatedAuth-audit-test.tsx

FROM jefzda/sweap-images@sha256:aa7fe7a0d2517293b6d689572867a2da18dd702cb418ffa586f758608f491ac6 AS reviewed_gold
RUN git -C /app checkout 41dfec20bfe9b62cddbbbf621bef2e9aa9685157 -- \
    src/utils/AutoDiscoveryUtils.tsx src/utils/ValidatedServerConfig.ts

FROM audit_base AS baseline

FROM audit_base AS gold
COPY --from=reviewed_gold /app/src/utils/AutoDiscoveryUtils.tsx /app/src/utils/AutoDiscoveryUtils.tsx
COPY --from=reviewed_gold /app/src/utils/ValidatedServerConfig.ts /app/src/utils/ValidatedServerConfig.ts
