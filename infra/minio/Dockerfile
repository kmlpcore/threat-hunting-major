# MinIO no longer publishes images on Docker Hub/Quay. Chainguard's builds are
# shell-less, so the bucket-init job gets Chainguard's `mc` on top of Wolfi base
# (same glibc, has a shell).
ARG MC_IMAGE=cgr.dev/chainguard/minio-client:latest
FROM ${MC_IMAGE} AS mc

FROM cgr.dev/chainguard/wolfi-base:latest
COPY --from=mc /usr/bin/mc /usr/bin/mc
COPY init.sh /init.sh
ENTRYPOINT ["/bin/sh", "/init.sh"]
