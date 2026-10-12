FROM golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd AS build
WORKDIR /src
RUN curl --fail --location --retry 3 --output /tmp/source.tar.gz https://codeload.github.com/portainer/kubesolo/tar.gz/2ef1c4787989f11f868f81bb84ae2afd4a49a81d \
    && echo '9d5f3ce1f3fbda971fb1e2fb6da18ae3880caeec677f0e5d928a3bbe7bb76aec  /tmp/source.tar.gz' | sha256sum --check \
    && tar --extract --gzip --file /tmp/source.tar.gz --strip-components=1
ENV CGO_ENABLED=1 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
COPY scalar_capture_test.go /src/internal/config/diorama_scalar_review_test.go
RUN mkdir /out && go test -c -p 2 -tags external_deps -trimpath -o /out/scalar.test ./internal/config
FROM build AS capture
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT []
