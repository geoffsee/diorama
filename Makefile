# Workspace build, verification, and container image targets.

CARGO_BIN_DIR := $(or $(CARGO_HOME),$(HOME)/.cargo)/bin
export PATH := $(CARGO_BIN_DIR):$(PATH)

CONTAINER_ENGINE ?= podman
IMAGE ?= localhost/diorama:latest
CONTAINER_NAME ?= diorama
CONTAINER_VOLUME ?= diorama-data
KUBECONFIG_OUT ?= kubeconfig.yaml
IGNOREFILE_FLAG := $(if $(findstring podman,$(CONTAINER_ENGINE)),--ignorefile container/.dockerignore,)
MODULES_MOUNT := $(if $(wildcard /lib/modules),-v /lib/modules:/lib/modules:ro,)

.PHONY: help build fmt fmt-check lint test test-doc policy deny check \
	image dev-image image-source container-run container-stop kubeconfig \
	conformance clean

help:
	@printf '%s\n' \
		"Usage: make <target>" \
		"" \
		"Workspace targets:" \
		"  build          Build diorama and dioramactl" \
		"  fmt            Format all workspace Rust sources" \
		"  fmt-check      Check formatting without modifying files" \
		"  lint           Run workspace Clippy lints" \
		"  test           Run nextest CI suite" \
		"  test-doc       Run workspace documentation tests" \
		"  policy         Run repository language policy check" \
		"  deny           Run cargo-deny advisories, bans, licenses, and sources checks" \
		"  check          Run all pre-push verification gates" \
		"  clean          Remove build and dist artifacts" \
		"" \
		"Container targets:" \
		"  image          Build runtime image from incremental host musl binary (container/dev-image.sh)" \
		"  image-source   Compile diorama inside container and build runtime image (container/Dockerfile.source)" \
		"  container-run  Start privileged diorama container in the background" \
		"  container-stop Stop and remove the running diorama container" \
		"  kubeconfig     Write $(KUBECONFIG_OUT) from the running container" \
		"  conformance    Run ignored conformance probe suite against $(IMAGE)"

build:
	CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm cargo build --locked -p diorama -p dioramactl

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt-check

lint:
	cargo lint

test:
	CI=1 NEXTEST_SHOW_PROGRESS=none NEXTEST_HIDE_PROGRESS_BAR=1 NEXTEST_NO_INPUT_HANDLER=1 cargo test-ci

test-doc:
	cargo test --locked --workspace --doc --all-features

policy:
	cargo run --locked -p diorama-dev --bin diorama-language-policy

deny:
	cargo deny check

check: fmt-check lint test test-doc policy deny

image dev-image:
	CONTAINER_ENGINE=$(CONTAINER_ENGINE) IMAGE=$(IMAGE) ./container/dev-image.sh

image-source:
	$(CONTAINER_ENGINE) build $(IGNOREFILE_FLAG) -f container/Dockerfile.source -t $(IMAGE) .

container-run:
	$(CONTAINER_ENGINE) run -d --privileged \
		--hostname diorama \
		--security-opt seccomp=unconfined \
		--tmpfs /tmp --tmpfs /run \
		$(MODULES_MOUNT) \
		-v $(CONTAINER_VOLUME):/var/lib/diorama \
		-p 6443:6443 \
		--name $(CONTAINER_NAME) \
		$(IMAGE)

container-stop:
	-$(CONTAINER_ENGINE) stop $(CONTAINER_NAME)
	-$(CONTAINER_ENGINE) rm $(CONTAINER_NAME)

kubeconfig:
	$(CONTAINER_ENGINE) exec $(CONTAINER_NAME) cat /var/lib/diorama/pki/admin.kubeconfig \
		| sed 's#https://[^:]*:6443#https://127.0.0.1:6443#g' > $(KUBECONFIG_OUT)

conformance:
	DIORAMA_IMAGE=$(IMAGE) cargo test --locked -p diorama-conformance --test suite client_gaps::client_gaps -- --ignored --nocapture

clean:
	cargo clean
	rm -rf dist
