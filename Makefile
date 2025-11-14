WASM_CORE ?= --manifest-path wasm_core/Cargo.toml

.PHONY: all build fmt lint test serve clean

all: build serve

fmt:
	cargo fmt $(WASM_CORE)

lint:
	cargo clippy $(WASM_CORE) -- -D warnings

test:
	cargo test $(WASM_CORE) --all

build: fmt lint test
	@command -v wasm-pack >/dev/null || (cargo install wasm-pack)
	cd wasm_core && \
	wasm-pack build --target web --out-dir ../www/pkg

serve:
	cd www && npx --yes serve

clean:
	cargo clean $(WASM_CORE)
	rm -rf www/pkg