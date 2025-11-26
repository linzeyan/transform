WASM_CORE ?= --manifest-path wasm_core/Cargo.toml

.PHONY: all build fmt lint test serve clean

all: build serve

fmt:
	cargo fmt $(WASM_CORE)

lint:
	cargo clippy $(WASM_CORE) -- -D warnings

test:
	cargo test $(WASM_CORE) --all

e2e:
# fmt
	npx prettier "www/*.{js,jsx,ts,tsx,css,scss,html}" --write
# lint
	npx htmlhint "www/*.html"
	npx stylelint "www/*.{css,scss,sass,less}" --fix
	npx eslint -c www/eslint.config.cjs www/main.js --fix

	cargo build $(WASM_CORE) --tests --target wasm32-unknown-unknown
	wasm-pack test --chrome --headless wasm_core

build: fmt lint test
	@command -v wasm-pack >/dev/null || (cargo install wasm-pack)
	cd wasm_core && \
	wasm-pack build --target web --out-dir ../www/pkg

serve: e2e
	cd www && npx --yes serve

clean:
	cargo clean $(WASM_CORE)
	rm -rf www/pkg