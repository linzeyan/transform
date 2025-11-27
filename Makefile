WASM_CORE ?= --manifest-path wasm_core/Cargo.toml
DEPS = prettier stylelint stylelint-config-standard htmlhint eslint @eslint/js eslint-config-prettier

.PHONY: all build fmt lint test serve clean e2e frontend-fmt frontend-lint

all: build serve

fmt:
	cargo fmt $(WASM_CORE)

lint:
	cargo clippy $(WASM_CORE) -- -D warnings

test:
	cargo test $(WASM_CORE) --all
	wasm-pack test --chrome --headless wasm_core

frontend-fmt:
	@npm ls $(DEPS) --depth=0 --silent >/dev/null 2>&1 || npm i -D $(DEPS)
	npx prettier "www/*.{js,jsx,ts,tsx,css,scss,html}" --write

frontend-lint: frontend-fmt
	npx htmlhint "www/*.html"
	npx stylelint "www/*.{css,scss,sass,less}" --fix
	npx eslint -c www/eslint.config.cjs www/main.js --fix

build: fmt lint test
	@command -v wasm-pack >/dev/null || (cargo install wasm-pack)
	cd wasm_core && \
	wasm-pack build --target web --out-dir ../www/pkg

serve:
	cd www && npx --yes serve

clean:
	cargo clean $(WASM_CORE)
	rm -rf www/pkg