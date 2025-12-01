WASM_CORE ?= --manifest-path wasm_core/Cargo.toml
DEPS = prettier stylelint stylelint-config-standard htmlhint eslint @eslint/js eslint-config-prettier

.PHONY: all build fmt lint test serve clean frontend-fmt frontend-lint test-all

all: frontend-lint build serve

fmt:
	cargo fmt $(WASM_CORE)

lint: fmt
	cargo clippy $(WASM_CORE) -- -D warnings

test:
	cargo test $(WASM_CORE) --all
	@command -v wasm-pack >/dev/null || (cargo install wasm-pack)
	wasm-pack test --chrome --headless wasm_core

test-all: lint frontend-lint test

frontend-fmt:
	@npm ls $(DEPS) --depth=0 --silent >/dev/null 2>&1 || npm i -D $(DEPS)
	npx prettier --config www/prettier.json "www/**/*.{json,cjs,js,jsx,ts,tsx,css,scss,html}" --write

frontend-lint: frontend-fmt
	npx htmlhint --config www/htmlhint.json "www/*.html"
	npx stylelint --config www/stylelint.config.cjs "www/**/*.{css,scss,sass,less}" --fix
	npx eslint --config www/eslint.config.cjs --fix

build: lint test
	wasm-pack build wasm_core --target web --out-dir ../www/pkg

serve:
	npx serve www

clean:
	cargo clean $(WASM_CORE)
	rm -rf www/pkg