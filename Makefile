WASM_CORE ?= --manifest-path wasm_core/Cargo.toml
DEPS = prettier stylelint stylelint-config-standard htmlhint eslint @eslint/js eslint-config-prettier

# zstd (parquet, arrow-ipc and arrow-avro codecs) is C. Apple clang emits no
# wasm32 objects, so the link fails on missing ZSTD_* symbols; use Homebrew LLVM.
LLVM_BIN ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin))
ifneq ($(LLVM_BIN),)
export CC_wasm32_unknown_unknown := $(LLVM_BIN)/clang
export AR_wasm32_unknown_unknown := $(LLVM_BIN)/llvm-ar
endif

.PHONY: all build fmt lint test serve clean frontend-fmt frontend-lint test-all wasm-cc

all: frontend-lint build serve

fmt:
	cargo fmt $(WASM_CORE)

lint: fmt
	cargo clippy $(WASM_CORE) -- -D warnings

wasm-cc:
	@[ "$$(uname)" != Darwin ] || [ -n "$(LLVM_BIN)" ] || \
		{ echo "wasm32 needs LLVM's clang for zstd: brew install llvm"; exit 1; }

test: wasm-cc
	cargo test $(WASM_CORE) --all -- --quiet
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