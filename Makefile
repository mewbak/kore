include include.mk

jenkins: STACK_OPTS += --test --bench --coverage
export STACK_OPTS

.PHONY: all clean docs haddock jenkins kore k-frontend stylish \
        test test-kore test-k

kore:
	stack build $(STACK_BUILD_OPTS)

k-frontend:
	mkdir -p $(BUILD_DIR)
	rm -rf $(K_DIR) $(K_NIGHTLY)
	wget --output-document $(K_NIGHTLY) \
	    $$(curl 'https://api.github.com/repos/kframework/k/releases' | jq --raw-output '.[0].assets[0].browser_download_url')
	mkdir --parents $(K_DIR)
	tar --extract --verbose --file $(K_NIGHTLY) --strip-components 1 --directory $(K_DIR)

docs: haddock

haddock:
	stack haddock --no-haddock-deps $(STACK_HADDOCK_OPTS)
	if [ -n "$$BUILD_NUMBER" ]; then \
		cp -r $$(stack path --local-doc-root) haskell_documentation; \
	fi

all: kore k-frontend

test: test-kore test-k

test-kore:
	stack test $(STACK_TEST_OPTS)
	if [ -n "$$BUILD_NUMBER" ]; then \
		cp -r $$(stack path --local-hpc-root) coverage_report; \
	fi

test-k:
	$(MAKE) -C src/main/k/working test-k

jenkins: clean check all test docs

clean:
	stack clean
	find . -name '*.tix' -exec rm -f '{}' \;
	$(MAKE) -C src/main/k/working clean
	rm -rf $(BUILD_DIR)

check:
	if ! ./scripts/git-assert-clean.sh; \
	then \
		echo >&2 "Please commit your changes!"; \
		exit 1; \
	fi
	if ! ./scripts/git-rebased-on.sh "$$(git rev-parse $(UPSTREAM_BRANCH))" --linear; \
	then \
		echo >&2 "Please rebase your branch onto ‘master’!"; \
		exit 1; \
	fi
	$(MAKE) stylish
	if ! ./scripts/git-assert-clean.sh; \
	then \
		echo >&2 "Please run ‘make stylish’ to fix style errors!"; \
		exit 1; \
	fi

stylish:
	if ! command -v stylish-haskell; then\
		stack install stylish-haskell; \
	fi
	find $(HS_SOURCE_DIRS) \
		\( -name '*.hs' -o -name '*.hs-boot' \) \
		-print0 | xargs -0L1 stylish-haskell -i
