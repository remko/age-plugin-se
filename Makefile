PREFIX ?= /usr/local
AGE ?= age

ifeq ($(RELEASE),1)
SWIFT_BUILD_FLAGS=-c release --disable-sandbox
endif

ifeq ($(COVERAGE),1)
SWIFT_TEST_FLAGS=--enable-code-coverage
endif
# E.g. Tests.RecipientV1Tests/testRecipient
ifneq ($(TEST_FILTER),)
SWIFT_TEST_FLAGS := $(SWIFT_TEST_FLAGS) --filter $(TEST_FILTER)
endif

VERSION ?= $(shell cat Sources/CLI.swift | grep '^let version' | sed -e "s/.*\"v\\(.*\\)\".*/\\1/")
BUILD_DIR = $(shell swift build $(SWIFT_BUILD_FLAGS) --show-bin-path)

.PHONY: all
all:
	swift build $(SWIFT_BUILD_FLAGS)

.PHONY: package
package:
	swift build -c release --triple arm64-apple-macosx
	swift build -c release --triple x86_64-apple-macosx
	lipo -create -output .build/age-plugin-applese .build/arm64-apple-macosx/release/age-plugin-applese .build/x86_64-apple-macosx/release/age-plugin-applese
	cd .build && ditto -c -k age-plugin-applese age-plugin-applese-v$(VERSION)-macos.zip

.PHONY: test
test:
	swift test $(SWIFT_TEST_FLAGS)
ifeq ($(COVERAGE),1)
	coverage_total=`cat $$(swift test --show-codecov-path) | jq '.data[0].totals.lines.percent' | xargs printf "%.0f%%"` && (cat Documentation/img/coverage.svg | sed -e "s/{COVERAGE}/$$coverage_total/" > .build/coverage.svg)
	(command -v llvm-coverage-viewer > /dev/null) && llvm-coverage-viewer --json $$(swift test --show-codecov-path) --output .build/coverage.html
	@cat $$(swift test --show-codecov-path) | jq '.data[0].totals.lines.percent' | xargs printf "Test coverage (lines): %.2f%%\\n"
	@cat $$(swift test --show-codecov-path) | jq -r '.data[0].files[] | "\(.filename)\t\(.summary.lines.percent)\t\(.summary.lines.covered)\t\(.summary.lines.count)"' | grep -v "Tests.swift" | sed -r -e 's/.*\/(Sources\/|Tests\/)/\1/' | xargs printf "  %s: %.2f %% (%d/%d)\\n"
endif

.PHONY: lint
lint:
	swift-format lint --recursive --strict .
	
.PHONY: install
install:
	install -d $(PREFIX)/bin
	install $(BUILD_DIR)/age-plugin-applese $(PREFIX)/bin

.PHONY: smoke-test
smoke-test:
	PATH="$(BUILD_DIR):$$PATH" && \
	recipient=`age-plugin-applese keygen --access-control=any-biometry-or-passcode -o key.txt | sed -e "s/Public key: //"` && \
	$(AGE) --encrypt --recipient $$recipient -o README.md.age README.md && \
	$(AGE) --decrypt -i key.txt README.md.age && \
	rm -f key.txt README.md.age

.PHONY: smoke-test-noninteractive
smoke-test-noninteractive:
	PATH="$(BUILD_DIR):$$PATH" && \
	recipient=`age-plugin-applese keygen --access-control=none -o key.txt | sed -e "s/Public key: //"` && \
	$(AGE) --encrypt --recipient $$recipient -o README.md.age README.md && \
	$(AGE) --decrypt -i key.txt README.md.age && \
	rm -f key.txt README.md.age

.PHONY: smoke-test-encrypt
smoke-test-encrypt:
	PATH="$(BUILD_DIR):$$PATH" && \
	$(AGE) --encrypt --recipient age1applese1qvxkey2trcz70ds5knnrlrx6q59xjedrd65mdmc4zel53ppfdxmjqyg4qzv -o README.md.age README.md

.PHONY: gen-manual-tests
gen-manual-tests:
	-rm -rf gen-manual-tests
	mkdir -p manual-tests
	PATH="$(BUILD_DIR):$$PATH" && set -e && \
	for control in none passcode current-biometry any-biometry current-biometry-and-passcode any-biometry-and-passcode any-biometry-or-passcode; do \
		recipient=`age-plugin-applese keygen --access-control=$$control -o manual-tests/key.$$control.txt | sed -e "s/Public key: //"`;\
		$(AGE) --encrypt --recipient $$recipient -o manual-tests/README.md.$$control.age README.md; \
	done

.PHONY: run-manual-tests
run-manual-tests:
	PATH="$(BUILD_DIR):$$PATH" && set -e && \
	for control in none passcode any-biometry current-biometry-and-passcode any-biometry-and-passcode any-biometry-or-passcode; do \
		echo "Decrypting $$control"; \
		$(AGE) --decrypt -i manual-tests/key.$$control.txt manual-tests/README.md.$$control.age; \
		echo -e "\n-----\n"; \
	done

.PHONY: clean
clean:
	-rm -rf .build manual-tests
