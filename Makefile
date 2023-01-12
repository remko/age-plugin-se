ifeq ($(RELEASE),1)
SWIFT_BUILD_FLAGS=-c release
BUILD_DIR=$(PWD)/.build/release
else
BUILD_DIR=$(PWD)/.build/debug
endif
PREFIX ?= /usr/local

ifeq ($(COVERAGE),1)
SWIFT_TEST_FLAGS=--enable-code-coverage
endif

VERSION ?= $(shell cat Sources/AgeAppleSEPlugin/Version.swift | grep VERSION | sed -e "s/.*\"v\\(.*\\)\".*/\\1/")

ifeq (, $(shell which gtar))
TAR := tar
else
# bsd-tar corrupts files on GitHub: https://github.com/actions/virtual-environments/issues/2619
TAR := gtar
endif

.PHONY: all
all:
	swift build $(SWIFT_BUILD_FLAGS)

.PHONY: package
package:
	swift build -c release --triple arm64-apple-macosx
	swift build -c release --triple x86_64-apple-macosx
	lipo -create -output .build/age-plugin-applese .build/arm64-apple-macosx/release/age-plugin-applese .build/x86_64-apple-macosx/release/age-plugin-applese
	$(TAR) czf .build/age-plugin-applese-v$(VERSION).tgz .build/age-plugin-applese

.PHONY: test
test:
	swift test
ifeq ($(COVERAGE),1)
	echo "codecov file: $$(swift test --show-codecov-path)"
endif

.PHONY: install
install:
	install -d $(PREFIX)/bin
	install $(BUILD_DIR)/age-plugin-applese $(PREFIX)/bin

.PHONY: smoke-test
smoke-test:
	PATH="$(BUILD_DIR):$$PATH" && \
		recipient=`age-plugin-applese keygen --access-control=any-biometry-or-passcode -o key.txt | sed -e "s/Public key: //"` && \
		age --encrypt --recipient $$recipient -o README.md.age README.md  && \
		age --decrypt -i key.txt README.md.age && \
		rm -f key.txt README.md.age

.PHONY: gen-manual-tests
gen-manual-tests:
	-rm -rf gen-manual-tests
	mkdir -p manual-tests
	PATH="$(BUILD_DIR):$$PATH" && set -e && \
	for control in none passcode current-biometry any-biometry current-biometry-and-passcode any-biometry-and-passcode any-biometry-or-passcode; do \
		recipient=`age-plugin-applese keygen --access-control=$$control -o manual-tests/key.$$control.txt | sed -e "s/Public key: //"`;\
		age --encrypt --recipient $$recipient -o manual-tests/README.md.$$control.age README.md; \
	done

.PHONY: run-manual-tests
run-manual-tests:
	PATH="$(BUILD_DIR):$$PATH" && set -e && \
	for control in none passcode any-biometry current-biometry-and-passcode any-biometry-and-passcode any-biometry-or-passcode; do \
		echo "Decrypting $$control"; \
		age --decrypt -i manual-tests/key.$$control.txt manual-tests/README.md.$$control.age; \
		echo -e "\n-----\n"; \
	done

.PHONY: clean
clean:
	-rm -rf .build