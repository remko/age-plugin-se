ifeq ($(RELEASE),1)
SWIFT_BUILD_FLAGS=-c release
BUILD_DIR=$(PWD)/.build/apple/Products/Release
else
BUILD_DIR=$(PWD)/.build/debug
endif
PREFIX ?= /usr/local

ifeq ($(COVERAGE),1)
SWIFT_TEST_FLAGS=--enable-code-coverage
endif

.PHONY: all
all:
	swift build $(SWIFT_BUILD_FLAGS)

.PHONY: package
package:
	swift build -c release --triple arm64-apple-macosx
	swift build -c release --triple x86_64-apple-macosx
	lipo -create -output .build/age-plugin-applese .build/arm64-apple-macosx/release/age-plugin-applese .build/x86_64-apple-macosx/release/age-plugin-applese

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
		recipient=`age-plugin-applese keygen --access-control=biometry-or-passcode -o key.txt | sed -e "s/Public key: //"` && \
		age --encrypt --recipient $$recipient -o README.md.age README.md  && \
		age --decrypt -i key.txt README.md.age && \
		rm -f key.txt README.md.age

