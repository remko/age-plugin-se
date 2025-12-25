PREFIX ?= /usr/local
AGE ?= age
SCDOC=$(shell command -v scdoc)

export SOURCE_DATE_EPOCH=1766687436

ifneq ($(V),1)
AT=@
endif

ifeq ($(RELEASE),1)
SWIFT_BUILD_FLAGS=-c release --disable-sandbox $(SWIFT_EXTRA_BUILD_FLAGS)
endif

SWIFT_TEST_FLAGS := --parallel
ifeq ($(COVERAGE),1)
SWIFT_TEST_FLAGS := $(SWIFT_TEST_FLAGS) --enable-code-coverage
endif
# E.g. Tests.RecipientV1Tests/testRecipient
ifneq ($(TEST_FILTER),)
SWIFT_TEST_FLAGS := $(SWIFT_TEST_FLAGS) --filter $(TEST_FILTER)
endif

ifeq ($(OS),Windows_NT)
UNAME_S=Windows
else
UNAME_S=$(shell uname -s)
endif

VERSION ?= $(shell cat Sources/CLI.swift | grep '^let version' | sed -e "s/.*\"v\\(.*\\)\".*/\\1/")
BUILD_DIR ?= $(shell swift build $(SWIFT_BUILD_FLAGS) --show-bin-path)
COMMIT_SHA=$(shell git rev-parse HEAD)
PACKAGE_ARCHS = arm64-apple-macosx x86_64-apple-macosx
PACKAGE_LINUX_ARCHS = aarch64 x86_64
APK_PACKAGE_VERSION=r0

ECHO = echo
ifneq ($(UNAME_S),Darwin)
ECHO = /usr/bin/echo -e
endif

ifneq ($(SCDOC),)
MAN_TARGET := man
endif

.PHONY: all
all: $(BUILD_DIR)/age-plugin-tag $(BUILD_DIR)/age-plugin-tagpq $(MAN_TARGET)
	swift build $(SWIFT_BUILD_FLAGS)

.PHONY: package
ifeq ($(UNAME_S),Darwin)
package:
	for arch in $(PACKAGE_ARCHS); do swift build -c release --triple $$arch; done
	lipo -create -output .build/age-plugin-se $(foreach arch, $(PACKAGE_ARCHS), \
		$(shell swift build -c release --triple $(arch) --show-bin-path)/age-plugin-se)
	cd .build && ditto -c -k age-plugin-se age-plugin-se-v$(VERSION)-macos.zip
package-linux:
	set -e; for arch in $(PACKAGE_LINUX_ARCHS); do \
		package=age-plugin-se-v$(VERSION)-$$arch-linux; \
		make RELEASE=1 PREFIX=/usr DESTDIR=.build/$$package SWIFT_EXTRA_BUILD_FLAGS="--swift-sdk $$arch-swift-linux-musl" all install; \
		tar czf .build/$$package.tgz -C .build $$package; \
		go run Scripts/alpine/dir2apk.go --arch=$$arch --version=$(VERSION)-$(APK_PACKAGE_VERSION) --commit=$(COMMIT_SHA) --key=Scripts/alpine/r@mko.re-66596f64.rsa --out=.build .build/$$package; \
	done
else
package:
	swift build -c release --static-swift-stdlib
	tar czf .build/age-plugin-se-v$(VERSION)-$(shell uname -m)-linux.tgz -C $(shell swift build -c release --show-bin-path) age-plugin-se
endif

.PHONY: test
test:
	swift test $(SWIFT_TEST_FLAGS)
ifeq ($(COVERAGE),1)
	swift ./Scripts/ProcessCoverage.swift $$(swift test --show-codecov-path) .build/coverage.json .build/coverage.html .build/coverage.svg
endif


.PHONY: test-loop
test-loop: test
	reflex -r '\.swift$$' $(MAKE) test


# Need to explicitly list source dirs instead of `.`, because swift-format doesn't ignore
# hidden dirs. Should be fixed 'soon'? (https://github.com/apple/swift-format/pull/644)
.PHONY: lint
lint:
	swift-format lint --recursive --strict Package.swift Sources Scripts Tests
	
.PHONY: install 
install: install-doc
	install -d $(DESTDIR)$(PREFIX)/bin
	install $(BUILD_DIR)/age-plugin-se $(DESTDIR)$(PREFIX)/bin

.PHONY: install-doc
install-doc:
	install -d $(DESTDIR)$(PREFIX)/share/licenses/age-plugin-se
	install LICENSE.txt $(DESTDIR)$(PREFIX)/share/licenses/age-plugin-se
ifneq ($(SCDOC),)
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install .build/age-plugin-se.1 $(DESTDIR)$(PREFIX)/share/man/man1
endif

.IGNORE: .build/age-plugin-se.1
man: .build/age-plugin-se.1

.build/age-plugin-se.1: Documentation/age-plugin-se.1.scd
	mkdir -p .build
	cat $< | sed "s/@VERSION@/$(VERSION)/g" | $(SCDOC) > $@.tmp
	mv $@.tmp $@

$(BUILD_DIR)/age-plugin-tag $(BUILD_DIR)/age-plugin-tagpq:
	mkdir -p $(BUILD_DIR)
	ln -sf age-plugin-se $@

.PHONY: clean
clean:
	-rm -rf .build manual-tests

patch-package-swift-legacy:
	cat Package.swift | sed -e 's/\/\/ swift-tools-version: .*/\/\/ swift-tools-version: 5.9/' -e 's/\.macOS(\.v26)/\.macOS(\.v14)/' > Package.swift.tmp
	mv Package.swift.tmp Package.swift

################################################################################

.PHONY: smoke-test
smoke-test:
	$(AT)PATH="$(BUILD_DIR):$$PATH" && \
	$(ECHO) '\xf0\x9f\x94\x91 Generating key...' && \
	recipient=`age-plugin-se keygen $(TEST_KEYGEN_FLAGS) --access-control=any-biometry -o key.txt | sed -e "s/Public key: //"` && \
	$(ECHO) '\xf0\x9f\x94\x92 Encrypting...' && \
	($(ECHO) '\xe2\x9c\x85 \x53\x75\x63\x63\x65\x73\x73' | $(AGE) --encrypt --recipient $$recipient -o secret.txt.age) && \
	$(ECHO) '\xf0\x9f\x94\x93 Decrypting...' && \
	$(AGE) --decrypt -i key.txt secret.txt.age && \
	rm -f key.txt secret.txt.age

.PHONY: smoke-test-noninteractive
smoke-test-noninteractive:
	$(AT)PATH="$(BUILD_DIR):$$PATH" && \
	$(ECHO) '\xf0\x9f\x94\x91 Generating key...' && \
	recipient=`age-plugin-se keygen $(TEST_KEYGEN_FLAGS) --access-control=none -o key.txt | sed -e "s/Public key: //"` && \
	$(ECHO) '\xf0\x9f\x94\x92 Encrypting...' && \
	($(ECHO) '\xe2\x9c\x85 \x53\x75\x63\x63\x65\x73\x73' | $(AGE) --encrypt --recipient $$recipient -o secret.txt.age) && \
	$(ECHO) '\xf0\x9f\x94\x93 Decrypting...' && \
	$(AGE) --decrypt -i key.txt secret.txt.age && \
	rm -f key.txt secret.txt.age

.PHONY: smoke-test-encrypt
smoke-test-encrypt:
	$(AT)PATH="$(BUILD_DIR):$$PATH" && \
	$(ECHO) '\xf0\x9f\x94\x92 Encrypting...' && \
	($(ECHO) "test" | $(AGE) --encrypt $(TEST_KEYGEN_FLAGS) --recipient age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp -o secret.txt.age) && \
	$(ECHO) '\xe2\x9c\x85 \x53\x75\x63\x63\x65\x73\x73' && \
	rm -f secret.txt.age

INTEROP_PLUGIN=yubikey

.PHONY: piv-p256-decrypt-interop-test
piv-p256-decrypt-interop-test:
	$(AT)PATH="$(BUILD_DIR):$$PATH" && \
	$(ECHO) '\xf0\x9f\x94\x91 Generating key...' && \
	recipient=`age-plugin-se keygen --access-control=none -o key.txt | sed -e "s/Public key: //"` && \
	interop_recipient=`./Scripts/ConvertBech32HRP.swift $$recipient age1$(INTEROP_PLUGIN)` && \
	$(ECHO) '\xf0\x9f\x94\x92 Encrypting to '$$interop_recipient'...' && \
	($(ECHO) '\xe2\x9c\x85 \x53\x75\x63\x63\x65\x73\x73' | $(AGE) --encrypt --recipient $$interop_recipient -o secret.txt.age) && \
	$(ECHO) '\xf0\x9f\x94\x93 Decrypting...' && \
	$(AGE) --decrypt -i key.txt secret.txt.age && \
	rm -f key.txt secret.txt.age

.PHONY: p256tag-decrypt-interop-test
p256tag-decrypt-interop-test:
	$(AT)PATH="$(BUILD_DIR):$$PATH" && \
	$(ECHO) '\xf0\x9f\x94\x91 Generating key...' && \
	recipient=`age-plugin-se keygen --access-control=none --recipient-type=tag -o key.txt | sed -e "s/Public key: //"` && \
	$(ECHO) '\xf0\x9f\x94\x92 Encrypting to '$$recipient'...' && \
	($(ECHO) '\xe2\x9c\x85 \x53\x75\x63\x63\x65\x73\x73' | $(AGE) --encrypt --recipient $$recipient -o secret.txt.age) && \
	$(ECHO) '\xf0\x9f\x94\x93 Decrypting...' && \
	$(AGE) --decrypt -i key.txt secret.txt.age && \
	rm -f key.txt secret.txt.age

.PHONY: mlkemp256tag-decrypt-interop-test
mlkem768p256tag-decrypt-interop-test:
	$(AT)PATH="$(BUILD_DIR):$$PATH" && \
	$(ECHO) '\xf0\x9f\x94\x91 Generating key...' && \
	recipient=`age-plugin-se keygen --access-control=none --pq --recipient-type=tag -o key.txt | sed -e "s/Public key: //"` && \
	$(ECHO) '\xf0\x9f\x94\x92 Encrypting to '$$recipient'...' && \
	($(ECHO) '\xe2\x9c\x85 \x53\x75\x63\x63\x65\x73\x73' | $(AGE) --encrypt --recipient $$recipient -o secret.txt.age) && \
	$(ECHO) '\xf0\x9f\x94\x93 Decrypting...' && \
	$(AGE) --decrypt -i key.txt secret.txt.age && \
	rm -f key.txt secret.txt.age

.PHONY: gen-manual-tests
gen-manual-tests:
	-rm -rf gen-manual-tests
	mkdir -p manual-tests
	PATH="$(BUILD_DIR):$$PATH" && set -e && \
	for control in none passcode current-biometry any-biometry current-biometry-and-passcode any-biometry-and-passcode any-biometry-or-passcode; do \
		recipient=`age-plugin-se keygen $(TEST_KEYGEN_FLAGS) --access-control=$$control -o manual-tests/key.$$control.txt | sed -e "s/Public key: //"`;\
		($(ECHO) '\xe2\x9c\x85 \x53\x75\x63\x63\x65\x73\x73' | $(AGE) --encrypt --recipient $$recipient -o manual-tests/secret.txt.$$control.age); \
	done

.PHONY: run-manual-tests
run-manual-tests:
	$(AT)PATH="$(BUILD_DIR):$$PATH" && set -e && \
	for control in none passcode any-biometry current-biometry-and-passcode any-biometry-and-passcode any-biometry-or-passcode; do \
		$(ECHO) "\\xf0\\x9f\\x94\\x93 Decrypting '$$control'..." && \
		$(AGE) --decrypt -i manual-tests/key.$$control.txt manual-tests/secret.txt.$$control.age; \
		$(ECHO) "\n-----\n"; \
	done
