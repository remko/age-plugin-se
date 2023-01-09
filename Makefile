ifeq ($(RELEASE),1)
SWIFT_BUILD_FLAGS=-c release
BUILD_DIR=$(PWD)/.build/release
else
BUILD_DIR=$(PWD)/.build/debug
endif
PREFIX ?= /usr/local

.PHONY: all
all:
	swift build $(SWIFT_BUILD_FLAGS)

.PHONY: test
test:
	swift test

.PHONY: install
install:
	install -d $(PREFIX)/bin
	install $(BUILD_DIR)/age-plugin-applese $(PREFIX)/bin

.PHONY: smoke-test
smoke-test:
	PATH="$(BUILD_DIR):$$PATH" && \
		recipient=`age-plugin-applese keygen -o key.txt | sed -e "s/Public key: //"` && \
		age --encrypt --recipient $$recipient -o README.md.age README.md  && \
		age --decrypt -i key.txt README.md.age && \
		rm -f key.txt README.md.age

