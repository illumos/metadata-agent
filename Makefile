MODE=debug
USER=root
BIN_GROUP=bin
SYS_GROUP=sys

.PHONY: all

# Convenience magic so packagers don't accidentally package debug builds
ifdef DESTDIR
MODE=release
endif

ifndef DESTDIR
ADDITIONAL_INSTALL_ARGS_BIN += -u $(USER) -g $(BIN_GROUP)
ADDITIONAL_INSTALL_ARGS_SMF += -u $(USER) -g $(SYS_GROUP)
endif

ifeq ($(MODE), release)
cargo_args += --release
endif

build: target/$(MODE)/metadata

target/$(MODE)/metadata:
	cargo build $(cargo_args)

install: build
	mkdir -p $(DESTDIR)/usr/lib
	mkdir -p $(DESTDIR)/lib/svc/manifest/system
	install -m 0755 $(ADDITIONAL_INSTALL_ARGS_BIN) target/$(MODE)/metadata $(DESTDIR)/usr/lib/metadata
	install -m 0755 $(ADDITIONAL_INSTALL_ARGS_BIN) userscript.sh $(DESTDIR)/usr/lib/userscript.sh
	install -m 0644 $(ADDITIONAL_INSTALL_ARGS_SMF) metadata.xml $(DESTDIR)/lib/svc/manifest/system/metadata.xml
	install -m 0644 $(ADDITIONAL_INSTALL_ARGS_SMF) userscript.xml $(DESTDIR)/lib/svc/manifest/system/userscript.xml
