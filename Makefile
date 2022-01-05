MODE=debug
USER=root
BIN_GROUP=bin
SYS_GROUP=sys

.PHONY: all build install

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
	install -c $(DESTDIR)/usr/lib -m 0755 $(ADDITIONAL_INSTALL_ARGS_BIN) target/$(MODE)/metadata
	install -c $(DESTDIR)/usr/lib -m 0755 $(ADDITIONAL_INSTALL_ARGS_BIN) userscript.sh
	install -c $(DESTDIR)/lib/svc/manifest/system -m 0644 $(ADDITIONAL_INSTALL_ARGS_SMF) metadata.xml
	install -c $(DESTDIR)/lib/svc/manifest/system -m 0644 $(ADDITIONAL_INSTALL_ARGS_SMF) userscript.xml
