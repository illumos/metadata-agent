DESTDIR=
MODE=debug
USER=root
BIN_GROUP=bin
SYS_GROUP=sys

.PHONY: all

ifeq ($(MODE), release)
cargo_args=--release
else
cargo_args=
endif

build: target/$(MODE)/metadata

target/$(MODE)/metadata:
	cargo build $(cargo_args)

install: build
	mkdir -p $(DESTDIR)/usr/lib
	mkdir -p $(DESTDIR)/lib/svc/manifest/system
	install -m 0755 -u $(USER) -g $(BIN_GROUP) target/$(MODE)/metadata $(DESTDIR)/usr/lib/metadata
	install -m 0755 -u $(USER) -g $(BIN_GROUP) userscript.sh $(DESTDIR)/usr/lib/userscript.sh
	install -m 0755 -u $(USER) -g $(SYS_GROUP) metadata.xml $(DESTDIR)/lib/svc/manifest/system/metadata.xml
	install -m 0755 -u $(USER) -g $(SYS_GROUP) userscript.xml $(DESTDIR)/lib/svc/manifest/system/userscript.xml
