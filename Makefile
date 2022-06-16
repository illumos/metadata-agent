INSTALL = /usr/sbin/install
BINDIR = /usr/lib
MANIFESTDIR = /lib/svc/manifest/system

PRE_HASH = pre\#
HASH = $(PRE_HASH:pre\%=%)

SET_OWNER ?= $(HASH)
$(SET_OWNER)OWNER_BIN = -u root -g bin
$(SET_OWNER)OWNER_SMF = -u root -g sys

INSTALL_BIN = $(INSTALL) -s -f $(DESTDIR)$(BINDIR) $(OWNER_BIN) -m 0755
INSTALL_SMF = $(INSTALL) -s -f $(DESTDIR)$(MANIFESTDIR) $(OWNER_SMF) -m 0644

build: build-debug

build-debug:
	cargo build

build-release:
	cargo build --release

install-%: build-%
	mkdir -p $(DESTDIR)/usr/lib
	mkdir -p $(DESTDIR)/lib/svc/manifest/system
	$(INSTALL_BIN) target/$(@:install-%=%)/metadata
	$(INSTALL_BIN) userscript.sh
	$(INSTALL_SMF) metadata.xml
	$(INSTALL_SMF) userscript.xml

install: install-release

clean:
	cargo clean