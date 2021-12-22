.PHONY: all

CC?=		/usr/bin/cc
CFLAGS= 	-Wall -Wextra -Werror -std=c89

DEBUG=		1
.ifdef DEBUG
CFLAGS+=	-O0 -g
.endif

SANITY=		1
.ifdef SANITY
CFLAGS+=	-Wno-unused-variable -Wno-unused-parameter # -Wno-comment
.endif

PREFIX?=	/usr/local
BINDIR=		$(PREFIX)/libexec/systemd
SYSCONFDIR?=	/etc

INSTALL_PROGRAM=	install -c -s -o root -g bin -m 555
INSTALL_PROGRAM_DIR=	install -d -o root -g bin -m 755
INSTALL_DATA=		install -c -o root -g bin -m 444
INSTALL_DATA_DIR=	install -d -o root -g bin -m 755

LINKGN=		bin/obj/hostnamed-gen.o \
		bin/obj/localed-gen.o \
		bin/obj/timedated-gen.o \
		bin/obj/logind-gen.o

LINKHN=		bin/systemd-hostnamed \
		bin/systemd-localed \
		bin/systemd-timedated \
		bin/systemd-logind

DBUS_SERVICES=	org.freedesktop.hostname1.service \
		org.freedesktop.locale1.service \
		org.freedesktop.timedate1.service

GLIBEF=`pkg-config --cflags --libs glib-2.0 gobject-2.0 gio-2.0 gio-unix-2.0 polkit-agent-1`
GLIBOF=`pkg-config --cflags        glib-2.0 gobject-2.0 gio-2.0 gio-unix-2.0 polkit-agent-1`

SRCDIR=		src
CONFDIR=	conf
POLICYDIR=	$(CONFDIR)/sysbus-policy
ISPECTDIR=	$(CONFDIR)/introspect-xml
SERVICEFDIR=	$(CONFDIR)/service-files
POLKITDIR=	$(CONFDIR)/polkit-policy

INTFDIR=	$(SRCDIR)/interfaces

DBUS_POLICYDIR=		$(SYSCONFDIR)/dbus-1/system.d
DBUS_CONFIGDIR=		$(PREFIX)/share/dbus-1/system-services
POLKIT_POLICYDIR=	$(PREFIX)/share/polkit-1/actions

INVOKE_GENFILE_SCRIPT= \
		./scripts/gen-gdbus-interfaces.sh 

all: build

build: _build_interface_objs

clean:
	find ./bin -type f -exec rm {} \;
	find $(INTFDIR)/ -type f -iname *-gen.* -exec rm {} \;

install: _install_conf _install_interface_binaries

_build_interface_objs: _build_genfile_objs
	$(CC) -o bin/systemd-hostnamed $(CFLAGS) $(GLIBEF) $(INTFDIR)/hostnamed/hostnamed.c bin/obj/hostnamed-gen.o bin/obj/polkit-auth.o 
	$(CC) -o bin/systemd-localed   $(CFLAGS) $(GLIBEF) $(INTFDIR)/localed/localed.c     bin/obj/localed-gen.o   bin/obj/polkit-auth.o
	$(CC) -o bin/systemd-timedated $(CFLAGS) $(GLIBEF) $(INTFDIR)/timedated/timedated.c bin/obj/timedated-gen.o bin/obj/polkit-auth.o
	$(CC) -o bin/systemd-logind    $(CFLAGS) $(GLIBEF) $(INTFDIR)/logind/logind.c       bin/obj/logind-gen.o    bin/obj/polkit-auth.o

_build_genfile_objs: _generate_genfiles _build_auth_obj
	$(CC) -o bin/obj/hostnamed-gen.o $(CFLAGS) $(GLIBOF) -c $(INTFDIR)/hostnamed/hostnamed-gen.c
	$(CC) -o bin/obj/localed-gen.o   $(CFLAGS) $(GLIBOF) -c $(INTFDIR)/localed/localed-gen.c
	$(CC) -o bin/obj/timedated-gen.o $(CFLAGS) $(GLIBOF) -c $(INTFDIR)/timedated/timedated-gen.c
	$(CC) -o bin/obj/logind-gen.o    $(CFLAGS) $(GLIBOF) -c $(INTFDIR)/logind/logind-gen.c

_build_auth_obj:
	$(CC) -o bin/obj/polkit-auth.o $(CFLAGS) $(GLIBOF) -c $(SRCDIR)/util.c

_generate_genfiles:
	$(INVOKE_GENFILE_SCRIPT) hostnamed
	$(INVOKE_GENFILE_SCRIPT) localed
	$(INVOKE_GENFILE_SCRIPT) timedated
	$(INVOKE_GENFILE_SCRIPT) logind

_generate_servicefiles:
	for svc in $(DBUS_SERVICES); do \
		sed -e 's,@BINDIR@,${BINDIR},' $(SERVICEFDIR)/$$svc.in > $(SERVICEFDIR)/$$svc; \
	done

_install_conf: _generate_servicefiles
	${INSTALL_DATA_DIR} $(DESTDIR)$(DBUS_POLICYDIR)
	${INSTALL_DATA_DIR} $(DESTDIR)$(DBUS_CONFIGDIR)
	${INSTALL_DATA_DIR} $(DESTDIR)$(POLKIT_POLICYDIR)
	${INSTALL_DATA} $(CONFDIR)/machine-info $(DESTDIR)$(SYSCONFDIR)/
	${INSTALL_DATA} $(POLICYDIR)/*-dbus.conf $(DESTDIR)$(DBUS_POLICYDIR)/
	${INSTALL_DATA} $(SERVICEFDIR)/*.service $(DESTDIR)$(DBUS_CONFIGDIR)/
	${INSTALL_DATA} $(POLKITDIR)/*.policy $(DESTDIR)$(POLKIT_POLICYDIR)/

_install_interface_binaries: $(LINKHN)
	${INSTALL_PROGRAM_DIR} $(DESTDIR)$(BINDIR)
	${INSTALL_PROGRAM} bin/systemd-* $(DESTDIR)$(BINDIR)/ 
