CC=gcc
CFLAGS=-g -O2 -fPIC -fno-stack-protector 
LIBS=
INSTALL=/bin/install -c
prefix=/
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
libdir=${exec_prefix}/lib
mandir=${datarootdir}/man
datarootdir=${prefix}/share
sysconfdir=${prefix}/etc
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1
OBJ=utility.o sha2.o


all: pam_digestauth.so

pam_digestauth.so: common.h pam_module.c $(OBJ)
	$(CC) $(FLAGS) -opam_digestauth.so -shared -lpam pam_module.c $(OBJ)
	-strip pam_digestauth.so

utility.o: utility.h utility.c
	$(CC) $(FLAGS) -c utility.c

sha2.o: sha2.h sha2.c
	$(CC) $(FLAGS) -c sha2.c

install: pam_digestauth.so
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) -d $(DESTDIR)$(libdir)/security
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) pam_digestauth.so $(DESTDIR)$(libdir)/security
	$(INSTALL) pam_digestauth.8 $(DESTDIR)$(mandir)/man8

clean:
	-rm -f *.o *.so
	-rm -f config.log config.status */config.log */config.status
	-rm -fr autom4te.cache */autom4te.cache

distclean:
	-rm -f *.o *.so
	-rm -f config.log config.status */config.log */config.status Makefile */Makefile
	-rm -fr autom4te.cache */autom4te.cache

