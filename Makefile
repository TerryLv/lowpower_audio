# file      Makefile
# copyright Copyright (c) 2012-2016 Toradex AG
#           [Software License Agreement]
# author    $Author$
# version   $Rev$
# date      $Date$
# brief     a simple makefile to (cross) compile.
#           uses the openembedded provided sysroot and toolchain
# target    Linux on Apalis/Colibri modules
# caveats   -

##############################################################################
# Setup your project settings
##############################################################################

# Set the input source files, the binary name and used libraries to link
SRCS_PLAY =	lp_play.o
SRCS_REC =	lp_record.o
PROG_PLAY := lp_play
PROG_REC := lp_record
LIBS = -lm

#ARCH_CFLAGS = -march=armv7-a -fno-tree-vectorize -mthumb-interwork -mfloat-abi=hard -mfpu=neon -mtune=cortex-a5

# Set flags to the compiler and linker
#CFLAGS += -O2 -g -Wall -DNV_IS_LDK=1 `$(PKG-CONFIG) --cflags glib-2.0 gstreamer-0.10` --sysroot=$(OECORE_TARGET_SYSROOT) $(ARCH_CFLAGS)
#LDFLAGS += -lpthread `$(PKG-CONFIG) --libs glib-2.0 gstreamer-0.10`
CFLAGS += -O2 -g -Wall -DNV_IS_LDK=1 -I$(OECORE_TARGET_SYSROOT)/usr/include/glib-2.0 -I$(OECORE_TARGET_SYSROOT)/usr/lib/glib-2.0/include -I$(OECORE_TARGET_SYSROOT)/usr/include/gstreamer-1.0 --sysroot=$(OECORE_TARGET_SYSROOT) $(ARCH_CFLAGS)
#CFLAGS += -O0 -g -Wall -DNV_IS_LDK=1 -I$(OECORE_TARGET_SYSROOT)/usr/include/glib-2.0 -I$(OECORE_TARGET_SYSROOT)/usr/lib/glib-2.0/include -I$(OECORE_TARGET_SYSROOT)/usr/include/gstreamer-1.0 --sysroot=$(OECORE_TARGET_SYSROOT) $(ARCH_CFLAGS)
LDFLAGS += -lpthread -L$(OECORE_TARGET_SYSROOT)/usr/lib -lglib-2.0 -lgstreamer-1.0 -lgobject-2.0

##############################################################################
# Setup your build environment
##############################################################################
OECORE_NATIVE_SYSROOT ?= /usr/local/oecore-x86_64/sysroots/x86_64-angstromsdk-linux/
OECORE_TARGET_SYSROOT ?= /usr/local/oecore-x86_64/sysroots/armv7at2hf-neon-angstrom-linux-gnueabi/
CROSS_COMPILE ?= $(OECORE_NATIVE_SYSROOT)usr/bin/arm-angstrom-linux-gnueabi/arm-angstrom-linux-gnueabi-

##############################################################################
# The rest of the Makefile usually needs no change
##############################################################################

# Set differencies between native and cross compilation
ifneq ($(strip $(CROSS_COMPILE)),)
  LDFLAGS += -L$(OECORE_TARGET_SYSROOT)/usr/lib -Wl,-rpath-link,$(OECORE_TARGET_SYSROOT)/usr/lib -L$(OECORE_TARGET_SYSROOT)/lib -Wl,-rpath-link,$(OECORE_TARGET_SYSROOT)/lib
  BIN_POSTFIX =
  PKG-CONFIG = export PKG_CONFIG_SYSROOT_DIR=$(OECORE_TARGET_SYSROOT); \
               export PKG_CONFIG_PATH=$(OECORE_TARGET_SYSROOT)/usr/lib/pkgconfig/; \
               $(OECORE_NATIVE_SYSROOT)/usr/share/bash-completion/completions/pkg-config
else
# Native compile
  PKG-CONFIG = pkg-config
  ARCH_CFLAGS = 
# Append .x86 to the object files and binaries, so that native and cross builds can live side by side
  BIN_POSTFIX = .x86
endif

# Toolchain binaries
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
RM = rm -f

# Sets the output filename and object files
PROG_PLAY := $(PROG_PLAY)$(BIN_POSTFIX)
PROG_REC := $(PROG_REC)$(BIN_POSTFIX)
OBJS_PLAY = $(SRCS_PLAY:.c=$(BIN_POSTFIX).o)
OBJS_REC = $(SRCS_REC:.c=$(BIN_POSTFIX).o)
DEPS_PLAY = $(OBJS_PLAY:.o=.o.d)
DEPS_REC = $(OBJS_REC:.o=.o.d)

# pull in dependency info for *existing* .o files
-include $(DEPS_PLAY) $(DEPS_REC)

all: play rec

play: $(PROG_PLAY)
rec:  $(PROG_REC)

$(PROG_PLAY): $(OBJS_PLAY) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS_PLAY) $(LIBS) $(LDFLAGS)
	#$(STRIP) $@ 

$(PROG_REC): $(OBJS_REC) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJS_REC) $(LIBS) $(LDFLAGS)
	#$(STRIP) $@ 

%$(BIN_POSTFIX).o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<
	$(CC) -MM $(CFLAGS) $< > $@.d

clean:
	$(RM) $(OBJS_PLAY) $(OBJS_REC) $(PROG_PLAY) $(PROG_RECORD) $(DEPS_PLAY) $(DEPS_REC)

.PHONY: all clean
