# Copied from certificate's Makefile, which was copied from security's, which
# was copied from font's, which was copied from model's, per CONVENTIONS.md
# section 12. SUITE, PROJECT, the dependency block (certificate and security as
# well as cutil), the fuzzers, and the gates that are this library's are the
# parts that changed. certificate's OpenSSL oracle is not carried over: this
# library's reference is RFC 8448, pinned and extracted by tools/fetch.sh, and
# check-foundation is what holds that pin. security's constant-time gate is
# carried over in shape (check-ct), driving the one comparison this library
# makes of a secret, the check of Finished.

SUITE := ghoti.io
PROJECT := tls

BUILD ?= release
MAJOR_VERSION := 0
MINOR_VERSION := 0.0
VERSION_MINOR_ONLY := $(word 1,$(subst ., ,$(MINOR_VERSION)))
VERSION_PATCH_ONLY := $(or $(word 2,$(subst ., ,$(MINOR_VERSION))),0)
VERSION := $(MAJOR_VERSION).$(MINOR_VERSION)

# Names this build everywhere: the .pc file, the install directory, the soname
# and the symbol token. Defaults to the major version. Override for a build
# that wants its own identity: make BRANCH=-dev
BRANCH ?= -$(MAJOR_VERSION)

ifeq ($(BRANCH),-$(MAJOR_VERSION))
VERSION_STRING := $(VERSION)
else
VERSION_STRING := $(VERSION)$(BRANCH)
endif

# override: BRANCH may have come from the command line, and a command-line
# variable otherwise beats a plain assignment. Without it, `make BRANCH=-dev
# BUILD=debug` produced a debug build carrying the release token.
ifeq ($(BUILD),debug)
    override BRANCH := $(BRANCH)-debug
    override VERSION_STRING := $(VERSION_STRING)-debug
endif

# Decided here, before the platform rewrite below. `BUILD := linux/$(BUILD)`
# is a plain assignment, so a command-line BUILD=debug stays "debug" and an
# environment BUILD=debug becomes "linux/debug". Testing it up here is true
# in both cases. Release is -O2 because that is what ships, and the
# constant-time gate builds with these flags so it measures that level.
ifeq ($(BUILD),debug)
OPT_CFLAGS := -O0
else
OPT_CFLAGS := -O2
endif

BASE_NAME := lib$(SUITE)-$(PROJECT)$(BRANCH).so
LIBVER_SYMBOL := $(shell echo "ghotiio_$(PROJECT)$(BRANCH)" | sed 's/[.-]/_/g')
BASE_NAME_PREFIX := lib$(SUITE)-$(PROJECT)$(BRANCH)
SO_NAME := $(BASE_NAME).$(MAJOR_VERSION)
STATIC_TARGET := $(BASE_NAME_PREFIX).a
ENV_VARS :=

# Do not assign PKG_CONFIG_PATH. Make exports an inherited variable with
# whatever value the makefile last gave it, so overwriting it handed every
# sub-make a different path from the parent's.
PKG_CONFIG_PATH_ENV := $(PKG_CONFIG_PATH)

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
	OS_NAME := Linux
	LIB_EXTENSION := so
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG := -Wl,-soname,$(SO_NAME)
	TARGET := $(SO_NAME).$(MINOR_VERSION)
	EXE_EXTENSION :=
	PC_INSTALL_PATH := /usr/local/share/pkgconfig
	INCLUDE_INSTALL_PATH := /usr/local/include
	LIB_INSTALL_PATH := /usr/local/lib
	PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
	override BUILD := linux/$(BUILD)

else ifeq ($(UNAME_S), Darwin)
	OS_NAME := Mac
	LIB_EXTENSION := dylib
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG := -Wl,-install_name,$(BASE_NAME_PREFIX).dylib
	TARGET := $(BASE_NAME_PREFIX).dylib
	EXE_EXTENSION :=
	PC_INSTALL_PATH := /usr/local/share/pkgconfig
	INCLUDE_INSTALL_PATH := /usr/local/include
	LIB_INSTALL_PATH := /usr/local/lib
	PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
	override BUILD := mac/$(BUILD)

# TODO(windows): the Windows branches in this file were adapted from
# certificate's, which were adapted from security's. They have run for those
# libraries under tools/xwin's imitation of MSYS2 and wine; for this one they
# have not run at all yet. Check list: notes/suite/WINDOWS-TODO.md.
else ifeq ($(findstring MINGW32_NT,$(UNAME_S)),MINGW32_NT)
	OS_NAME := Windows
	LIB_EXTENSION := dll
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG = -Wl,--out-implib,$(APP_DIR)/$(BASE_NAME_PREFIX).dll.a
	TARGET := $(BASE_NAME_PREFIX).dll
	EXE_EXTENSION := .exe
	PC_INSTALL_PATH := /mingw32/lib/pkgconfig
	INCLUDE_INSTALL_PATH := /mingw32/include
	LIB_INSTALL_PATH := /mingw32/lib
	BIN_INSTALL_PATH := /mingw32/bin
	PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
	PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
	override BUILD := win32/$(BUILD)

else ifeq ($(findstring MINGW64_NT,$(UNAME_S)),MINGW64_NT)
	OS_NAME := Windows
	LIB_EXTENSION := dll
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG = -Wl,--out-implib,$(APP_DIR)/$(BASE_NAME_PREFIX).dll.a
	TARGET := $(BASE_NAME_PREFIX).dll
	EXE_EXTENSION := .exe
	PC_INSTALL_PATH := /mingw64/lib/pkgconfig
	INCLUDE_INSTALL_PATH := /mingw64/include
	LIB_INSTALL_PATH := /mingw64/lib
	BIN_INSTALL_PATH := /mingw64/bin
	PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
	PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
	override BUILD := win64/$(BUILD)

else
    $(error Unsupported OS: $(UNAME_S))
endif

ifdef PREFIX
INCLUDE_INSTALL_PATH := $(PREFIX)/include
LIB_INSTALL_PATH := $(PREFIX)/lib
BIN_INSTALL_PATH := $(PREFIX)/bin
PC_INSTALL_PATH := $(PREFIX)/share/pkgconfig
ifeq ($(OS_NAME), Windows)
PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
else
PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
endif
LDCONF_INSTALL_PATH :=
endif

PKG_CONFIG_LOOKUP_PATH := $(if $(PKG_CONFIG_PATH_ENV),$(PKG_CONFIG_PATH_ENV):)$(PC_INSTALL_PATH)

CXX := g++
CXXFLAGS := -pedantic-errors -Wall -Wextra -Werror -Wno-error=unused-function -Wfatal-errors -std=c++20 -O1 -g $(EXTRA_CXXFLAGS)
CC := cc
# -Wstrict-aliasing=1 and -fstrict-aliasing, named rather than inherited.
# -Wall sets the aliasing warning to level 3, which is silent on the probe
# check-aliasing compiles. An explicit level beats -Wall from either side.
# -fstrict-aliasing is off below -O2 unless named, so a debug or coverage
# tree would otherwise have the warning armed and the assumption off.
# The probe is a pointer parameter stored through a second variable: that
# shape is reported at level 1 and silent at 0, 2, and 3. Do not simplify it
# to `*(int *)&local`, which fires at every level from 1 up and certifies
# nothing. check-aliasing is the measurement.
# Hardening. A crypto library is worth the exploit-mitigation flags the
# distributions have compiled everything else with for a decade, and this one
# shipped without them: no stack protector, lazy binding, no fortified string
# functions. They are *probed* rather than assumed, because this tree builds
# with GCC 14 here, GCC 16 on the EVO-X2, clang on macOS and mingw on
# Windows, and `-fcf-protection` is an error on a compiler targeting anything
# but x86 - with -Werror in play an unknown flag would break the build rather
# than degrade it. `-U_FORTIFY_SOURCE` first because a distribution compiler
# may define it already, and a redefinition is a diagnostic.
#
# check-harden asserts the result is not empty on this platform, so a probe
# that silently stops matching does not quietly disarm all of this.
gtls_flag_ok = $(shell printf 'int gtls_flag_probe(void);\n' | \
	$(CC) $(1) -O2 -x c -c -o /dev/null - >/dev/null 2>&1 && printf '%s' '$(1)')
HARDEN_CFLAGS := $(call gtls_flag_ok,-fstack-protector-strong) \
	$(call gtls_flag_ok,-fstack-clash-protection) \
	$(call gtls_flag_ok,-fcf-protection=full)
ifneq ($(BUILD),debug)
HARDEN_CFLAGS += $(or \
	$(call gtls_flag_ok,-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3), \
	$(call gtls_flag_ok,-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2))
endif

CFLAGS := -pedantic-errors -Wall -Wextra -Werror -Wfloat-conversion -fstrict-aliasing -Wstrict-aliasing=1 -Wno-error=unused-function -Wfatal-errors -std=c17 $(OPT_CFLAGS) -g $(HARDEN_CFLAGS) $(EXTRA_CFLAGS)
ifeq ($(OS_NAME), Windows)
CFLAGS += -DGTLS_STATIC -DGCERT_STATIC
CXXFLAGS += -DGTLS_STATIC -DGCERT_STATIC
endif
LIB_CFLAGS := $(CFLAGS) -fvisibility=hidden -DGTLS_BUILD $(EXTRA_CFLAGS)
LDFLAGS := -L /usr/lib -lstdc++ -lm $(EXTRA_LDFLAGS)
ifeq ($(OS_NAME), Linux)
# Full RELRO. Partial is what a bare link gives: the GOT stays writable for
# lazy binding, which is a write target in a process that holds keys.
LDFLAGS += -Wl,-z,relro,-z,now
endif
ifdef PREFIX
LDFLAGS += -Wl,-rpath,$(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Windows)
export PATH := $(BIN_INSTALL_PATH):$(PATH)
endif
endif

BUILD_DIR := ./build/$(BUILD)
OBJ_DIR := $(BUILD_DIR)/objects
FLAGS_STAMP := $(OBJ_DIR)/.flags
GEN_DIR := $(BUILD_DIR)/generated
APP_DIR := $(BUILD_DIR)/apps

ifeq ($(UNAME_S), Linux)
	LIB_CFLAGS += -fPIC
endif

INCLUDE := -I include/ -I $(GEN_DIR)/

DEPLESS_GOALS := docs docs-pdf clean fuzz-clean cloc help
ifeq ($(filter-out $(DEPLESS_GOALS),$(or $(MAKECMDGOALS),all)),)
SKIP_DEP_CHECK := 1
endif

# The name carries $(BRANCH). ghoti.io-cutil never matches the installed file.
CUTIL_PC ?= ghoti.io-cutil$(BRANCH)
CUTIL_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --cflags $(CUTIL_PC) 2>/dev/null)
CUTIL_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs $(CUTIL_PC) 2>/dev/null)
ifeq ($(strip $(CUTIL_CFLAGS)),)
ifndef SKIP_DEP_CHECK
$(error ghoti.io-cutil was not found by pkg-config. Run ./bootstrap.sh at the root of the workspace - two levels up, the directory holding libs/ - to build and install the suite into a local prefix, then pass the same PREFIX here - or point PKG_CONFIG_PATH at the directory holding its .pc file. There is deliberately no sibling-checkout fallback.)
endif
endif
INCLUDE += $(CUTIL_CFLAGS)

# The primitives. The name carries $(BRANCH) for the same reason cutil's does.
SECURITY_PC ?= ghoti.io-security$(BRANCH)
SECURITY_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --cflags $(SECURITY_PC) 2>/dev/null)
SECURITY_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs $(SECURITY_PC) 2>/dev/null)
ifeq ($(strip $(SECURITY_CFLAGS)),)
ifndef SKIP_DEP_CHECK
$(error ghoti.io-security was not found by pkg-config. Run ./bootstrap.sh at the root of the workspace - two levels up, the directory holding libs/ - to build and install the suite into a local prefix, then pass the same PREFIX here - or point PKG_CONFIG_PATH at the directory holding its .pc file. There is deliberately no sibling-checkout fallback.)
endif
endif
INCLUDE += $(SECURITY_CFLAGS)

# The certificate library: chains, names, signatures, keys.
CERTIFICATE_PC ?= ghoti.io-certificate$(BRANCH)
CERTIFICATE_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --cflags $(CERTIFICATE_PC) 2>/dev/null)
CERTIFICATE_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs $(CERTIFICATE_PC) 2>/dev/null)
ifeq ($(strip $(CERTIFICATE_CFLAGS)),)
ifndef SKIP_DEP_CHECK
$(error ghoti.io-certificate was not found by pkg-config. Run ./bootstrap.sh at the root of the workspace - two levels up, the directory holding libs/ - to build and install the suite into a local prefix, then pass the same PREFIX here - or point PKG_CONFIG_PATH at the directory holding its .pc file. There is deliberately no sibling-checkout fallback.)
endif
endif
INCLUDE += $(CERTIFICATE_CFLAGS)

# System libraries the archive needs, named AFTER it and after the libraries
# above on a link line: a static import library is searched once, in order
# (the lesson from security's -lbcrypt). None yet.
SYS_LIBS :=

# Each library's own dependencies are in its .pc file, so the order here is
# the order the linker wants: this library, certificate, security, cutil.
DEP_LIBS := $(CERTIFICATE_LIBS) $(SECURITY_LIBS) $(CUTIL_LIBS) $(SYS_LIBS)

SOURCES := $(shell find src -type f -name '*.c')
LIBOBJECTS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

TESTFLAGS := `PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs --cflags gtest`

# coverage clears this: --coverage links the gcov runtime, whose mangle_path
# check-symbols is right to reject in a shipping library.
TEST_GATES ?= check-symbols check-aliasing check-stamps check-secret check-harden \
	check-depfiles check-analyzer check-foundation check-ct check-fuzz-ub check-controls-anchors

VALGRIND_FLAGS := --leak-check=full --show-leak-kinds=definite,indirect,possible --track-origins=yes --error-exitcode=1 --suppressions=tests/valgrind.supp

TEST_HELPER_SRC := $(wildcard tests/test_helpers.cpp)
TEST_HELPER_OBJ := $(patsubst tests/%.cpp,$(OBJ_DIR)/tests/%.o,$(TEST_HELPER_SRC))

# The archive, not the shared library: a static link resolves hidden symbols.
# --whole-archive because a constructor-registered object would otherwise be
# dropped. The archive is a normal prerequisite of every test, so a clean
# tree builds it; the .so is order-only because check-symbols wants it and
# the tests do not link it.
TLSLIBRARY := -Wl,--whole-archive $(APP_DIR)/$(STATIC_TARGET) -Wl,--no-whole-archive $(DEP_LIBS)

ifeq ($(OS_NAME), Windows)
TEST_LDFLAGS := -Wl,--wrap=__mingw_fprintf
else
TEST_LDFLAGS :=
endif

TEST_PAIRS := $(shell find tests -type f -name 'test_*.cpp' 2>/dev/null | sort | grep -v test_helpers | while read f; do \
	echo "$$f|$$(basename "$$f" .cpp | sed 's/test_/test/; s/^test\([a-z]\)/test\U\1/')"; done)
TEST_SOURCES := $(foreach pair,$(TEST_PAIRS),$(word 1,$(subst |, ,$(pair))))
TEST_NAMES := $(foreach pair,$(TEST_PAIRS),$(word 2,$(subst |, ,$(pair))))
TEST_EXECUTABLES := $(addprefix $(APP_DIR)/,$(addsuffix $(EXE_EXTENSION),$(TEST_NAMES)))

EXAMPLE_SOURCES := $(shell find examples -type f -name '*.c' 2>/dev/null)
EXAMPLES := $(patsubst examples/%.c,$(APP_DIR)/examples/%$(EXE_EXTENSION),$(EXAMPLE_SOURCES))

TLS_ROOT := $(CURDIR)
TEST_DATA := $(CURDIR)/tests/data

all: $(APP_DIR)/$(TARGET) $(APP_DIR)/$(STATIC_TARGET) ## Build shared + static libraries

TEST_DEPFILES := $(foreach pair,$(TEST_PAIRS),$(OBJ_DIR)/tests/$(basename $(notdir $(word 1,$(subst |, ,$(pair))))).d)
DEPFILES := $(LIBOBJECTS:.o=.d) $(TEST_HELPER_OBJ:.o=.d) $(TEST_DEPFILES)
-include $(DEPFILES)

LIBVER_GEN := $(GEN_DIR)/ghoti.io/$(PROJECT)/libver_gen.h

.PHONY: force-libver
force-libver:

$(LIBVER_GEN): force-libver
	@if [ -z "$(LIBVER_SYMBOL)" ]; then \
		printf "### LIBVER_SYMBOL is empty ###\n" >&2; \
		printf "Every exported symbol would lose its version namespace.\n" >&2; \
		exit 1; \
	fi
	@mkdir -p $(@D)
	@printf '%s\n' \
		'// Generated by the Makefile. Do not edit; see CONVENTIONS.md section 4.' \
		'#ifndef GHOTI_IO_GTLS_LIBVER_GEN_H' \
		'#define GHOTI_IO_GTLS_LIBVER_GEN_H' \
		'' \
		'/** The symbol namespace for this build, from the Makefile'"'"'s BRANCH. */' \
		'#define GHOTIIO_TLS_NAME $(LIBVER_SYMBOL)' \
		'' \
		'/** Human-readable version of this build. */' \
		'#define GHOTIIO_TLS_VERSION "$(VERSION_STRING)"' \
		'' \
		'/** The same version as three integers. */' \
		'#define GHOTIIO_TLS_VERSION_MAJOR $(MAJOR_VERSION)' \
		'#define GHOTIIO_TLS_VERSION_MINOR $(VERSION_MINOR_ONLY)' \
		'#define GHOTIIO_TLS_VERSION_PATCH $(VERSION_PATCH_ONLY)' \
		'' \
		'#endif // GHOTI_IO_GTLS_LIBVER_GEN_H' > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi

$(OBJ_DIR)/%.o: src/%.c $(FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(APP_DIR)/$(TARGET): $(LIBOBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -shared -o $@ $^ $(LDFLAGS) $(DEP_LIBS) $(OS_SPECIFIC_LIBRARY_NAME_FLAG)
ifeq ($(OS_NAME), Linux)
	@ln -f -s $(TARGET) $(APP_DIR)/$(SO_NAME)
	@ln -f -s $(SO_NAME) $(APP_DIR)/$(BASE_NAME)
endif

$(APP_DIR)/$(STATIC_TARGET): $(LIBOBJECTS)
	@mkdir -p $(@D)
	@rm -f $@
	ar rcs $@ $^

ifneq ($(TEST_HELPER_SRC),)
$(TEST_HELPER_OBJ): $(TEST_HELPER_SRC) $(FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@
endif

$(OBJ_DIR)/tests/%.o: tests/%.cpp $(FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -Itests -DGTLS_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(OBJ_DIR)/tests/%.o: tests/unit/%.cpp $(FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -Itests -DGTLS_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

define test-executable-rule
TEST_OBJ_$1 := $(OBJ_DIR)/tests/$(basename $(notdir $1)).o

$(APP_DIR)/$2$(EXE_EXTENSION): $$(TEST_OBJ_$1) $(TEST_HELPER_OBJ) \
		$(APP_DIR)/$(STATIC_TARGET) | $(APP_DIR)/$(TARGET)
	@mkdir -p $$(@D)
	$(CXX) $(CXXFLAGS) -o $$@ $$(TEST_OBJ_$1) $(TEST_HELPER_OBJ) $(LDFLAGS) $(TEST_LDFLAGS) $(TLSLIBRARY) $(DEP_LIBS) $(TESTFLAGS)
endef

$(foreach pair,$(TEST_PAIRS),\
	$(eval $(call test-executable-rule,$(word 1,$(subst |, ,$(pair))),$(word 2,$(subst |, ,$(pair))))))

$(APP_DIR)/examples/%$(EXE_EXTENSION): examples/%.c $(APP_DIR)/$(STATIC_TARGET) \
		$(FLAGS_STAMP) | $(APP_DIR)/$(TARGET) $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS) $(TLSLIBRARY) $(DEP_LIBS)

.PHONY: clean cloc docs docs-pdf examples coverage check-symbols check-stamps check-aliasing
.PHONY: check-secret check-foundation check-ct check-fuzz-ub check-harden check-depfiles
.PHONY: check-analyzer analyze check-interop interop-plants check-controls check-controls-anchors
.PHONY: all install test test-quiet test-asan test-valgrind test-valgrind-quiet test-watch uninstall watch
.PHONY: all-debug install-debug test-debug test-valgrind-debug test-watch-debug uninstall-debug watch-debug
.PHONY: fuzz fuzz-clean

watch: ## Watch sources and rebuild
	@while true; do \
		make --no-print-directory all; \
		inotifywait -qr -e modify -e create -e delete -e move src include tests Makefile; \
		done

test-watch: ## Watch sources and rerun the tests
	@while true; do \
		make --no-print-directory test; \
		inotifywait -qr -e modify -e create -e delete -e move src include tests Makefile; \
		done

examples: $(APP_DIR)/$(TARGET) $(EXAMPLES) ## Build the examples

TEST_LD_PATH := $(APP_DIR):$(LIB_INSTALL_PATH)/$(SUITE)

check-aliasing: ## Fail if -Wstrict-aliasing is not armed at level 1
	@mkdir -p $(BUILD_DIR)
	@printf 'int gtls_alias_probe(float * f);\nint gtls_alias_probe(float * f) { int * i = (int *)f; *i = 7; return *i; }\n' > $(BUILD_DIR)/alias_probe.c
	@printf 'int gtls_alias_clean(int * i);\nint gtls_alias_clean(int * i) { *i = 7; return *i; }\n' > $(BUILD_DIR)/alias_clean.c
	@probe=$$($(CC) $(CFLAGS) -Wno-error -c $(BUILD_DIR)/alias_probe.c -o $(BUILD_DIR)/alias_probe.o 2>&1); \
	ctl=$$($(CC) $(CFLAGS) -Wno-error -c $(BUILD_DIR)/alias_clean.c -o $(BUILD_DIR)/alias_clean.o 2>&1); ctlrc=$$?; \
	if [ $$ctlrc -ne 0 ]; then \
		printf 'check-aliasing: the control file did not compile, so this gate is measuring nothing:\n%s\n' "$$ctl" >&2; \
		exit 1; \
	fi; \
	if printf '%s' "$$ctl" | grep -q 'strict-aliasing'; then \
		printf 'check-aliasing: the control file drew a strict-aliasing diagnostic, so the probe proves nothing:\n%s\n' "$$ctl" >&2; \
		exit 1; \
	fi; \
	if printf '%s' "$$probe" | grep -q 'strict-aliasing'; then \
		printf 'check-aliasing: the planted violation is reported\n'; \
		exit 0; \
	fi; \
	qout=$$($(CC) -Q --help=warnings $(CFLAGS) 2>/dev/null); qrc=$$?; \
	level=$$(printf '%s' "$$qout" | awk '/-Wstrict-aliasing=</{print $$2}'); \
	if [ $$qrc -ne 0 ] || [ -z "$$level" ]; then \
		printf 'check-aliasing: no diagnostic, and %s reports no -Wstrict-aliasing level. That is a compiler which accepts the option and implements nothing.\n' "$(CC)" >&2; \
	elif [ "$$level" = 1 ]; then \
		printf 'check-aliasing: level 1 is set and the planted store still drew no diagnostic.\n' >&2; \
	else \
		printf 'check-aliasing: CFLAGS resolves to -Wstrict-aliasing=%s; only level 1 reports this probe.\n' "$$level" >&2; \
	fi; \
	exit 1

check-stamps: ## Fail if a compile rule names no flags stamp, or a stamp omits a variable
	@python3 tools/check-stamps.py

# The hardening flags are probed, so the failure mode is silence: a probe
# that stops matching disarms every one of them and the build still succeeds.
# This asserts three things - that the probe can still say no, that it said
# yes to something, and that the property reached the artifact rather than
# just the command line.
check-harden: $(APP_DIR)/$(TARGET) ## Fail if the hardening flags were probed away
	@if [ -n '$(call gtls_flag_ok,-fgsec-not-a-real-flag)' ]; then \
		printf 'check-harden: the probe accepted a flag that does not exist, so it certifies nothing\n' >&2; \
		exit 1; \
	fi
	@if [ -z '$(strip $(HARDEN_CFLAGS))' ]; then \
		printf 'check-harden: no hardening flag survived the probe on this platform\n' >&2; \
		exit 1; \
	fi
ifeq ($(OS_NAME), Linux)
	@if ! command -v readelf >/dev/null 2>&1; then \
		printf 'check-harden: no readelf, so only the flags were checked\n' >&2; \
		exit 0; \
	fi
	@if ! nm -D $(APP_DIR)/$(TARGET) 2>/dev/null | grep -q stack_chk; then \
		printf 'check-harden: %s has no stack-protector reference\n' '$(TARGET)' >&2; \
		exit 1; \
	fi
	@if ! readelf -dW $(APP_DIR)/$(TARGET) | grep -q BIND_NOW; then \
		printf 'check-harden: %s is not linked with full RELRO\n' '$(TARGET)' >&2; \
		exit 1; \
	fi
endif
	@printf 'check-harden: %s\n' '$(strip $(HARDEN_CFLAGS))'

# The fuzz flags must turn undefined behaviour into a failing run. They did
# not: UBSan's default is to print and continue, libFuzzer only fails on a
# crash, and a planted signed overflow in gtls_sha256_update printed its
# diagnostic while the run exited 0 after 270,975 inputs. Every campaign
# recorded up to 2026-09-28 was therefore incapable of failing on UB.
#
# One harness with the overflow in it, built with the flags the fuzzers use,
# and required to exit nonzero. A control harness without the overflow must
# exit 0, because a gate that fails for some other reason - a missing clang,
# a link error - is measuring nothing. Skipped, loudly, when clang is absent;
# there is nothing to gate then.
check-fuzz-ub: ## Fail unless the fuzz flags make undefined behaviour a failing run
	@if [ -z "$(FUZZ_CC_OK)" ]; then \
		printf 'check-fuzz-ub: no %s, so the fuzz flags are not gated here\n' \
			'$(FUZZ_CXX)' >&2; \
		exit 0; \
	fi
	@mkdir -p $(BUILD_DIR)/fuzzub
	@printf '#include <cstddef>\n#include <cstdint>\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t * d, size_t n) {\n  static int v = 0x7ffffff0;\n  if (n > 0) { v += d[0] | 0x10; }\n  return v == 0 ? 0 : 0;\n}\n' > $(BUILD_DIR)/fuzzub/ub.cpp
	@printf '#include <cstddef>\n#include <cstdint>\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t * d, size_t n) {\n  static unsigned v = 0u;\n  if (n > 0) { v += d[0]; }\n  return v == 0u ? 0 : 0;\n}\n' > $(BUILD_DIR)/fuzzub/clean.cpp
	@$(FUZZ_CXX) $(FUZZ_BIN_FLAGS) -std=c++20 -w -o $(BUILD_DIR)/fuzzub/ub \
		$(BUILD_DIR)/fuzzub/ub.cpp 2>/dev/null || { \
		printf 'check-fuzz-ub: the probe did not build, so this gate is measuring nothing\n' >&2; exit 1; }
	@$(FUZZ_CXX) $(FUZZ_BIN_FLAGS) -std=c++20 -w -o $(BUILD_DIR)/fuzzub/clean \
		$(BUILD_DIR)/fuzzub/clean.cpp 2>/dev/null || { \
		printf 'check-fuzz-ub: the control did not build, so this gate is measuring nothing\n' >&2; exit 1; }
	@rm -rf $(BUILD_DIR)/fuzzub/seed && mkdir -p $(BUILD_DIR)/fuzzub/seed
	@printf 'A' > $(BUILD_DIR)/fuzzub/seed/one
	@if ! $(BUILD_DIR)/fuzzub/clean $(BUILD_DIR)/fuzzub/seed -runs=0 \
			-print_final_stats=0 \
			-artifact_prefix=$(BUILD_DIR)/fuzzub/ >/dev/null 2>&1; then \
		printf 'check-fuzz-ub: the control run failed, so a nonzero status proves nothing\n' >&2; \
		exit 1; \
	fi
	@if $(BUILD_DIR)/fuzzub/ub $(BUILD_DIR)/fuzzub/seed -runs=0 \
			-print_final_stats=0 \
			-artifact_prefix=$(BUILD_DIR)/fuzzub/ >/dev/null 2>&1; then \
		printf 'check-fuzz-ub: a planted signed overflow ran to a zero exit. FUZZ_SAN needs -fno-sanitize-recover, or every campaign is unable to fail on UB.\n' >&2; \
		exit 1; \
	fi
	@printf 'check-fuzz-ub: planted undefined behaviour fails the run, and the control does not\n'

check-controls-anchors: ## Fail if a planted defect in tools/controls.sh no longer applies exactly once
	@sh tools/controls.sh --anchors

check-controls: ## Plant each defect in a scratch copy and require its test to fail (slow; needs PREFIX)
	@sh tools/controls.sh

check-secret: ## Fail if src/ calls memcmp, a userspace generator, or printf
	@python3 tools/check-secret.py

check-foundation: ## Fail if the registry, the manifest, or the oracle pins disagree
	@python3 tools/check_foundation.py

check-depfiles: ## Fail if an object tree does not track its header dependencies
	@python3 tools/check-depfiles.py

# Static analysis, gated rather than occasional. cppcheck is clean over this
# tree and costs a few seconds, so there is no reason for it to be a thing
# somebody remembers to run. A plant keeps it honest: if cppcheck stops
# reporting an obvious defect - a newer version, a different default, a
# missing binary mistaken for success - the gate says so instead of passing.
#
# `make analyze` is the slower sweep, GCC's -fanalyzer over the same sources.
# It is not in TEST_GATES because it takes minutes rather than seconds.
check-analyzer: ## Fail if cppcheck reports anything, or stops reporting a plant
	@if ! command -v cppcheck >/dev/null 2>&1; then \
		printf 'check-analyzer: no cppcheck, static analysis is not gated\n' >&2; \
		exit 0; \
	fi; \
	mkdir -p $(BUILD_DIR)/analyzer; \
	printf 'int gtls_plant(void);\nint gtls_plant(void) { int * p = 0; return *p; }\n' \
		> $(BUILD_DIR)/analyzer/plant.c; \
	if cppcheck --enable=warning --std=c17 --quiet --error-exitcode=2 \
			$(BUILD_DIR)/analyzer/plant.c >/dev/null 2>&1; then \
		printf 'check-analyzer: cppcheck did not report the planted null dereference, so this gate certifies nothing\n' >&2; \
		exit 1; \
	fi; \
	out=$$(cppcheck --enable=warning,portability --inline-suppr --std=c17 \
		--quiet -I include -I $(BUILD_DIR)/generated src/ 2>&1 \
		| grep -vE 'normalCheckLevelMaxBranches|^\^$$|^$$'); \
	if [ -n "$$out" ]; then \
		printf 'check-analyzer: cppcheck reports:\n%s\n' "$$out" >&2; \
		exit 1; \
	fi; \
	printf 'check-analyzer: cppcheck is clean, and still reports the plant\n'

analyze: ## GCC's -fanalyzer over src/, slower than check-analyzer
	@status=0; \
	for f in $(SOURCES); do \
		out=$$($(CC) -fanalyzer $(LIB_CFLAGS) $(INCLUDE) -c $$f -o /dev/null 2>&1); \
		if [ -n "$$out" ]; then printf '%s\n' "$$out"; status=1; fi; \
	done; \
	if [ $$status -eq 0 ]; then \
		printf 'analyze: -fanalyzer is clean over every source\n'; \
	fi; \
	exit $$status

####################################################################
# Interop: OpenSSL in a container, both roles
####################################################################
# Not part of `make test`: it needs a container engine and the OpenSSL image
# that libs/certificate builds (`make oracle-build` there). It fails, rather
# than skipping, when it cannot reach the reference. PREFIX must be given: the
# planted builds are made in scratch copies against it.

check-interop: $(APP_DIR)/examples/echo$(EXE_EXTENSION) ## Run the OpenSSL interop population, both roles
	@LD_LIBRARY_PATH="$(TEST_LD_PATH)" PREFIX="$(PREFIX)" python3 tools/oracle/interop.py --echo $(APP_DIR)/examples/echo$(EXE_EXTENSION)

interop-plants: $(APP_DIR)/examples/echo$(EXE_EXTENSION) ## Plant a defect, one at a time, and require the interop cases to fail
	@status=0; for p in record-nonce key-update-label server-cv-label client-finished alpn-failure supported-versions no-common-scheme plaintext-alert-rule sni-selection early-skip-off psk-refused retry-skip-ends resume-binder-transcript resume-client-binder resume-client-binder-retry resume-age-window resume-sni resume-alpn resume-key-name resume-client-assumes resume-selected early-server-never-accepts early-server-ignores-callback early-server-alpn-tie early-server-eoed-not-awaited early-client-eoed-not-in-transcript early-client-retry-keeps-early; do \
		LD_LIBRARY_PATH="$(TEST_LD_PATH)" PREFIX="$(PREFIX)" python3 tools/oracle/interop.py --echo $(APP_DIR)/examples/echo$(EXE_EXTENSION) --plant $$p || status=1; \
	done; exit $$status

####################################################################
# Constant-time gate
####################################################################
# The one comparison this library makes of a secret is the check of the
# server's Finished: HMAC under a key derived from the handshake secret,
# compared with what the peer sent. A separate object tree, compiled with
# GTLS_CT_TEST so the library stops tracking at the door of gsec_equal, which
# security's own check-ct gate covers; everything from the key up to that
# call is watched.
#
# Two programs. `clean` marks the key undefined and calls the check on a
# matching and on a differing value; memcheck must be silent. `leak` branches
# on a byte it marked undefined; memcheck must report it. A silent leak means
# the gate is measuring nothing, and that fails the build. Both programs
# refuse to run outside Valgrind.

CT_DIR := $(BUILD_DIR)/ct
CT_OBJ := $(CT_DIR)/objects
CT_APP := $(CT_DIR)/apps
CT_FLAGS_STAMP := $(CT_OBJ)/.flags
CT_DEPFILES := $(patsubst src/%.c,$(CT_OBJ)/%.d,$(SOURCES)) $(CT_OBJ)/clean.d
-include $(CT_DEPFILES)
CT_CFLAGS := $(LIB_CFLAGS) -DGTLS_CT_TEST -Wno-pedantic
CT_OBJECTS := $(patsubst src/%.c,$(CT_OBJ)/%.o,$(SOURCES))
CT_ARCHIVE := $(CT_APP)/$(STATIC_TARGET)

$(CT_OBJ)/%.o: src/%.c $(CT_FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CC) $(CT_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(CT_ARCHIVE): $(CT_OBJECTS)
	@mkdir -p $(@D)
	@rm -f $@
	ar rcs $@ $^

$(CT_OBJ)/clean.o: tools/ct/clean.c $(CT_FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CC) $(CT_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(CT_APP)/clean: $(CT_OBJ)/clean.o $(CT_ARCHIVE) | $(CT_FLAGS_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CT_CFLAGS) -o $@ $(CT_OBJ)/clean.o $(LDFLAGS) -Wl,--whole-archive $(CT_ARCHIVE) -Wl,--no-whole-archive $(DEP_LIBS)

$(CT_APP)/leak: tools/ct/leak.c $(CT_FLAGS_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CT_CFLAGS) -o $@ $<

check-ct: $(CT_APP)/clean $(CT_APP)/leak ## Fail unless memcheck sees a planted leak and not the checks of Finished and of a binder
ifeq ($(OS_NAME), Linux)
	@out=$$(LD_LIBRARY_PATH="$(TEST_LD_PATH)" valgrind --error-exitcode=1 --leak-check=no --undef-value-errors=yes $(CT_APP)/clean 2>&1); \
	rc=$$?; \
	if [ $$rc -ne 0 ]; then \
		printf 'check-ct: the check of Finished or of a binder was reported (or the harness failed, rc %s):\n%s\n' "$$rc" "$$out" >&2; \
		exit 1; \
	fi
	@out=$$(valgrind --error-exitcode=1 --leak-check=no --undef-value-errors=yes $(CT_APP)/leak 2>&1); \
	rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		printf 'check-ct: the planted secret branch was not reported, so this gate is measuring nothing\n%s\n' "$$out" >&2; \
		exit 1; \
	fi
	@printf 'check-ct: a secret branch is reported, and the checks of Finished and of a binder are not\n'
else
	@printf 'check-ct: skipped (Linux only)\n'
endif

####################################################################
# Symbols
####################################################################

check-symbols: $(APP_DIR)/$(TARGET) ## Fail if any exported symbol lacks the version namespace
ifeq ($(OS_NAME), Linux)
	@leaked=$$(nm -D --defined-only $(APP_DIR)/$(TARGET) \
		| awk '$$2 ~ /^[TDBR]$$/ {print $$3}' \
		| grep -v '^$(LIBVER_SYMBOL)_' | grep -v '^_' || true); \
	if [ -n "$$leaked" ]; then \
		printf '### Exported symbols missing the $(LIBVER_SYMBOL)_ namespace ###\n%s\n' "$$leaked" >&2; \
		exit 1; \
	fi
	@unexported=$$(find include -name '*.h' -exec awk '/^#if DOXYGEN/{d=1} d==0 && /^[a-z_][A-Za-z0-9_ ]*\**[[:space:]]*gtls_[a-z0-9_]+[[:space:]]*\(/{print FILENAME": "$$0} /^#endif/{d=0}' {} + \
		| grep -vE 'typedef|static inline' || true); \
	if [ -n "$$unexported" ]; then \
		printf '### Public declarations without GTLS_API ###\n%s\n' "$$unexported" >&2; \
		exit 1; \
	fi
	@split=$$(nm -D --undefined-only $(APP_DIR)/$(TARGET) \
		| awk '{print $$2}' | grep '^$(LIBVER_SYMBOL)_' || true); \
	if [ -n "$$split" ]; then \
		printf '### Renamed but undefined - a split symbol ###\n%s\n' "$$split" >&2; \
		exit 1; \
	fi
	@nomacros=$$(find include src -name '*.h' \
		! -name 'libver.h' ! -name 'libver_gen.h' ! -name 'namespace.h' ! -name 'macros.h' \
		-exec grep -L '#include <ghoti.io/tls/macros.h>' {} + || true); \
	if [ -n "$$nomacros" ]; then \
		printf '### Headers that do not include macros.h ###\n%s\n' "$$nomacros" >&2; \
		exit 1; \
	fi
	@badguards=$$(find include src -name '*.h' -exec awk 'FNR==1{d=0} !d && /^#ifndef/{print $$2; d=1}' {} + \
		| awk '$$1 !~ /^GHOTI_IO_GTLS_/ {print $$1}' || true); \
	if [ -n "$$badguards" ]; then \
		printf '### Include guards with the wrong prefix ###\n%s\n' "$$badguards" >&2; \
		exit 1; \
	fi
	@dupguards=$$(find include src -name '*.h' -exec awk 'FNR==1{d=0} !d && /^#ifndef/{print $$2; d=1}' {} + \
		| sort | uniq -d || true); \
	if [ -n "$$dupguards" ]; then \
		printf '### Headers sharing an include guard ###\n%s\n' "$$dupguards" >&2; \
		exit 1; \
	fi
	@printf 'Every exported symbol carries the %s_ namespace.\n' "$(LIBVER_SYMBOL)"
else
	@printf 'check-symbols: skipped (Linux only)\n'
endif

test: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES) $(TEST_GATES) ## Build and run the tests
	@for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		printf '\n### Running %s ###\n\n' "$$test_name"; \
		LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$test_exe --gtest_brief=1 || exit 1; \
	done

test-quiet: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES) ## Run tests, one line per suite
	@total_tests=0; total_passed=0; total_failed=0; total_time=0; failed_suites=""; any_failed=0; \
	printf '\n%-30s %8s %10s %s\n' "Test Suite" "Tests" "Time" "Status"; \
	for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		output=$$(LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$test_exe --gtest_brief=1 2>&1); \
		exit_code=$$?; \
		num_tests=$$(echo "$$output" | grep -oP '\[\s*=+\s*\]\s*\K\d+(?=\s+tests?)' | head -1); \
		time_ms=$$(echo "$$output" | grep -oP '\(\K\d+(?=\s*ms\s*total\))' | head -1); \
		[ -z "$$num_tests" ] && num_tests=0; \
		[ -z "$$time_ms" ] && time_ms=0; \
		total_tests=$$((total_tests + num_tests)); \
		total_time=$$((total_time + time_ms)); \
		if [ $$exit_code -eq 0 ]; then \
			total_passed=$$((total_passed + num_tests)); \
			printf '%-30s %8d %8dms PASS\n' "$$test_name" "$$num_tests" "$$time_ms"; \
		else \
			any_failed=1; \
			failures=$$(echo "$$output" | grep -oP '\[\s*FAILED\s*\]\s*\K\d+' | head -1); \
			[ -z "$$failures" ] && failures=$$num_tests; \
			[ "$$failures" -eq 0 ] && failures=1; \
			total_failed=$$((total_failed + failures)); \
			total_passed=$$((total_passed + num_tests - failures)); \
			printf '%-30s %8d %8dms FAIL (exit %d)\n' "$$test_name" "$$num_tests" "$$time_ms" "$$exit_code"; \
			failed_suites="$$failed_suites\n=== $$test_name FAILURES ===\n$$output\n"; \
		fi; \
	done; \
	if [ $$any_failed -eq 0 ]; then \
		printf '%-30s %8d %6dms PASS\n\n' "TOTAL" "$$total_tests" "$$total_time"; \
	else \
		printf '%-30s %8d %6dms FAIL (%d failed)\n' "TOTAL" "$$total_tests" "$$total_time" "$$total_failed"; \
		printf '%s\n' "$$failed_suites"; \
		exit 1; \
	fi

test-valgrind: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES) ## Run the tests under Valgrind
ifeq ($(OS_NAME), Linux)
	@for test_exe in $(TEST_EXECUTABLES); do \
		printf '\n### Valgrind %s ###\n\n' "$$(basename $$test_exe)"; \
		LD_LIBRARY_PATH="$(TEST_LD_PATH)" valgrind $(VALGRIND_FLAGS) $$test_exe --gtest_brief=1 || exit 1; \
	done
else
	@printf 'Valgrind is only available on Linux\n' >&2; exit 1
endif

test-valgrind-quiet: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES) ## Valgrind, one line per suite
ifeq ($(OS_NAME), Linux)
	@total_tests=0; total_failed=0; total_time=0; failed_suites=""; \
	printf '\n%-30s %8s %10s %s\n' "Test Suite (Valgrind)" "Tests" "Time" "Status"; \
	for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		output=$$(LD_LIBRARY_PATH="$(TEST_LD_PATH)" valgrind $(VALGRIND_FLAGS) $$test_exe --gtest_brief=1 2>&1); \
		exit_code=$$?; \
		num_tests=$$(echo "$$output" | grep -oP '\[\s*=+\s*\]\s*\K\d+(?=\s+tests?)' | head -1); \
		time_ms=$$(echo "$$output" | grep -oP '\(\K\d+(?=\s*ms\s*total\))' | head -1); \
		[ -z "$$num_tests" ] && num_tests=0; \
		[ -z "$$time_ms" ] && time_ms=0; \
		total_tests=$$((total_tests + num_tests)); \
		total_time=$$((total_time + time_ms)); \
		has_leak=$$(echo "$$output" | grep -c "are definitely lost\|are indirectly lost\|are possibly lost" || true); \
		if [ $$exit_code -eq 0 ] && [ $$has_leak -eq 0 ]; then \
			printf '%-30s %8d %8dms PASS\n' "$$test_name" "$$num_tests" "$$time_ms"; \
		else \
			total_failed=$$((total_failed + 1)); \
			printf '%-30s %8d %8dms FAIL\n' "$$test_name" "$$num_tests" "$$time_ms"; \
			failed_suites="$$failed_suites\n=== $$test_name ===\n$$output\n"; \
		fi; \
	done; \
	if [ $$total_failed -eq 0 ]; then \
		printf '%-30s %8d %6dms PASS\n\n' "TOTAL" "$$total_tests" "$$total_time"; \
	else \
		printf '%-30s %8d %6dms FAIL (%d suites)\n' "TOTAL" "$$total_tests" "$$total_time" "$$total_failed"; \
		printf '%s\n' "$$failed_suites"; \
		exit 1; \
	fi
else
	@printf 'Valgrind is only available on Linux\n' >&2; exit 1
endif

####################################################################
# ASan + UBSan, in their own tree
####################################################################

UBSAN_CHECKS := undefined,float-cast-overflow
ASAN_UBSAN_FLAGS := -fsanitize=address,$(UBSAN_CHECKS) -fno-sanitize-recover=$(UBSAN_CHECKS) -fno-omit-frame-pointer -g -O1
COV_BUILD_DIR := ./build/$(BUILD)-cov
ASAN_BUILD_DIR := ./build/$(BUILD)-asan
ASAN_OBJ_DIR := $(ASAN_BUILD_DIR)/objects
ASAN_FLAGS_STAMP := $(ASAN_OBJ_DIR)/.flags
ASAN_APP_DIR := $(ASAN_BUILD_DIR)/apps
ASAN_LIBOBJECTS := $(patsubst src/%.c,$(ASAN_OBJ_DIR)/%.o,$(SOURCES))
ASAN_DEPFILES := $(ASAN_LIBOBJECTS:.o=.d) \
    $(foreach pair,$(TEST_PAIRS),$(ASAN_OBJ_DIR)/tests/$(basename $(notdir $(word 1,$(subst |, ,$(pair))))).d)
-include $(ASAN_DEPFILES)
ASAN_ARCHIVE := $(ASAN_APP_DIR)/$(STATIC_TARGET)
ASAN_TLSLIBRARY := -Wl,--whole-archive $(ASAN_ARCHIVE) -Wl,--no-whole-archive $(DEP_LIBS)
ASAN_CFLAGS := $(CFLAGS) $(ASAN_UBSAN_FLAGS) -DGTLS_BUILD
ASAN_CXXFLAGS := $(CXXFLAGS) $(ASAN_UBSAN_FLAGS)
ASAN_LDFLAGS := $(LDFLAGS) $(ASAN_UBSAN_FLAGS)
ifeq ($(UNAME_S), Linux)
	ASAN_CFLAGS += -fPIC
endif

$(ASAN_OBJ_DIR)/%.o: src/%.c $(ASAN_FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CC) $(ASAN_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(ASAN_ARCHIVE): $(ASAN_LIBOBJECTS)
	@mkdir -p $(@D)
	@rm -f $@
	ar rcs $@ $^

$(ASAN_OBJ_DIR)/tests/%.o: tests/%.cpp $(ASAN_FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) $(INCLUDE) -Itests -DGTLS_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(ASAN_OBJ_DIR)/tests/%.o: tests/unit/%.cpp $(ASAN_FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) $(INCLUDE) -Itests -DGTLS_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

define asan-test-executable-rule
ASAN_TEST_OBJ_$1 := $(ASAN_OBJ_DIR)/tests/$(basename $(notdir $1)).o

$(ASAN_APP_DIR)/$2$(EXE_EXTENSION): $$(ASAN_TEST_OBJ_$1) $(ASAN_ARCHIVE)
	@mkdir -p $$(@D)
	$(CXX) $(ASAN_CXXFLAGS) -o $$@ $$(ASAN_TEST_OBJ_$1) $(ASAN_LDFLAGS) $(ASAN_TLSLIBRARY) $(DEP_LIBS) $(TESTFLAGS)
endef

$(foreach pair,$(TEST_PAIRS),\
	$(eval $(call asan-test-executable-rule,$(word 1,$(subst |, ,$(pair))),$(word 2,$(subst |, ,$(pair))))))

ASAN_TEST_EXECUTABLES := $(addprefix $(ASAN_APP_DIR)/,$(addsuffix $(EXE_EXTENSION),$(TEST_NAMES)))
ASAN_RUNTIME := $(shell $(CC) -print-file-name=libasan.so 2>/dev/null)

test-asan: $(ASAN_TEST_EXECUTABLES) ## Build with ASan+UBSan and run the tests
	@for test_exe in $(ASAN_TEST_EXECUTABLES); do \
		printf '\n### ASan+UBSan %s ###\n\n' "$$(basename $$test_exe)"; \
		LD_PRELOAD="$(ASAN_RUNTIME)$${LD_PRELOAD:+:$$LD_PRELOAD}" \
		LD_LIBRARY_PATH="$(ASAN_APP_DIR):$(LIB_INSTALL_PATH)/$(SUITE)" \
			$$test_exe --gtest_brief=1 || exit 1; \
	done
	@printf '\nASan+UBSan suite clean.\n'

####################################################################
# Fuzzing
####################################################################

FUZZ_CC ?= clang
FUZZ_CXX ?= clang++
FUZZ_CC_OK := $(shell which $(FUZZ_CC) 2>/dev/null)
# -fno-sanitize-recover is not optional here. Without it UBSan prints the
# diagnostic and the run continues, libFuzzer sees no crash, and `make fuzz`
# exits 0 with undefined behaviour in the log: a campaign that cannot fail.
# ASan aborts on its own, so only the UBSan half needed saying.
# implicit-conversion is clang's and not GCC's, so it cannot go in
# UBSAN_CHECKS, which the GCC-built ASan tree shares: `-fsanitize=` rejects
# the name outright there. The fuzz tree is clang, so it gets it, probed the
# same way the hardening flags are - a clang without the check must degrade
# rather than fail to build. It catches the narrowing this code does by the
# thousand, all of it currently explicit; four harnesses were run with it
# enabled and reported nothing.
FUZZ_EXTRA := $(shell printf 'int gtls_fuzz_probe(void);\n' | \
	$(FUZZ_CC) -fsanitize=implicit-conversion -x c -c -o /dev/null - \
	>/dev/null 2>&1 && printf '%s' '-fsanitize=implicit-conversion -fno-sanitize-recover=implicit-conversion')
FUZZ_SAN := -fsanitize=address,$(UBSAN_CHECKS) \
    -fno-sanitize-recover=$(UBSAN_CHECKS) $(FUZZ_EXTRA) \
    -fno-omit-frame-pointer -g -O1 -fstrict-aliasing
FUZZ_LIB_FLAGS := $(FUZZ_SAN) -fsanitize=fuzzer-no-link
FUZZ_BIN_FLAGS := $(FUZZ_SAN) -fsanitize=fuzzer
FUZZ_DIR := $(BUILD_DIR)/fuzz
FUZZ_OBJ_DIR := $(FUZZ_DIR)/objects
FUZZ_FLAGS_STAMP := $(FUZZ_OBJ_DIR)/.flags
FUZZ_APP_DIR := $(FUZZ_DIR)/apps
FUZZ_OBJECTS := $(patsubst src/%.c,$(FUZZ_OBJ_DIR)/%.o,$(SOURCES))
FUZZ_CORPUS := tests/fuzz/corpus
FUZZ_TIME ?= 60

FUZZ_DEPFILES := $(patsubst src/%.c,$(FUZZ_OBJ_DIR)/%.d,$(SOURCES))
-include $(FUZZ_DEPFILES)

$(FUZZ_OBJ_DIR)/%.o: src/%.c $(FUZZ_FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	@$(FUZZ_CC) $(FUZZ_LIB_FLAGS) -std=c17 -w $(INCLUDE) -DGTLS_BUILD \
		-MMD -MP -MF $(@:.o=.d) -c $< -o $@

define fuzz-rule
fuzz-$2: $$(FUZZ_APP_DIR)/$1 ## Build the $2 fuzzer

$$(FUZZ_APP_DIR)/$1: tests/fuzz/$1.cpp $$(FUZZ_OBJECTS) $$(FUZZ_FLAGS_STAMP) | $(LIBVER_GEN)
	@if [ -z "$$(FUZZ_CC_OK)" ]; then \
		echo "fuzzing requires $$(FUZZ_CXX)"; \
		exit 1; \
	fi
	@mkdir -p $$(@D) $$(FUZZ_CORPUS)/$2
	$$(FUZZ_CXX) $$(FUZZ_BIN_FLAGS) -std=c++20 -w $$(INCLUDE) -DGTLS_TEST_DATA=\"$$(TEST_DATA)\" \
		-o $$@ $$< $$(FUZZ_OBJECTS) $(DEP_LIBS)

fuzz-run-$2: $$(FUZZ_APP_DIR)/$1 ## Run the $2 fuzzer for $$(FUZZ_TIME) seconds
	@mkdir -p $$(FUZZ_CORPUS)/$2
	@LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$(FUZZ_APP_DIR)/$1 $$(FUZZ_CORPUS)/$2 \
		-max_total_time=$$(FUZZ_TIME) -print_final_stats=1
endef

$(eval $(call fuzz-rule,fuzz_msg,msg))
$(eval $(call fuzz-rule,fuzz_client,client))
$(eval $(call fuzz-rule,fuzz_server,server))
$(eval $(call fuzz-rule,fuzz_record,record))
$(eval $(call fuzz-rule,fuzz_pump,pump))
$(eval $(call fuzz-rule,fuzz_stream,stream))
$(eval $(call fuzz-rule,fuzz_resume,resume))
$(eval $(call fuzz-rule,fuzz_session,session))

FUZZERS := client msg server record pump stream resume session

fuzz: $(addprefix fuzz-run-,$(FUZZERS)) ## Build and run every fuzzer

fuzz-clean: ## Remove the fuzz build
	-@rm -rf $(FUZZ_DIR)

####################################################################
# Install
####################################################################

LDCONF_INSTALL_PATH ?= /etc/ld.so.conf.d
PC_REQUIRES := $(CUTIL_PC) $(SECURITY_PC) $(CERTIFICATE_PC)
PKGCONFIG_INSTALL_PATH ?= $(PC_INSTALL_PATH)

install: all ## Install the library
	@mkdir -p $(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Linux)
	@cp $(APP_DIR)/$(TARGET) $(LIB_INSTALL_PATH)/$(SUITE)/
	@ln -f -s $(TARGET) $(LIB_INSTALL_PATH)/$(SUITE)/$(SO_NAME)
	@ln -f -s $(SO_NAME) $(LIB_INSTALL_PATH)/$(SUITE)/$(BASE_NAME)
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then mkdir -p $(LDCONF_INSTALL_PATH); fi
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then echo "$(LIB_INSTALL_PATH)/$(SUITE)" > $(LDCONF_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).conf; fi
endif
ifeq ($(OS_NAME), Windows)
	@mkdir -p $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH)/$(SUITE)
	@cp $(APP_DIR)/$(TARGET).a $(LIB_INSTALL_PATH)/$(SUITE)/
	@cp $(APP_DIR)/$(TARGET) $(BIN_INSTALL_PATH)/
endif
	@rm -rf $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@mkdir -p $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@if [ -d include/ghoti.io ]; then \
		cp -r include/ghoti.io $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)/ ; \
	fi
	@if [ -d $(GEN_DIR)/ghoti.io ]; then \
		cp -r $(GEN_DIR)/ghoti.io $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)/ ; \
	fi
	@mkdir -p $(PKGCONFIG_INSTALL_PATH)
	@cat pkgconfig/$(SUITE)-$(PROJECT).pc | sed 's/(SUITE)/$(SUITE)/g; s/(PROJECT)/$(PROJECT)/g; s/(BRANCH)/$(BRANCH)/g; s/(VERSION)/$(VERSION)/g; s|(PC_LIB_DIR)|$(PC_LIB_DIR)|g; s|(PC_INCLUDE_DIR)|$(PC_INCLUDE_DIR)|g; s|(REQUIRES)|$(PC_REQUIRES)|g' > $(PKGCONFIG_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).pc
ifeq ($(OS_NAME), Linux)
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then ldconfig >> /dev/null 2>&1; fi
endif
	@echo "Ghoti.io $(PROJECT)$(BRANCH) installed"

uninstall: ## Delete the installed files
ifeq ($(OS_NAME), Linux)
	@rm -f $(LIB_INSTALL_PATH)/$(SUITE)/$(BASE_NAME)*
	@rm -f $(LDCONF_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).conf
endif
ifeq ($(OS_NAME), Windows)
	@rm -f $(LIB_INSTALL_PATH)/$(SUITE)/$(TARGET).a
	@rm -f $(BIN_INSTALL_PATH)/$(TARGET)
endif
	@rm -rf $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@rm -f $(PKGCONFIG_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).pc
ifeq ($(OS_NAME), Linux)
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then ldconfig >> /dev/null 2>&1; fi
endif
	@echo "Ghoti.io $(PROJECT)$(BRANCH) has been uninstalled"

debug: ## Build in DEBUG mode
	make all BUILD=debug

install-debug: ## Install the DEBUG library
	make install BUILD=debug

uninstall-debug: ## Uninstall the DEBUG library
	make uninstall BUILD=debug

test-debug: ## Run the tests in DEBUG mode
	make test BUILD=debug

test-valgrind-debug: ## Valgrind in DEBUG mode
	make test-valgrind BUILD=debug

watch-debug: ## Watch and rebuild in DEBUG mode
	make watch BUILD=debug

test-watch-debug: ## Watch and test in DEBUG mode
	make test-watch BUILD=debug

docs: ## Generate documentation under docs/
	doxygen

docs-pdf: docs ## Generate the PDF manual
	cd ./docs/latex/ && make
	mv -f ./docs/latex/refman.pdf ./docs/$(SUITE)-$(PROJECT)$(BRANCH)-docs.pdf

cloc: ## Count the lines of code used in the project
	cloc src include tests Makefile

coverage: ## Build instrumented, run the tests, and report line coverage
	@rm -rf $(COV_BUILD_DIR)/objects/*.gcda \
		$(COV_BUILD_DIR)/objects/*/*.gcda 2> /dev/null || true
	@status=0; \
	$(MAKE) --no-print-directory test TEST_GATES= \
		BUILD_DIR=$(COV_BUILD_DIR) \
		EXTRA_CFLAGS="--coverage -O0 -fprofile-update=atomic" \
		EXTRA_LDFLAGS="--coverage" > /dev/null || status=$$?; \
	if [ $$status -eq 0 ]; then \
		tools/coverage.sh $(COV_BUILD_DIR)/objects || status=$$?; \
	else \
		printf 'coverage: the instrumented test run failed; no report\n' >&2; \
	fi; \
	exit $$status

clean: ## Remove the build directories
	-@rm -rf ./build

help: ## Display this help
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' Makefile | sort | sed 's/\([^:]*\):.*## \(.*\)/\1:\2/' | awk -F: '{printf "%-22s %s\n", $$1, $$2}'

####################################################################
# Flag stamps. At the end so they are not the default goal, and so the
# directories they name have already been assigned.
####################################################################

.PHONY: force-flags

$(FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CXX) $(LIB_CFLAGS) $(CFLAGS) $(CXXFLAGS) $(LDFLAGS) $(INCLUDE) $(TEST_DATA) $(TLSLIBRARY) $(DEP_LIBS) $(TESTFLAGS) $(TEST_LDFLAGS) $(OS_SPECIFIC_LIBRARY_NAME_FLAG)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

$(ASAN_FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CXX) $(ASAN_CFLAGS) $(ASAN_CXXFLAGS) $(ASAN_LDFLAGS) $(INCLUDE) $(TEST_DATA) $(ASAN_TLSLIBRARY) $(DEP_LIBS) $(TESTFLAGS)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

$(CT_FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CT_CFLAGS) $(INCLUDE) $(LDFLAGS) $(DEP_LIBS)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

$(FUZZ_FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(FUZZ_CC) $(FUZZ_CXX) $(FUZZ_SAN) $(FUZZ_LIB_FLAGS) $(FUZZ_BIN_FLAGS) $(INCLUDE) $(TEST_DATA) $(DEP_LIBS)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@
