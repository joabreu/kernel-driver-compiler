TARGETS = $(wildcard $(CURDIR)/*/*.mk)
CLEAN_TARGETS = $(addprefix clean-,$(TARGETS))
HELPER = $(CURDIR)/Makefile.helper
INCLUDE_DIRS = $(CURDIR)/common /opt/homebrew/include
CCFLAGS += $(foreach dir,$(INCLUDE_DIRS),$(if $(wildcard $(dir)), -I$(dir)))
O ?= $(CURDIR)/build

export GCC=gcc
export BISON=bison
export LEX=flex
export HELPER
export CCFLAGS
export O

all: $(TARGETS)
clean: $(CLEAN_TARGETS)
.PHONY: clean

$(O):
	@mkdir -p $(O)

# Build all targets
$(TARGETS): $(O)
	@mkdir -p $(O)/$(shell basename $(shell dirname $@))
	@$(MAKE) --no-builtin-rules -f $(HELPER) \
		-C $(shell dirname $@) \
		input_spec=$@ \
		out=$(O)/$(shell basename $(shell dirname $@)) \
		all
.PHONY: $(TARGETS)

# Clean all targets
$(CLEAN_TARGETS): $(O)
	@mkdir -p $(O)/$(shell basename $(shell dirname $(subst clean-,,$@)))
	@$(MAKE) --no-builtin-rules -f $(HELPER) \
		-C $(shell dirname $(subst clean-,,$@)) \
		input_spec=$(subst clean-,,$@) \
		out=$(O)/$(shell basename $(shell dirname $(subst clean-,,$@))) \
		clean
