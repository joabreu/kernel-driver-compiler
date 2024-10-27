TARGETS = $(wildcard $(CURDIR)/*/*.mk)
CLEAN_TARGETS = $(addprefix clean-,$(TARGETS))
HELPER = $(CURDIR)/Makefile.helper
CCFLAGS = -I $(CURDIR)/common
O = $(CURDIR)/build

export GCC=gcc
export BISON=bison
export FLEX=flex
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
# Clean all targets
$(CLEAN_TARGETS): $(O)
	@mkdir -p $(O)/$(shell basename $(shell dirname $(subst clean-,,$@)))
	@$(MAKE) --no-builtin-rules -f $(HELPER) \
		-C $(shell dirname $(subst clean-,,$@)) \
		input_spec=$(subst clean-,,$@) \
		out=$(O)/$(shell basename $(shell dirname $(subst clean-,,$@))) \
		clean
