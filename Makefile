################################################
## Makefile configuration flags and variables ##
################################################

MAKEFLAGS=--warn-undefined-variables

# define the variable V to make verbose (e.g., make [target] V=1)
ifndef V
.SILENT:
endif

###############
## VARIABLES ##
###############

PATH_BASE    := /nvme/data/tmp
PATH_BG_PIDS := tmp/pids                  # backgrounded pids found here

# Rocksdb App parameters

ROCKSDB_APP_THREADS    := 18
ROCKSDB_APP_READ_RATIO := 0.5
CPUS_ROCKSDB_APP       := 30-70
PATH_ROCKSDB           := $(PATH_BASE)/bpf-sql/rocksdb-app # rocksdb app writes here
BIN_ROCKSDB_APP        := ./rocksdb-application/target/release/rocksdb-application

# syscall latency application parameters

BIN_SYSCALL            := ./syscall-latency/target/release/syscall-latency

###############
## Functions ##
###############

pprint := printf "+ %s\n"

define bg
	$(shell stty sane)
	$(shell $(1) > tmp/log-$@ 2>&1 & \
		echo $@,$$! >> $(PATH_BG_PIDS))
	$(shell stty sane)
	$(pprint) "Running $@"
	$(pprint) "Outputting to tmp/log-$@"
endef

#################
## Run Targets ##
#################

.PHONY: rocksdb-application
rocksdb-application: tmp-dir
	$(call bg, \
		taskset -c $(CPUS_ROCKSDB_APP) \
			$(BIN_ROCKSDB_APP) \
			--threads $(ROCKSDB_APP_THREADS) \
			--read-ratio $(ROCKSDB_APP_READ_RATIO) \
			--db-path $(PATH_ROCKSDB))


.PHONY: syscall-latency-rocksdb
syscall-latency-rocksdb: tmp-dir do-sudo
	$(call bg, sudo $(BIN_SYSCALL) --pid $$(pgrep rocksdb-applica))

###################
## Build targets ##
###################

define rust_build
	$(info + building $(1))
	stty sane
	$(eval $@_r = \
		$(shell cd $(1); \
			cargo build --release $(2) >../tmp/build-$(1) 2>&1; \
			test $$? -eq 0 && echo foo || echo ; ))
	# stop build if error
	$(if $($@_r),,$(error build $(1) failed))
	stty sane
endef

.PHONY: build-syscall-latency
build-syscall-latency: tmp-dir
	$(call rust_build,syscall-latency,,)

.PHONY: build-rocksdb-application
build-rocksdb-application: tmp-dir
	$(call rust_build,rocksdb-application,,)

#####################
## Utility targets ##
#####################

define rust_clean
	stty sane
	$(info + cleaning $(1))
	$(shell cd $(1); cargo clean)
	stty sane
endef

.PHONY: clean-code
clean-code:
	$(call rust_clean,syscall-latency)
	$(call rust_clean,rocksdb-application)
	rm -rf tmp

.PHONY: stop
stop:
	stty sane
	test ! -e $(PATH_BG_PIDS) && $(pprint) "$(PATH_BG_PIDS) does not exist" || true

	test -e $(PATH_BG_PIDS) && \
		test $$(cut $(PATH_BG_PIDS) -d, -f2 | wc -l) -eq 0 && \
		$(pprint) "No pids found" || \
		true

	test -e $(PATH_BG_PIDS) && \
		test $$(cut $(PATH_BG_PIDS) -d, -f2 | wc -l) -gt 0 && \
		( \
			$(pprint) "Killing the following pids"; \
			cat $(PATH_BG_PIDS) | xargs $(pprint); \
			cut $(PATH_BG_PIDS) -d, -f2 | xargs kill -9 \
		) ; \
		rm -f $(PATH_BG_PIDS)

	$(pprint) \
		"verify no stray processes (make ps)"

	$(pprint) \
		"clean files (make clean-files)"

.PHONY: clean-files
clean-files:
	rm -rf $(PATH_ROCKSDB)

.PHONY: ps
ps:
	ps -U $$(whoami) -o pid,comm,cmd --sort comm

.PHONY: tmp-dir
tmp-dir:
	mkdir -p tmp

.PHONY: do-sudo
do-sudo:
	stty sane
	sudo $(pprint) "confirmed sudo"
	stty sane
