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

path_base    := /nvme/data/tmp
path_bg_pids := tmp/pids                  # backgrounded pids found here

# Rocksdb App parameters
rocksdb_app_threads    := 18
rocksdb_app_read_ratio := 0.5
cpus_rocksdb_app       := 30-70
path_rocksdb           := $(path_base)/bpf-sql/rocksdb-app # rocksdb app writes here
bin_rocksdb_app        := ./rocksdb-application/target/release/rocksdb-application


bin_syscall         := ./syscall-latency/target/release/syscall-latency


###############
## Functions ##
###############

pprint := printf "+ %s\n"

define bg
	$(shell stty sane)
	$(shell $(1) > tmp/log-$@ 2>&1 & \
		echo $@,$$! >> $(path_bg_pids))
	$(shell stty sane)
	$(pprint) "Running $@"
	$(pprint) "Outputting to tmp/log-$@"
endef

#################
## Run Targets ##
#################


.PHONY: rocksdb-application
rocksdb-application:
	$(call bg, \
		taskset -c $(cpus_rocksdb_app) \
			$(bin_rocksdb_app) \
			--threads $(rocksdb_app_threads) \
			--read-ratio $(rocksdb_app_read_ratio) \
			--db-path $(path_rocksdb))


.PHONY: syscall-latency-rocksdb
syscall-latency-rocksdb: do-sudo
	$(call bg, sudo $(bin_syscall) --pid $$(pgrep rocksdb-applica))

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
	test ! -e $(path_bg_pids) && $(pprint) "$(path_bg_pids) does not exist" || true

	test -e $(path_bg_pids) && \
		test $$(cut $(path_bg_pids) -d, -f2 | wc -l) -eq 0 && \
		$(pprint) "No pids found" || \
		true

	test -e $(path_bg_pids) && \
		test $$(cut $(path_bg_pids) -d, -f2 | wc -l) -gt 0 && \
		( \
			$(pprint) "Killing the following pids"; \
			cat $(path_bg_pids) | xargs $(pprint); \
			cut $(path_bg_pids) -d, -f2 | xargs kill -9 \
		) ; \
		rm -f $(path_bg_pids)

	$(pprint) \
		"verify no stray processes (make ps)"

	$(pprint) \
		"clean files (make clean-files)"

.PHONY: clean-files
clean-files:
	rm -rf $(path_rocksdb)

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
