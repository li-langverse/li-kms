# Convenience targets to build the KMS externs and run the pure-Li selftests.
#
# Required (easiest when the lic CI/VM is available):
#   LIC      : path to the lic compiler binary (default: /agent/repos/lic/build/compiler/lic/lic)
#   LI_RT_LIB: path to the lic runtime static lib (libli_rt.a), native or interpreted
#   LI_NATIVE_RT: set to 1 to link the native runtime
#
# The KMS externs below are compiled separately so the repo is self-contained:
# lic links them via LI_RT_LIBS.
CC ?= cc
CFLAGS ?= -O2 -std=c11
LIC ?= /agent/repos/lic/build/compiler/lic/lic
LI_RT_LIB ?=
LI_NATIVE_RT ?= 0
BUILD := build
RT_LIB := $(BUILD)/librt_crypto.a
SELFTESTS := kms_core kms_envelope kms_exploits kms_persist kms_policy kms_ratelimit

export LI_RT_LIB
export LI_NATIVE_RT

all: $(RT_LIB)

# C-level parity check: drives runtime/li_rt_crypto.c through the same
# scenarios as the Li selftests — no lic toolchain needed.
verify: $(RT_LIB)
	$(CC) $(CFLAGS) -Iruntime tests/kms_verify.c runtime/li_rt_crypto.c runtime/vendor/monocypher/monocypher.c -o $(BUILD)/kms_verify
	./$(BUILD)/kms_verify

$(BUILD):
	mkdir -p $(BUILD)

$(RT_LIB): $(BUILD) runtime/li_rt_crypto.c runtime/vendor/monocypher/monocypher.c
	$(CC) $(CFLAGS) -Iruntime -c runtime/li_rt_crypto.c -o $(BUILD)/li_rt_crypto.o
	$(CC) $(CFLAGS) -Iruntime -c runtime/vendor/monocypher/monocypher.c -o $(BUILD)/monocypher.o
	ar rcs $@ $(BUILD)/li_rt_crypto.o $(BUILD)/monocypher.o

define build_prog
$(BUILD)/$(1): src/$(1).li $(RT_LIB)
	LI_RT_LIBS="$(RT_LIB)" $(LIC) build src/$(1).li -o $(BUILD)/$(1)
endef

$(foreach t,$(SELFTESTS),$(eval $(call build_prog,$(t))))

test: $(foreach t,$(SELFTESTS),$(BUILD)/$(t))
	@for t in $(SELFTESTS); do \
		echo "== $$t"; \
		./$(BUILD)/$$t || { echo "FAIL: $$t"; exit 1; }; \
	done
	@echo "all $(words $(SELFTESTS)) selftests passed"

# HTTP API smoke: start kms_server.li on :54400, hit the endpoints, kill it.
test-http: $(BUILD)/kms_server
	./$(BUILD)/kms_server & pid=$$!; \
	trap 'kill $$pid 2>/dev/null' EXIT; \
	sleep 1; \
	echo "== health";  curl -s http://127.0.0.1:54400/health; echo; \
	echo "== encrypt"; CT=$$(printf 'hello' | base64 | tr -d '\n'); \
	RESP=$$(curl -s -X POST http://127.0.0.1:54400/encrypt -d "$$CT"); echo "  -> $$RESP"; \
	MAC=$${RESP%%:*}; CT64=$${RESP#*:}; \
	echo "== decrypt"; curl -s -X POST http://127.0.0.1:54400/decrypt -d "$$MAC:$$CT64"; echo; \
	kill $$pid 2>/dev/null; wait $$pid 2>/dev/null; \
	trap - EXIT

$(BUILD)/kms_server: src/kms_server.li $(RT_LIB)
	LI_RT_LIBS="$(RT_LIB)" $(LIC) build src/kms_server.li -o $(BUILD)/kms_server

clean:
	rm -rf $(BUILD)

.PHONY: all test test-http verify clean
