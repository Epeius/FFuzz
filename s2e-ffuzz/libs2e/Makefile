
TARGETS := $(wildcard *-softmmu)

all: $(TARGETS)
.PHONY: $(TARGETS)

libcoroutine/src/libcoroutine.a:
	$(MAKE) -C libcoroutine

libq/src/libq.a:
	$(MAKE) -C libq

libse/src/libse.a:
	$(MAKE) -C libse

$(TARGETS): libse/src/libse.a libq/src/libq.a libcoroutine/src/libcoroutine.a
	$(MAKE) -C $@

clean:
	for f in $(TARGETS) libse libq libcoroutine; do $(MAKE) -C $$f clean; done
