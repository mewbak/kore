DEFINITION_NAME := priority

include $(CURDIR)/../../../working/include.mk

test: tests/1.test

test-k: tests/1.test

golden: tests/1.output.golden

clean:
	rm -rf $(KOMPILED) tests/*.output

.PHONY: test-k test golden clean %.test %.krun
