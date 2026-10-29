CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong
.PHONY: all check clean Greeter

all: greeter_safe

greeter_safe: greeter_safe.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

# test_safe.py: the safe bytearray-model/comparison suite.
# test_exploit.py: runs the supplied Greeter binary against the generated
# exploit payload (myRes.txt) and checks it actually spawns a shell that
# runs commands. Both use only the committed, prebuilt Greeter/shellcode_test
# binaries; neither builds anything vulnerable from source here.
check: greeter_safe
	python3 -m unittest -v test_safe test_exploit

# shellcode_test.c needs a 32-bit x86 toolchain (gcc-multilib on Debian/
# Ubuntu: `apt-get install gcc-multilib libc6-dev-i386`), which this
# project's Docker sandbox does not have. The committed `shellcode_test`
# binary was built elsewhere with:
#   gcc-12 -m32 -static -Wall -Wextra -O2 -o shellcode_test shellcode_test.c
# This target is for a machine that does have that toolchain.
shellcode_test: shellcode_test.c
	$(CC) -m32 -static -std=c11 -O2 -Wall -Wextra -o $@ $<

# Greeter.c is the historical, intentionally vulnerable source; use the
# supplied precompiled Greeter binary instead (per the assignment brief:
# non-PIE, static, fixed addresses). This target intentionally refuses to
# rebuild it with the original (protection-disabling) flags.
Greeter:
	@echo 'Rebuilding the vulnerable Greeter from source is not needed: use the supplied precompiled binary (see Readme.md).' >&2
	@exit 1

clean:
	rm -f greeter_safe
