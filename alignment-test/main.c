#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdalign.h>
#include <stdbool.h>

typedef struct {
	char a;
	uint32_t b;
	char c;
	char d;
	uint64_t e;
	char f;
} foo_t;

typedef struct {
	uint32_t a;
	foo_t b[6];
	char c;
} bar_t;

int main(void) {
	printf("%lu\n", offsetof(foo_t, a));
	printf("%lu\n", offsetof(foo_t, b));
	printf("%lu\n", offsetof(foo_t, c));
	printf("%lu\n", offsetof(foo_t, d));
	printf("%lu\n", offsetof(foo_t, e));
	printf("%lu\n", offsetof(foo_t, f));
	printf("size %lu\n", sizeof(foo_t));
	printf("alignment %lu\n", alignof(foo_t));

	printf("%lu\n", offsetof(bar_t, a));
	printf("%lu\n", offsetof(bar_t, b));
	printf("%lu\n", offsetof(bar_t, c));
	printf("size %lu\n", sizeof(bar_t));
	printf("alignment %lu\n", alignof(bar_t));

	printf("Bool %lu\n", alignof(bool));
	printf("Hello world\n");
}

