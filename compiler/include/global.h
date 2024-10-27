#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include <stdio.h>
#include "kdc_api.h"
#include "stack.h"

#define KDC_VAL(x)		(htole32(x))
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(*(x)))
#define DIV_ROUND_UP(n, d)	({	\
	typeof(d) __d = (d);		\
	(((n) + (__d) - 1) / (__d));	\
})
#define MIN(a, b)		({	\
	typeof(a) __a = (a);		\
	typeof(b) __b = (b);		\
	(__a < __b) ? __a : __b;	\
})
#define MAX(a, b)		({	\
	typeof(a) __a = (a);		\
	typeof(b) __b = (b);		\
	(__a > __b) ? __a : __b;	\
})
#define INF(__v, __fmt__, ...)		\
	do { \
		if (__v) { \
			printf("INFO at %s[%d]: " __fmt__, __func__, \
			       __LINE__, ##__VA_ARGS__); \
		} \
	} while (0)
#define WAR(__fmt__, ...)		\
	fprintf(stderr, "WARNING at %s[%d]: " __fmt__, __func__, \
		__LINE__, ##__VA_ARGS__)
#define ERR(__fmt__, ...)		\
	do { \
		fprintf(stderr, "ERROR at %s[%d]: " __fmt__, __func__, \
			__LINE__, ##__VA_ARGS__); \
		exit(1); \
	} while (0)

struct context {
	struct node *head;
	struct list *defines;
	struct list *global_types;
	struct list *params;
	struct list *global_arrays;
	struct list *sections;
	bool present_sections[KDC_SECTION_INIT_MAX];
	int unique_id;
	struct kdc_header header;
	FILE *dest;
	bool verbose;
};

extern struct context *ctx;
extern FILE *yyin;

#endif /* __GLOBAL_H__ */
