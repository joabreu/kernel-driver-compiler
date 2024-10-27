#ifndef __STACK_H__
#define __STACK_H__

#include <stdbool.h>

struct list {
	int size;
	void **items;
};

enum {
	TYPE_UND = 0,
	TYPE_APP,
	TYPE_INF,
	TYPE_VER,
	TYPE_AUX,
	TYPE_SEC,
	TYPE_STA,
	TYPE_ARG,
	TYPE_VAL,
	TYPE_TYD,
	TYPE_VAA,
	TYPE_REG,
	TYPE_IRG,
	TYPE_FUN,
	TYPE_ID,
	TYPE_IDA,
	TYPE_IFE,
	TYPE_IFC,
	TYPE_OPE,
	TYPE_SET,
	TYPE_STM,
	TYPE_DEF,
	TYPE_WHI,
	TYPE_BRK,
	TYPE_RET,
	TYPE_STR,
	TYPE_ARR,
	TYPE_ARV,
};

struct node {
	struct node *left;
	struct node *right;
	char *token;
	int type;
};

struct code {
	int id;
	char *name;
	struct list *insts;
	struct list *args;
	struct list *types;
	struct list *arrays;
};

struct variable {
	char *name;
	void *content;
};

struct list *list_new(void);
void list_free(struct list *list);
int list_size(const struct list *list);
void list_append(struct list *list, void *item);
void list_push(struct list *list, void *item);
void *list_pop(struct list *list);
void *list_get(struct list *list, int idx);
struct node *mknode(struct node *left, struct node *right, const char *token, int type);

#endif /* __STACK_H__ */
