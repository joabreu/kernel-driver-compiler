#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/stack.h"

struct list *list_new(void)
{
	struct list *list;

	list = calloc(1, sizeof(*list));
	assert(list);

	return list;
}

void list_free(struct list *list)
{
	if (list->size)
		free(list->items);
	free(list);
}

int list_size(const struct list *list)
{
	return list->size;
}

void list_append(struct list *list, void *item)
{
	list->size++;

	list->items = realloc(list->items, list->size * sizeof(item));
	assert(list->items);

	list->items[list->size - 1] = item;
}

void list_push(struct list *list, void *item)
{
	void **new_items = calloc(list->size + 1, sizeof(item));

	assert(new_items);

	list->size++;
	memcpy(new_items + 1, list->items, (list->size - 1) * sizeof(item));

	if (list->items)
		free(list->items);

	list->items = new_items;
	list->items[0] = item;
}

void *list_pop(struct list *list)
{
	void *item = list->items[list->size - 1];

	list->size--;
	list->items = realloc(list->items, list->size * sizeof(item));

	return item;
}

void *list_get(struct list *list, int idx)
{
	return list->items[idx];
}

struct node *mknode(struct node *left, struct node *right, const char *token, int type)
{
	struct node *node = malloc(sizeof(*node));

	assert(node);

	node->left = left;
	node->right = right;
	node->token = strdup(token);
	node->type = type;

	return node;
}
