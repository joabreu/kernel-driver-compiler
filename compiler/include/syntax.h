#ifndef __SYNTAX_H__
#define __SYNTAX_H__

#define MAX_ARRAY_SIZE	0x18

#include "global.h"
#include "stack.h"

void program_parse(struct node *head);
void program_dump(struct list *sections);
void program_dump_raw(__u32 *data, long size);
void program_write(FILE *dest, struct kdc_header *header, const time_t *timestamp,
		   struct list *sections, struct list *params);

#endif /* __SYNTAX_H__ */
