#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "include/global.h"
#include "include/syntax.h"

void yyerror(const char *s);
static void parse_arguments(struct code *code, struct kdc_field *field,
			    int *idx, struct node *node);
static void parse_node(struct code *code, struct node *node);

#define REG_FMT			"r%d"
#define IREG_FMT		"__r%d"

static const struct kdc_operation {
	char *name;
	__u32 id;
	int nargs;
	int type;
	int fmt;
} kdc_ops[] = {
	{
		.name = "JMP",
		.id = KDC_OPERATION_JUMP,
		.nargs = 1, /* min. args */
		.type = TYPE_ID,
	}, {
		.name = "JMP_IFE",
		.id = KDC_OPERATION_JUMP_IFE,
		.nargs = 5,
		.type = TYPE_IFE,
	}, {
		.name = "SET",
		.id = KDC_OPERATION_SET,
		.nargs = 3,
		.type = TYPE_SET,
	}, {
		.name = "SET_M",
		.id = KDC_OPERATION_SET,
		.nargs = 4,
		.type = TYPE_STM,
	}, {
		.name = "BRK",
		.id = KDC_OPERATION_STOP,
		.nargs = 1,
		.type = TYPE_BRK,
	}, {
		.name = "RET",
		.id = KDC_OPERATION_STOP,
		.nargs = 1,
		.type = TYPE_RET,
	}, {
		.name = "STOP",
		.id = KDC_OPERATION_STOP,
		.nargs = 1,
		.type = TYPE_UND,
	}, {
		.name = "SLEEP",
		.id = KDC_OPERATION_SLEEP,
		.nargs = 1,
		.type = TYPE_UND,
	}, {
		.name = "DUMP",
		.id = KDC_OPERATION_DUMP,
		.nargs = 1,
		.type = TYPE_UND,
	}, {
		.name = "WHILE",
		.id = KDC_OPERATION_WHILE,
		.nargs = 5,
		.type = TYPE_WHI,
	}, {
		.name = "PRINT",
		.id = KDC_OPERATION_PRINT,
		.nargs = 1,
		.type = TYPE_UND,
	}, {
		.name = "R_%d",
		.id = KDC_OPERATION_READ_X,
		.nargs = 2,
		.type = TYPE_UND,
		.fmt = true,
	}, {
		.name = "W_%d",
		.id = KDC_OPERATION_WRITE_X,
		.nargs = 2,
		.type = TYPE_UND,
		.fmt = true,
	}, {
		.name = "RMW_%d",
		.id = KDC_OPERATION_RMW_X,
		.nargs = 3,
		.type = TYPE_UND,
		.fmt = true,
	},
};

static const struct kdc_condition {
	char *name;
	__u32 data;
	int args;
} kdc_conds[] = {
	{ .name = "lshift", .data = KDC_COND_LSHIFT, .args = 2 },
	{ .name = "rshift", .data = KDC_COND_RSHIFT, .args = 2 },
	{ .name = "mod", .data = KDC_COND_MOD, .args = 2 },
	{ .name = "div", .data = KDC_COND_DIV, .args = 2 },
	{ .name = "mult", .data = KDC_COND_MULT, .args = 2 },
	{ .name = "minus", .data = KDC_COND_MINUS, .args = 2 },
	{ .name = "plus", .data = KDC_COND_PLUS, .args = 2 },
	{ .name = "or_op", .data = KDC_COND_OR, .args = 2 },
	{ .name = "and_op", .data = KDC_COND_AND, .args = 2 },
	{ .name = "or", .data = KDC_COND_LOR, .args = 2 },
	{ .name = "xor", .data = KDC_COND_LXOR, .args = 2 },
	{ .name = "and", .data = KDC_COND_LAND, .args = 2 },
	{ .name = "ne_op", .data = KDC_COND_NEQ, .args = 2 },
	{ .name = "eq_op", .data = KDC_COND_EQ, .args = 2 },
	{ .name = "ge_op", .data = KDC_COND_GE, .args = 2 },
	{ .name = "le_op", .data = KDC_COND_LE, .args = 2 },
	{ .name = "gt_op", .data = KDC_COND_GT, .args = 2 },
	{ .name = "lt_op", .data = KDC_COND_LT, .args = 2 },
	{ .name = "not_op", .data = KDC_COND_NOT, .args = 1 },
	{ .name = "neg_op", .data = KDC_COND_NEG, .args = 1 },
};

static const struct kdc_operation *kdc_find_op(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(kdc_ops); i++) {
		if (kdc_ops[i].fmt) {
			__u32 idx;

			if (sscanf(name, kdc_ops[i].name, &idx) == 1) {
				assert(idx <= KDC_OPERATION_MASK);
				return &kdc_ops[i];
			}
		} else {
			size_t len = MAX(strlen(kdc_ops[i].name), strlen(name));

			if (!strncmp(kdc_ops[i].name, name, len))
				return &kdc_ops[i];
		}
	}

	return NULL;
}

static const struct kdc_operation *kdc_get_op_id(__u32 inst)
{
	int i;

	if (inst & KDC_OPERATION_X_MASK)
		inst = inst & KDC_OPERATION_X_MASK;

	for (i = 0; i < ARRAY_SIZE(kdc_ops); i++) {
		if (inst == kdc_ops[i].id)
			return &kdc_ops[i];
	}

	ERR("invalid operation ID: '0x%x'\n", inst);
}

static const struct kdc_operation *kdc_get_op_type(int type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(kdc_ops); i++) {
		if (type == kdc_ops[i].type)
			return &kdc_ops[i];
	}

	ERR("operation not found: '0x%x'\n", type);
}

static const struct kdc_condition *kdc_find_condition(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(kdc_conds); i++) {
		size_t len = MAX(strlen(kdc_conds[i].name), strlen(name));

		if (!strncmp(kdc_conds[i].name, name, len))
			return &kdc_conds[i];
	}

	ERR("condition not found: '%s'\n", name);
}

static __u32 kdc_get_reg(const char *name)
{
	__u32 idx;

	if (sscanf(name, REG_FMT, &idx) != 1)
		ERR("invalid register name: '%s'\n", name);

	return idx;
}

static __u32 kdc_get_int_reg(const char *name)
{
	__u32 idx;

	if (sscanf(name, IREG_FMT, &idx) != 1)
		ERR("invalid internal register name: '%s'\n", name);

	return idx;
}

static struct kdc_field *kdc_get_from_list(struct list *list, const char *name)
{
	struct kdc_field *field = NULL;
	int i;

	for (i = 0; i < list_size(list); i++) {
		struct variable *var = (struct variable *)list_get(list, i);
		size_t len = MAX(strlen(var->name), strlen(name));

		if (!strncmp(var->name, name, len)) {
			if (field)
				WAR("found duplicate id '%s'\n", name);
			field = (struct kdc_field *)var->content;
		}
	}

	return field;
}

static struct kdc_section *kdc_get_param(const char *name)
{
	struct kdc_section *section = NULL;
	struct list *list = ctx->params;
	int i;

	for (i = 0; i < list_size(list); i++) {
		struct kdc_section *sec = (struct kdc_section *)list_get(list, i);
		size_t len = MAX(strlen((char *)sec->data), strlen(name));

		if (!strncmp((char *)sec->data, name, len)) {
			if (section)
				WAR("found duplicate id '%s'\n", name);
			section = sec;
		}
	}

	return section;
}

static struct kdc_field *kdc_get_variable(struct code *code, const char *name)
{
	assert(code);
	return kdc_get_from_list(code->args, name);
}

static struct kdc_field *kdc_get_type(struct code *code, const char *name)
{
	struct kdc_field *field = NULL, *g_field = NULL;

	g_field = kdc_get_from_list(ctx->global_types, name);
	if (code)
		field = kdc_get_from_list(code->types, name);

	if (field && g_field)
		WAR("found overwritten id '%s'\n", name);

	return field ? field : g_field;
}

static struct kdc_field *kdc_get_define(const char *name)
{
	return kdc_get_from_list(ctx->defines, name);
}

static struct kdc_field *kdc_get_array(struct code *code, const char *name)
{
	struct kdc_field *field = NULL, *g_field = NULL;

	g_field = kdc_get_from_list(ctx->global_arrays, name);
	if (code)
		field = kdc_get_from_list(code->arrays, name);

	if (field && g_field)
		WAR("found overwritten id '%s'\n", name);

	return field ? field : g_field;
}

static struct kdc_field *kdc_get_identifier(struct code *code, const char *name,
					  const int *idx)
{
	struct kdc_field *field;

	field = kdc_get_type(code, name);
	if (field) {
		if (field->id == TYPE_REG) {
			field->flags = KDC_VAL(KDC_FLAG_NVAL << *idx);
			assert((KDC_FLAG_NVAL << *idx) <= KDC_FLAG_NVAL_MASK);
		} else if (field->id == TYPE_IRG) {
			field->flags = KDC_VAL(KDC_FLAG_NVAL << *idx);
			assert((KDC_FLAG_NVAL << *idx) <= KDC_FLAG_NVAL_MASK);
		} else {
			assert(0);
		}

		return field;
	}

	field = kdc_get_variable(code, name);
	if (field) {
		field->flags = KDC_VAL(KDC_FLAG_NVAL << *idx);
		assert((KDC_FLAG_NVAL << *idx) <= KDC_FLAG_NVAL_MASK);
		return field;
	}

	field = kdc_get_define(name);
	if (field)
		return field;

	field = kdc_get_array(code, name);
	if (field)
		return field;

	ERR("invalid identifier: '%s'\n", name);
}

static __u32 kdc_add_param(char *name)
{
	__u32 id = KDC_SECTION_PARAMS_0 + list_size(ctx->params);
	struct kdc_section *param = kdc_get_param(name);
	int size;

	/* Re-use existing param, if available */
	if (param)
		return param->id;

	assert(id <= KDC_SECTION_PARAMS_MAX);
	assert(name);

	size = DIV_ROUND_UP(strlen(name) + 1, sizeof(__u32));
	param = calloc(size + sizeof(*param), sizeof(__u32));

	assert(param);

	param->id = KDC_VAL(id);
	param->size = KDC_VAL(size);
	param->name = KDC_VAL(KDC_FLAG_SECTION_STR);

	memset(param->data, '\0', size);
	memcpy(param->data, name, strlen(name));

	list_append(ctx->params, param);

	return id;
}

static int kdc_add_data(struct kdc_field *field, int size)
{
	__u32 id = KDC_SECTION_PARAMS_0 + list_size(ctx->params);
	struct kdc_section *param;
	int sz32;

	assert(id <= KDC_SECTION_PARAMS_MAX);
	assert(field);

	sz32 = DIV_ROUND_UP(size * sizeof(__u32), sizeof(__u32));
	param = calloc(size + sizeof(*param), sizeof(__u32));

	assert(param);

	param->id = KDC_VAL(id);
	param->size = KDC_VAL(sz32);
	param->name = KDC_VAL(KDC_FLAG_SECTION_DATA);

	memcpy(param->data, field->data, size * sizeof(__u32));

	list_append(ctx->params, param);

	return id;
}

static void kdc_dump_field(struct kdc_field *field)
{
	const __u32 *ptr = (__u32 *)field;
	const struct kdc_operation *op;
	int i, size;

	op = kdc_get_op_id(field->id);
	size = sizeof(*field) / sizeof(__u32);
	size = size + KDC_SIZE_GET(field->flags);

	if (op->fmt) {
		__u32 idx = field->id & KDC_OPERATION_MASK;
		int slen = 10 + 6;
		char *str;

		str = malloc(slen);
		assert(str);
		snprintf(str, slen, "\t[%10s]:\t", op->name);
		printf(str, idx);
		free(str);
	} else {
		printf("\t[%10s]:\t", op->name);
	}

	for (i = 0; i < size; i++)
		printf("0x%08x\t", ptr[i]);
	printf("\n");
}

static void kdc_write_field(FILE *dest, struct kdc_field *field)
{
	const __u32 *ptr = (__u32 *)field;
	int size;

	size = sizeof(*field) / sizeof(__u32);
	size = size + KDC_SIZE_GET(field->flags);

	assert(fwrite(ptr, sizeof(__u32), size, dest) == size);
}

static void kdc_write_section(FILE *dest, struct kdc_section *section)
{
	const __u32 *ptr = (__u32 *)section;
	int size;

	size = sizeof(*section) / sizeof(__u32);
	size = size + section->size;

	assert(fwrite(ptr, sizeof(__u32), size, dest) == size);
}

static struct code *kdc_get_code(const char *name)
{
	int i;

	for (i = 0; i < ctx->unique_id; i++) {
		struct code *code = (struct code *)list_get(ctx->sections, i);
		size_t len = MAX(strlen(code->name), strlen(name));

		if (!strncmp(code->name, name, len))
			return code;
	}

	return NULL;
}

static __u32 kdc_set_array_idx(struct code *code, struct node *node,
			       struct kdc_field *field, struct kdc_field *array, int *idx)
{
	struct kdc_field *array_index;
	const struct node *index;
	__u32 arg;

	assert(node->right);

	index = node->right;

	switch (index->type) {
	case TYPE_IDA:
		array_index = kdc_get_identifier(code, index->token, idx);
		assert(array_index);
		field->data[*idx] = KDC_VAL(array_index->data[0] | KDC_FLAG_IDX);
		*idx = *idx + 1;
		break;
	case TYPE_TYD:
		array_index = kdc_get_identifier(code, index->token, idx);
		assert(array_index);
		field->data[*idx] = KDC_VAL(array_index->data[0] | KDC_FLAG_IDX);
		*idx = *idx + 1;
		break;
	case TYPE_VAL:
		arg = strtoul(index->token, NULL, 0);
		field->data[*idx] = KDC_VAL(arg | KDC_FLAG_IDX);
		*idx = *idx + 1;
		break;
	default:
		assert(0);
		break;
	}

	return array->data[0];
}

static void __parse_arg(struct code *code, struct kdc_field *field,
			int *idx, struct node *node)
{
	struct kdc_field *ida, *array;
	__u32 arg;

	switch (node->type) {
	case TYPE_VAL:
		arg = strtoul(node->token, NULL, 0);
		break;
	case TYPE_REG:
		arg = kdc_get_reg(node->token) | KDC_FLAG_REG;
		field->flags |= KDC_VAL(KDC_FLAG_NVAL << *idx);
		assert((KDC_FLAG_NVAL << *idx) <= KDC_FLAG_NVAL_MASK);
		break;
	case TYPE_IRG:
		arg = kdc_get_int_reg(node->token) | KDC_FLAG_IREG;
		field->flags |= KDC_VAL(KDC_FLAG_NVAL << *idx);
		assert((KDC_FLAG_NVAL << *idx) <= KDC_FLAG_NVAL_MASK);
		break;
	case TYPE_IDA:
		ida = kdc_get_identifier(code, node->token, idx);
		field->flags |= ida->flags;
		arg = ida->data[0];
		break;
	case TYPE_ARV:
		array = kdc_get_identifier(code, node->token, idx);
		field->flags |= KDC_VAL(KDC_FLAG_NVAL << *idx);
		assert((KDC_FLAG_NVAL << *idx) <= KDC_FLAG_NVAL_MASK);
		arg = kdc_set_array_idx(code, node, field, array, idx);
		break;
	case TYPE_BRK:
		field->flags |= KDC_VAL(KDC_FLAG_MODS_BRK);
		arg = KDC_FIELD_INV;
		break;
	case TYPE_RET:
		field->flags |= KDC_VAL(KDC_FLAG_MODS_RET);
		arg = KDC_FIELD_INV;
		break;
	case TYPE_STR:
		arg = kdc_add_param(node->token);
		break;
	default:
		assert(0 && "Invalid argument");
		break;
	}

	field->data[*idx] = KDC_VAL(arg);
	*idx = *idx + 1;
}

static void parse_arg(struct code *code, struct kdc_field *field,
		      int *idx, struct node *node)
{
	if (!node)
		return;

	if (!strcmp(node->token, "arguments"))
		parse_arguments(code, field, idx, node);
	else
		__parse_arg(code, field, idx, node);
}

static void parse_arguments(struct code *code, struct kdc_field *field,
			    int *idx, struct node *node)
{
	parse_arg(code, field, idx, node->left);
	parse_arg(code, field, idx, node->right);
}

static void parse_condition(struct code *code,
			    struct kdc_field *field, struct node *node,
			    struct code *if_code, struct code *else_code)
{
	const struct kdc_condition *cond = kdc_find_condition(node->token);
	int idx = 0;

	parse_arguments(code, field, &idx, node);
	assert((idx == cond->args) && "Missing condition arguments");

	field->data[2] = KDC_VAL(cond->data);
	field->data[3] = KDC_VAL(if_code->id);

	if (else_code)
		field->data[4] = KDC_VAL(else_code->id);
	else
		field->data[4] = KDC_VAL(0);
}

static struct code *kdc_new_private_code(struct code *orig, char *name, bool dup)
{
	struct code *code = malloc(sizeof(*code));

	assert(code);

	code->id = KDC_SECTION_RES_0 + ctx->unique_id++;
	assert(code->id <= KDC_SECTION_RES_MAX);

	code->name = name;
	code->insts = list_new();

	if (dup) {
		code->args = orig->args;
		code->types = orig->types;
		code->arrays = orig->arrays;
	} else {
		code->args = list_new();
		code->types = list_new();
		code->arrays = list_new();
	}

	list_append(ctx->sections, code);
	return code;
}

static void parse_if_else(struct code *code, struct node *node)
{
	struct code *new_code = kdc_new_private_code(code, "if", true);
	const struct kdc_operation *op = kdc_get_op_type(node->type);
	struct code *else_code = NULL;
	struct node *r = node->right;
	struct node *l = node->left;
	struct node *cond, *then;
	struct kdc_field *field;

	assert(l);
	node = l;
	cond = node->left;
	then = node->right;

	field = malloc(sizeof(*field) + op->nargs * sizeof(*field->data));
	assert(field);

	field->id = KDC_VAL(op->id);
	field->flags = KDC_VAL(0);

	assert((op->nargs << KDC_FLAG_SIZE_SHIFT) <= KDC_FLAG_SIZE_MASK);
	field->flags |= KDC_VAL(KDC_SIZE_SET(op->nargs));
	list_append(code->insts, field);

	parse_node(new_code, then);

	if (r) { /* Has else condition */
		node = r;
		then = node->right;

		else_code = kdc_new_private_code(code, "else", true);
		parse_node(else_code, then);
	}

	parse_condition(code, field, cond, new_code, else_code);
}

static void parse_while(struct code *code, struct node *node)
{
	struct code *new_code = kdc_new_private_code(code, "while", true);
	const struct kdc_operation *op = kdc_get_op_type(node->type);
	struct node *r = node->right;
	struct node *l = node->left;
	struct node *cond, *then;
	struct kdc_field *field;

	assert(l);
	assert(r);

	cond = l;
	then = r;

	field = malloc(sizeof(*field) + op->nargs * sizeof(*field->data));
	assert(field);

	field->id = KDC_VAL(op->id);
	field->flags = KDC_VAL(0);

	assert((op->nargs << KDC_FLAG_SIZE_SHIFT) <= KDC_FLAG_SIZE_MASK);
	field->flags |= KDC_VAL(KDC_SIZE_SET(op->nargs));
	list_append(code->insts, field);

	parse_node(new_code, then);
	parse_condition(code, field, cond, new_code, NULL);
}

static void parse_function_args(struct code *code, struct node *node)
{
	int pos = list_size(code->args), size = 1;
	struct kdc_field *field;
	struct variable *var;

	assert(list_size(code->args) < KDC_FLAG_REGS_COUNT);

	switch (node->type) {
	case TYPE_VAA:
		field = malloc(sizeof(*field) + size * sizeof(*field->data));
		var = malloc(sizeof(*var));

		assert(field);
		assert(var);

		field->id = KDC_VAL(KDC_OPERATION_INVALID);

		/* no need to convert to KDC_VAL yet */
		field->data[0] = pos | KDC_FLAG_VAR;

		var->name = node->token;
		var->content = field;

		list_append(code->args, var);
		break;
	default:
		break;
	}

	if (node->left)
		parse_function_args(code, node->left);
	if (node->right)
		parse_function_args(code, node->right);
}

static int parse_function_call(struct code *code, struct node *node,
			       struct kdc_field **field_ptr)
{
	const struct kdc_operation *op = kdc_get_op_type(node->type);
	struct code *fn_code = kdc_get_code(node->token);
	struct node *args = node->right;
	int size, found_args = 0;
	struct kdc_field *field;

	if (!fn_code)
		ERR("unable to find function: '%s'\n", node->token);

	size = sizeof(*field) + op->nargs * sizeof(*field->data);
	size = size + list_size(fn_code->args) * sizeof(*field->data);

	field = malloc(size);
	assert(field);

	field->id = KDC_VAL(op->id);
	field->flags = KDC_VAL(0);

	assert(!node->left);
	assert((!((!!list_size(fn_code->args)) ^ (!!args))) && "Invalid argument");

	if (list_size(fn_code->args)) {
		assert((!strcmp(args->token, "arguments")) && "Missing arguments");
		parse_arguments(code, field, &found_args, args);
		assert((found_args == list_size(fn_code->args)) && "Missing arguments");
	}

	field->data[found_args++] = KDC_VAL(fn_code->id);
	*field_ptr = field;
	return found_args;
}

static void parse_identificator(struct code *code, struct node *node)
{
	const struct kdc_operation *op = kdc_find_op(node->token);
	struct node *args = node->right;
	struct kdc_field *field;
	int found_args = 0;

	if (!op) {
		found_args = parse_function_call(code, node, &field);
	} else {
		int size = sizeof(*field) + op->nargs * sizeof(*field->data);

		field = malloc(size);
		assert(field);

		if (op->fmt) {
			__u32 idx;

			assert((sscanf(node->token, op->name, &idx) == 1) &&
			       "Invalid operation name");
			idx |= op->id;

			field->id = KDC_VAL(idx);
		} else {
			field->id = KDC_VAL(op->id);
		}

		field->flags = KDC_VAL(0);

		assert(!node->left);
		assert((!((!!op->nargs) ^ (!!args))) && "Missing arguments");

		if (op->nargs) {
			assert((!strcmp(args->token, "arguments")) && "Missing arguments");
			parse_arguments(code, field, &found_args, args);
		}

		assert((found_args == op->nargs) && "Missing arguments");
	}

	assert((found_args << KDC_FLAG_SIZE_SHIFT) <= KDC_FLAG_SIZE_MASK);
	field->flags |= KDC_VAL(KDC_SIZE_SET(found_args));
	list_append(code->insts, field);
}

static int parse_section(struct node *node)
{
	struct node *id_node = node->left;
	struct kdc_field *define;
	int id;

	assert(id_node);

	switch (id_node->type) {
	case TYPE_IDA:
		define = kdc_get_define(id_node->token);
		assert(define && "Identifier for section not found");
		id = define->data[0];
		break;
	case TYPE_VAL:
		id = strtoul(id_node->token, NULL, 0);
		break;
	default:
		assert(0 && "Invalid section specification");
		break;
	}

	assert(((id > 0) && (id <= KDC_SECTION_INIT_MAX)) && "Invalid section ID");
	return id;
}

static void parse_code(struct node *node, int forced_id, struct node *args)
{
	struct code *code = malloc(sizeof(*code));

	assert(code);

	/* forced_id different than 0 means it is a section */
	if (forced_id) {
		code->id = forced_id;

		assert(code->id <= KDC_SECTION_INIT_MAX);
		assert((!ctx->present_sections[code->id]) && "Duplicate section");

		ctx->present_sections[code->id] = true;
	} else {
		code->id = KDC_SECTION_RES_0 + ctx->unique_id;
		assert(code->id <= KDC_SECTION_RES_MAX);
	}

	ctx->unique_id++;

	code->name = forced_id ? "section" : node->token;
	code->insts = list_new();
	code->args = list_new();
	code->types = list_new();
	code->arrays = list_new();
	list_append(ctx->sections, code);

	if (args)
		parse_function_args(code, args);
	if (node->left)
		parse_node(code, node->left);
	if (node->right)
		parse_node(code, node->right);
}

static void parse_set(struct code *code, struct node *node)
{
	const struct kdc_operation *op = kdc_get_op_type(node->type);
	struct node *val = node->right;
	struct node *reg = node->left;
	struct kdc_field *field;
	int idx = 0;

	assert(reg);
	assert(val);

	field = malloc(sizeof(*field) + op->nargs * sizeof(*field->data));
	assert(field);

	field->id = KDC_VAL(op->id);
	field->flags = KDC_VAL(0);

	assert((op->nargs << KDC_FLAG_SIZE_SHIFT) <= KDC_FLAG_SIZE_MASK);
	field->flags |= KDC_VAL(KDC_SIZE_SET(op->nargs));
	list_append(code->insts, field);

	__parse_arg(code, field, &idx, reg);
	if (node->type == TYPE_STM) {
		const struct kdc_condition *cond = kdc_find_condition(val->token);
		struct node *reg_l, *reg_r;

		reg_l = val->left;
		reg_r = val->right;

		assert(reg_l);
		assert(reg_r);

		__parse_arg(code, field, &idx, reg_l);
		__parse_arg(code, field, &idx, reg_r);
		field->data[idx++] = KDC_VAL(cond->data);
	} else {
		__parse_arg(code, field, &idx, val);
	}

	assert((idx <= op->nargs) && "Missing arguments");
}

static void parse_define(struct code *code, struct node *node)
{
	struct variable *define = malloc(sizeof(*define));
	struct node *val = node->right;
	struct kdc_field *field;
	int idx = 0, size = 1;

	assert(define);
	assert(!node->left);
	assert(val);

	field = malloc(sizeof(*field) + size * sizeof(*field->data));
	assert(field);

	field->id = KDC_VAL(KDC_OPERATION_INVALID);
	field->flags = KDC_VAL(0);

	__parse_arg(code, field, &idx, val);
	assert(idx == size);

	define->name = node->token;
	define->content = field;

	list_append(ctx->defines, define);
}

static void parse_typedef(struct code *code, struct node *node)
{
	struct variable *var = malloc(sizeof(*var));
	int max_types = KDC_FLAG_REGS_COUNT;
	const struct node *n_reg;
	struct kdc_field *field;
	struct node *n_name;
	struct list *list;
	int size = 1;

	assert(var);

	field = malloc(sizeof(*field) + size * sizeof(*field->data));
	assert(field);

	assert(node->type == TYPE_TYD);
	assert(node->left);
	assert(node->right);

	if (code) {
		/* Means it's local typedef */
		list = code->types;
	} else {
		/* Means it's global typedef */
		list = ctx->global_types;
	}

	assert(list_size(list) <= max_types);

	n_reg = node->left;
	n_name = node->right;

	switch (n_reg->type) {
	case TYPE_REG:
		/* no need to convert to KDC_VAL yet */
		field->data[0] = kdc_get_reg(n_reg->token) | KDC_FLAG_REG;
		field->id = TYPE_REG;
		break;
	case TYPE_IRG:
		/* no need to convert to KDC_VAL yet */
		field->data[0] = kdc_get_int_reg(n_reg->token) | KDC_FLAG_IREG;
		field->id = TYPE_IRG;
		break;
	default:
		assert(0 && "Invalid typedef");
		break;
	}

	switch (n_name->type) {
	case TYPE_IDA:
		var->name = n_name->token;
		var->content = field;
		break;
	default:
		assert(0 && "Invalid typedef");
		break;
	}

	list_append(list, var);
}

static int parse_array_args(struct code *code, struct node *args,
			    struct kdc_field *field)
{
	int found_args = 0;

	field->id = KDC_VAL(KDC_OPERATION_INVALID);
	field->flags = KDC_VAL(0);

	assert(!strcmp(args->token, "arguments"));
	parse_arguments(code, field, &found_args, args);

	return found_args;
}

static void parse_array_size(struct code *code, struct node *size_arr,
			     struct kdc_field *field, int *idx)
{
	field->id = KDC_VAL(KDC_OPERATION_INVALID);
	field->flags = KDC_VAL(0);

	assert(size_arr->type == TYPE_VAL);
	__parse_arg(code, field, idx, size_arr);
}

static void parse_array(struct code *code, struct node *node)
{
	int found_args = 0, size_set = 0, idx = 0, size = 1;
	struct variable *array = malloc(sizeof(*array));
	struct kdc_field *field_tmp, *field, *arr_id;
	struct node *size_arr, *args;
	struct list *list;
	__u32 id;

	assert(array);

	assert(node->type == TYPE_ARR);
	assert(node->left);
	assert(node->right);

	size_arr = node->left;
	args = node->right;

	field = malloc(sizeof(*field) + MAX_ARRAY_SIZE * sizeof(*field->data));
	assert(field);

	parse_array_size(code, size_arr, field, &idx);

	size_set = field->data[0];
	assert(size_set <= MAX_ARRAY_SIZE);

	found_args = parse_array_args(code, args, field);
	assert(found_args == size_set);

	field_tmp = realloc(field, sizeof(*field) + (size_set * sizeof(__u32)));

	assert(field_tmp);
	field = field_tmp;

	id = kdc_add_data(field, size_set);
	assert(id);

	KDC_FREE(field);

	arr_id = malloc(sizeof(*arr_id) + size * sizeof(*arr_id->data));
	assert(arr_id);

	arr_id->id = KDC_VAL(KDC_OPERATION_INVALID);
	arr_id->flags = KDC_VAL(0);
	arr_id->data[0] = id;

	array->name = node->token;
	array->content = arr_id;

	if (code) {
		/* Means it's local typedef */
		list = code->arrays;
	} else {
		/* Means it's global typedef */
		list = ctx->global_arrays;
	}

	list_append(list, array);
}

static void parse_node(struct code *code, struct node *node)
{
	int id = 0;

	switch (node->type) {
	case TYPE_VER:
		ctx->header.version = KDC_VAL(kdc_add_param(node->token));
		break;
	case TYPE_DEF:
		parse_define(code, node);
		break;
	case TYPE_ARG:
		assert(code);
		parse_function_args(code, node);
		break;
	case TYPE_ID:
		assert(code);
		parse_identificator(code, node);
		break;
	case TYPE_SEC:
		assert(node->left);
		id = parse_section(node->left);
		parse_code(node->right, id, node->left->right);
		break;
	case TYPE_FUN:
		parse_code(node, id, NULL);
		break;
	case TYPE_IFE:
		assert(code);
		parse_if_else(code, node);
		break;
	case TYPE_WHI:
		assert(code);
		parse_while(code, node);
		break;
	case TYPE_SET:
	case TYPE_STM:
		assert(code);
		parse_set(code, node);
		break;
	case TYPE_TYD:
		parse_typedef(code, node);
		break;
	case TYPE_ARR:
		parse_array(code, node);
		break;
	default:
		if (node->left)
			parse_node(code, node->left);
		if (node->right)
			parse_node(code, node->right);
		break;
	}
}

void program_parse(struct node *head)
{
	assert(head->left);
	assert(head->right);

	parse_node(NULL, head->left);
	parse_node(NULL, head->right);
}

void program_dump(struct list *sections)
{
	struct kdc_field *field;
	struct code *code;
	int i, j;

	for (i = 0; i < list_size(sections); i++) {
		struct list *insts;

		code = (struct code *)list_get(sections, i);
		insts = code->insts;

		printf("section[0x%x]: id:0x%x name:'%s'\n",
		       i, code->id, code->name);

		for (j = 0; j < list_size(insts); j++) {
			field = (struct kdc_field *)list_get(insts, j);

			kdc_dump_field(field);
		}
	}
}

void program_dump_raw(__u32 *data, long size)
{
	const struct kdc_header *header;
	struct kdc_field *field;
	struct kdc_section *sec;
	int i, j, field_size;

	for (i = 0; i < size; ) {
		sec = (struct kdc_section *)&data[i];

		printf("section: id=0x%08x, size=0x%08x, insts=0x%08x\n",
		       sec->id, sec->size, sec->insts);

		switch (sec->id) {
		case KDC_SECTION_INIT_0...KDC_SECTION_INIT_MAX:
		case KDC_SECTION_RES_0...KDC_SECTION_RES_MAX:
			for (j = 0; j < sec->size; ) {
				field = (struct kdc_field *)&sec->data[j];

				kdc_dump_field(field);

				field_size = sizeof(*field) / sizeof(__u32);
				field_size += KDC_SIZE_GET(field->flags);

				j += field_size;
			}

			break;
		case KDC_SECTION_HEADER:
			header = (struct kdc_header *)sec->data;
			printf("[HEADER] crc=0x%08x\n", header->crc);
			break;
		case KDC_SECTION_PARAMS_0...KDC_SECTION_PARAMS_MAX:
			if (sec->name == KDC_FLAG_SECTION_STR) {
				printf("[PARAM] content='%s'\n", (char *)sec->data);
			} else if (sec->name == KDC_FLAG_SECTION_DATA) {
				printf("[DATA] content:\n");
				for (j = 0; j < sec->size; j++) {
					__u32 data_val = sec->data[j];

					printf("\t0x%08x", data_val);
					if (j && !(j % 4))
						printf("\n");
				}
				printf("\n");
			}
			break;
		default:
			assert(0);
			break;
		}

		i += (sizeof(*sec) / sizeof(__u32)) + sec->size;
	}
}

void program_write(FILE *dest, struct kdc_header *header, const time_t *timestamp,
		   struct list *sections, struct list *params)
{
	const char *rfc_2822 = "%a, %d %b %Y %T %z"; /* RFC 2822-compliant date fmt */
	struct kdc_section kdc_sec;
	struct kdc_field *field;
	struct code *code;
	char time_str[80];
	struct tm *tm;
	int i, j;

	assert(list_size(sections));

	memset(&kdc_sec, 0, sizeof(kdc_sec));
	kdc_sec.id = KDC_VAL(KDC_SECTION_HEADER);
	kdc_sec.size = KDC_VAL(sizeof(*header) / sizeof(__u32));
	kdc_sec.name = KDC_VAL(kdc_add_param("header"));
	kdc_sec.insts = 0;

	tm = localtime(timestamp);
	assert(tm);

	strftime(time_str, sizeof(time_str), rfc_2822, tm);
	header->timestamp = KDC_VAL(kdc_add_param(time_str));

	assert(fwrite(&kdc_sec, sizeof(kdc_sec), 1, dest) == 1);
	assert(fwrite(header, sizeof(*header), 1, dest) == 1);

	for (i = 0; i < list_size(sections); i++) {
		struct list *insts;

		code = (struct code *)list_get(sections, i);
		insts = code->insts;
		__u32 size = 0;

		/* Get section size first */
		for (j = 0; j < list_size(insts); j++) {
			field = (struct kdc_field *)list_get(insts, j);

			size += sizeof(*field) / sizeof(__u32);
			size += KDC_SIZE_GET(field->flags);
		}

		kdc_sec.id = KDC_VAL(code->id);
		kdc_sec.size = KDC_VAL(size);
		kdc_sec.name = KDC_VAL(kdc_add_param(code->name));
		kdc_sec.insts = KDC_VAL(list_size(insts));
		assert(fwrite(&kdc_sec, sizeof(kdc_sec), 1, dest) == 1);

		for (j = 0; j < list_size(insts); j++) {
			field = (struct kdc_field *)list_get(insts, j);

			kdc_write_field(dest, field);
		}
	}

	for (i = 0; i < list_size(params); i++) {
		struct kdc_section *param_sec;

		param_sec = (struct kdc_section *)list_get(params, i);
		kdc_write_section(dest, param_sec);
	}
}
