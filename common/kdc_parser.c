struct kdc_parser_ctx {
	__u32 *data;
	long data_size32;
	struct kdc_ops *ops;
	void *call_ptr;
	__u32 regs[KDC_FLAG_REGS_COUNT];
	__u32 int_regs[KDC_FLAG_REGS_COUNT * KDC_MAX_DEPTH];
	__u32 vars[KDC_FLAG_REGS_COUNT * KDC_MAX_DEPTH];
	__u32 vars_flags[KDC_FLAG_REGS_COUNT * KDC_MAX_DEPTH];
	int depth_pos;
	int block_pos;
	int exit_found;
	int brk_found;
	int ret_found;
	__u32 exit_code;
	int exit_print;
	int scope;
	int in_loop;
	int debug;
};

static int __kdc_common_process(struct kdc_parser_ctx *ctx, int section_id);

static void kdc_dump_field_err(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	int i, size = KDC_SIZE_GET(field->flags);

	KDC_ERR("op=0x%08x, flags=0x%08x\n", field->id, field->flags);
	for (i = 0; i < size; i++)
		KDC_ERR("data[%d]: 0x%08x\n", i, field->data[i]);
}

static struct kdc_section *kdc_get_section(struct kdc_parser_ctx *ctx, __u32 id)
{
	unsigned long i;

	for (i = 0; i < ctx->data_size32; ) {
		struct kdc_section *section;

		section = (struct kdc_section *)&ctx->data[i];
		if (section->id == id)
			return section;

		i += section->size + sizeof(*section) / sizeof(*ctx->data);
	}

	KDC_ERR("failed to find firmware section '%d'\n", id);
	return NULL;
}

static struct kdc_header *kdc_get_header(struct kdc_parser_ctx *ctx)
{
	struct kdc_section *section = kdc_get_section(ctx, KDC_SECTION_HEADER);

	if (!section)
		return NULL;

	return (struct kdc_header *)section->data;
}

static int kdc_get_nval_val(struct kdc_parser_ctx *ctx, struct kdc_field *field,
			   __u32 **val, int i, int i_pos, __u32 *out_flags)
{
	int max_regs = KDC_FLAG_REGS_COUNT * KDC_MAX_DEPTH;
	int pos = ctx->depth_pos * KDC_FLAG_REGS_COUNT;
	__u32 flags, data, extra_flags = 0;
	bool is_reg = false;

	/* Save current data field */
	flags = field->data[i_pos] & KDC_FLAG_MASK;
	data = field->data[i_pos] & KDC_FLAG_DATA;

	/* Advance to next data field */
	i_pos++;

	if (flags & KDC_FLAG_REG) {
		val[i] = &ctx->regs[data];
		is_reg = true;
	}

	if (flags & KDC_FLAG_IREG) {
		val[i] = &ctx->int_regs[data + pos];
		is_reg = true;
	}

	if (flags & KDC_FLAG_VAR) {
		val[i] = &ctx->vars[data + pos];
		extra_flags = ctx->vars_flags[data + pos];
	}

	if (extra_flags & KDC_FLAG_REG) {
		if ((*val[i] < 0) || (*val[i] >= max_regs)) {
			KDC_ERR("invalid register '0x%x'\n", *val[i]);
			goto out;
		}

		val[i] = &ctx->regs[*val[i]];
		is_reg = true;
	} else if (extra_flags & KDC_FLAG_IREG) {
		if ((*val[i] < 0) || (*val[i] >= max_regs)) {
			KDC_ERR("invalid int. register '0x%x'\n", *val[i]);
			goto out;
		}

		val[i] = &ctx->int_regs[*val[i]];
		is_reg = true;
	}

	if (is_reg && out_flags)
		*out_flags |= (1 << i);

	if (flags & KDC_FLAG_IDX) {
		__u32 arr_idx = *val[i] & KDC_FLAG_DATA;
		struct kdc_section *section;

		section = kdc_get_section(ctx, field->data[i_pos]);
		if (!section) {
			KDC_ERR("couldn't find param '%d'\n", data);
			goto out;
		}

		if (arr_idx >= section->size) {
			KDC_ERR("invalid array index '%d'\n", arr_idx);
			goto out;
		}

		/* Replace with true value */
		val[i] = &section->data[arr_idx];

		/* Advance to next data field */
		i_pos++;
	}

out:
	return i_pos;
}

static int kdc_get_val(struct kdc_parser_ctx *ctx, struct kdc_field *field,
		      __u32 **val, int count, __u32 *flags)
{
	int i, pos;

	for (i = 0, pos = 0; i < count; i++) {
		val[pos] = &field->data[pos];

		if (field->flags & (KDC_FLAG_NVAL << pos))
			pos = kdc_get_nval_val(ctx, field, val, i, pos, flags);
		else
			pos++;
	}

	return pos;
}

static int kdc_process_read(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	__u32 op_id = field->id & KDC_OPERATION_MASK;
	int ret, size = KDC_SIZE_GET(field->flags);
	int (*fn)(struct kdc_cmd *cmd) = NULL;
	struct kdc_cmd cmd = { 0, };
	__u32 **val, flags = 0;
	bool compare = true;

	if (!ctx->ops) {
		KDC_ERR("undeclared operations\n");
		return -EOPNOTSUPP;
	}

	fn = ctx->ops->read[op_id];
	if (!fn) {
		KDC_ERR("undeclared operation '0x%x'\n", field->id);
		return -EOPNOTSUPP;
	}

	val = KDC_ZALLOC(size * sizeof(*val));
	if (!val)
		return -ENOMEM;

	kdc_get_val(ctx, field, val, size, &flags);

	if (flags & (1 << 1))
		compare = false;

	cmd.call_ptr = ctx->call_ptr;
	cmd.op_id = op_id;
	cmd.address = *val[0];
	cmd.data = 0x0;

	ret = fn(&cmd);

	KDC_DEBUG(ctx->debug, "read[%d, ret=%d]: reg=0x%08x, val=0x%08x\n",
		      op_id, ret, cmd.address, cmd.data);

	if (ret) {
		kdc_dump_field_err(ctx, field);
		goto out_free;
	}

	if (compare && cmd.data != *val[1]) {
		KDC_ERR("read 0x%x, got 0x%x, exp 0x%x\n",
			    cmd.address, cmd.data, *val[1]);
		ret = -EIO;
	} else if (!compare) {
		*val[1] = cmd.data;
	}

out_free:
	KDC_FREE(val);
	return ret;
}

static int kdc_process_write(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	__u32 op_id = field->id & KDC_OPERATION_MASK;
	int ret, size = KDC_SIZE_GET(field->flags);
	int (*fn)(struct kdc_cmd *cmd) = NULL;
	struct kdc_cmd cmd = { 0, };
	__u32 **val;

	if (!ctx->ops) {
		KDC_ERR("undeclared operations\n");
		return -EOPNOTSUPP;
	}

	fn = ctx->ops->write[op_id];
	if (!fn) {
		KDC_ERR("undeclared operation '0x%x'\n", field->id);
		return -EOPNOTSUPP;
	}

	val = KDC_ZALLOC(size * sizeof(*val));
	if (!val)
		return -ENOMEM;

	kdc_get_val(ctx, field, val, size, NULL);

	cmd.call_ptr = ctx->call_ptr;
	cmd.op_id = op_id;
	cmd.address = *val[0];
	cmd.data = *val[1];

	ret = fn(&cmd);

	KDC_DEBUG(ctx->debug, "write[%d, ret=%d]: reg=0x%08x, val=0x%08x\n",
		      op_id, ret, cmd.address, cmd.data);

	if (ret) {
		kdc_dump_field_err(ctx, field);
		goto out_free;
	}

out_free:
	KDC_FREE(val);
	return ret;
}

static int __kdc_process_jump(struct kdc_parser_ctx *ctx, __u32 id)
{
	if (ctx->depth_pos >= (KDC_MAX_DEPTH - 1)) {
		KDC_ERR("too many function calls (max: %d)\n", KDC_MAX_DEPTH);
		return -ENOMEM;
	}

	if (ctx->block_pos >= (KDC_MAX_DEPTH - 1)) {
		KDC_ERR("too many conditions (max: %d)\n", KDC_MAX_DEPTH);
		return -ENOMEM;
	}

	return __kdc_common_process(ctx, id);
}

static int kdc_process_jump(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	int ret, prev_pos, pos, i, size = KDC_SIZE_GET(field->flags);
	int ireg_prev, var_prev, prev_scope = ctx->scope;

	ctx->depth_pos++;
	ctx->scope = KDC_SCOPE_FUN;

	prev_pos = ctx->depth_pos - 1;
	ireg_prev = prev_pos * KDC_FLAG_REGS_COUNT;
	var_prev = prev_pos * KDC_FLAG_REGS_COUNT;
	pos = ctx->depth_pos * KDC_FLAG_REGS_COUNT;

	for (i = 0; i < (size - 1); i++) {
		__u32 flags, data;

		flags = field->flags & (KDC_FLAG_NVAL << i);
		data = field->data[i];

		/* Check if data is NVAL */
		if (flags) {
			flags = field->data[i] & KDC_FLAG_MASK;
			data = field->data[i] & KDC_FLAG_DATA;
		}

		ctx->vars[pos + i] = data;
		ctx->vars_flags[pos + i] = flags;

		if (flags & KDC_FLAG_IREG)
			ctx->vars[pos + i] = data + ireg_prev;
		if (flags & KDC_FLAG_VAR) {
			ctx->vars[pos + i] = ctx->vars[data + var_prev];
			ctx->vars_flags[pos + i] = ctx->vars_flags[data + var_prev];
		}
	}

	ret = __kdc_process_jump(ctx, field->data[i]);

	ctx->depth_pos--;
	ctx->scope = prev_scope;
	return ret;
}

static int kdc_process_condition(struct kdc_parser_ctx *ctx, __u32 **val,
				__u32 condition, __u32 *result)
{
	switch (condition) {
	case KDC_COND_OR:
		*result = *val[0] || *val[1];
		break;
	case KDC_COND_AND:
		*result = *val[0] && *val[1];
		break;
	case KDC_COND_LOR:
		*result = *val[0] | *val[1];
		break;
	case KDC_COND_LXOR:
		*result = *val[0] ^ *val[1];
		break;
	case KDC_COND_LAND:
		*result = *val[0] & *val[1];
		break;
	case KDC_COND_NEQ:
		*result = *val[0] != *val[1];
		break;
	case KDC_COND_EQ:
		*result = *val[0] == *val[1];
		break;
	case KDC_COND_GE:
		*result = *val[0] >= *val[1];
		break;
	case KDC_COND_LE:
		*result = *val[0] <= *val[1];
		break;
	case KDC_COND_GT:
		*result = *val[0] > *val[1];
		break;
	case KDC_COND_LT:
		*result = *val[0] < *val[1];
		break;
	case KDC_COND_PLUS:
		*result = *val[0] + *val[1];
		break;
	case KDC_COND_MINUS:
		*result = *val[0] - *val[1];
		break;
	case KDC_COND_MULT:
		*result = *val[0] * *val[1];
		break;
	case KDC_COND_DIV:
		*result = *val[0] / *val[1];
		break;
	case KDC_COND_MOD:
		*result = *val[0] % *val[1];
		break;
	case KDC_COND_RSHIFT:
		*result = *val[0] >> *val[1];
		break;
	case KDC_COND_LSHIFT:
		*result = *val[0] << *val[1];
		break;
	case KDC_COND_NOT:
		*result = ~*val[0];
		break;
	case KDC_COND_NEG:
		*result = !*val[0];
		break;
	default:
		KDC_ERR("unsupported conditional operation\n");
		return -EINVAL;
	}

	return 0;
}

static int kdc_process_if(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	int pos, prev_scope = ctx->scope, ret = 0;
	__u32 *values[2];
	__u32 result = 0;

	pos = kdc_get_val(ctx, field, values, 2, NULL);

	ret = kdc_process_condition(ctx, values, field->data[pos], &result);
	if (ret)
		return ret;

	ctx->scope = KDC_SCOPE_BLK;
	ctx->block_pos++;

	if (result)
		ret = __kdc_process_jump(ctx, field->data[pos + 1]);
	else if (field->data[4])
		ret = __kdc_process_jump(ctx, field->data[pos + 2]);

	ctx->block_pos--;
	ctx->scope = prev_scope;
	return ret;
}

static int kdc_process_while(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	int pos, prev_scope = ctx->scope, ret = 0;
	__u32 *values[2];
	__u32 result = 0;

	pos = kdc_get_val(ctx, field, values, 2, NULL);

	ctx->scope = KDC_SCOPE_BLK;
	ctx->in_loop++;
	ctx->block_pos++;
	do {
		ret = kdc_process_condition(ctx, values, field->data[pos], &result);
		if (ret)
			goto out;

		if (result) {
			ret = __kdc_process_jump(ctx, field->data[pos + 1]);
			if (ret)
				goto out;
		}
	} while (result && !ctx->brk_found && !ctx->ret_found);

out:
	ctx->block_pos--;
	ctx->in_loop--;
	ctx->brk_found = false;
	ctx->scope = prev_scope;
	return ret;
}

static int kdc_process_set(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	int size = KDC_SIZE_GET(field->flags);
	__u32 result = 0;
	__u32 *val[3];

	if (size >= 4) {
		int ret, pos = kdc_get_val(ctx, field, val, 3, NULL);

		ret = kdc_process_condition(ctx, &val[1], field->data[pos], &result);
		if (ret)
			return ret;

		*val[0] = result;
	} else if (size >= 2) {
		kdc_get_val(ctx, field, val, 2, NULL);
		*val[0] = *val[1];
	} else {
		return -EINVAL;
	}

	return 0;
}

static int kdc_process_stop(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	__u32 flags = field->flags & KDC_FLAG_MODS_MASK;
	__u32 *value = NULL;

	kdc_get_val(ctx, field, &value, 1, NULL);

	ctx->exit_code = *value;

	if (flags & KDC_FLAG_MODS_RET)
		ctx->ret_found = true;
	else if (ctx->in_loop && (flags & KDC_FLAG_MODS_BRK))
		ctx->brk_found = true;
	else
		ctx->exit_found = true;

	return 0;
}

static int kdc_process_sleep(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	__u32 micros, *value = NULL;

	kdc_get_val(ctx, field, &value, 1, NULL);
	micros = *value;

	while (micros > 0) {
		__u32 delta = micros > KDC_UDELAY_MAX ? KDC_UDELAY_MAX : micros;

		KDC_USLEEP(delta);
		micros -= delta;
	}

	return 0;
}

static int kdc_process_dump(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	__u32 *value = NULL, data = field->data[0] & KDC_FLAG_DATA;

	kdc_get_val(ctx, field, &value, 1, NULL);
	KDC_INFO("DUMP[%02d]: 0x%08x\n", data, *value);
	return 0;
}

static char *__kdc_get_print(struct kdc_parser_ctx *ctx, __u32 param_id)
{
	struct kdc_section *param;
	unsigned int size, end;

	param = kdc_get_section(ctx, param_id);
	if (!param) {
		KDC_ERR("couldn't find param '%d'\n", param_id);
		return NULL;
	}

	size = param->size * sizeof(__u32);
	if (size >= (ctx->data_size32 * sizeof(__u32))) {
		KDC_ERR("invalid param size '%d'\n", param_id);
		return NULL;
	}

	end = (__u32 *)(param->data + size) - ctx->data;
	if (end >= (ctx->data_size32 * sizeof(__u32))) {
		KDC_ERR("invalid param size '%d'\n", param_id);
		return NULL;
	}

	return (char *)param->data;
}

static int kdc_process_print(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	char *str = __kdc_get_print(ctx, field->data[0]);

	if (!str)
		return -EINVAL;

	KDC_INFO("%s\n", str);
	return 0;
}

static int kdc_process_rmw(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	__u32 op_id = field->id & KDC_OPERATION_MASK;
	int ret, size = KDC_SIZE_GET(field->flags);
	int (*fn_r)(struct kdc_cmd *cmd) = NULL;
	int (*fn_w)(struct kdc_cmd *cmd) = NULL;
	struct kdc_cmd cmd_r = { 0, };
	struct kdc_cmd cmd_w = { 0, };
	__u32 **val;

	if (!ctx->ops) {
		KDC_ERR("undeclared operations\n");
		return -EOPNOTSUPP;
	}

	fn_r = ctx->ops->read[op_id];
	fn_w = ctx->ops->write[op_id];
	if (!fn_r || !fn_w) {
		KDC_ERR("undeclared operation '0x%x'\n", field->id);
		return -EOPNOTSUPP;
	}

	val = KDC_ZALLOC(size * sizeof(*val));
	if (!val)
		return -ENOMEM;

	kdc_get_val(ctx, field, val, size, NULL);

	cmd_r.call_ptr = ctx->call_ptr;
	cmd_r.op_id = op_id;
	cmd_r.address = *val[0];
	cmd_r.data = 0x0;

	/* Read initial value */
	ret = fn_r(&cmd_r);
	if (ret) {
		kdc_dump_field_err(ctx, field);
		goto out_free;
	}

	/* Perform RMW */
	cmd_w.call_ptr = ctx->call_ptr;
	cmd_w.op_id = op_id;
	cmd_w.address = *val[0];
	cmd_w.data = (*val[1] & *val[2]) | (cmd_r.data & ~*val[2]);

	/* Write back final value */
	ret = fn_w(&cmd_w);
	if (ret) {
		kdc_dump_field_err(ctx, field);
		goto out_free;
	}

out_free:
	KDC_DEBUG(ctx->debug,
		      "rmw[%d, ret=%d]: reg=0x%08x, val=0x%08x, mask=0x%08x\n",
		      field->id, ret, *val[0], *val[1], *val[2]);
	KDC_FREE(val);
	return ret;
}

static int kdc_process_field(struct kdc_parser_ctx *ctx, struct kdc_field *field)
{
	int ret = 0;

	switch (field->id) {
	case KDC_OPERATION_JUMP:
		ret = kdc_process_jump(ctx, field);
		break;
	case KDC_OPERATION_JUMP_IFE:
		ret = kdc_process_if(ctx, field);
		break;
	case KDC_OPERATION_SET:
		ret = kdc_process_set(ctx, field);
		break;
	case KDC_OPERATION_STOP:
		ret = kdc_process_stop(ctx, field);
		break;
	case KDC_OPERATION_SLEEP:
		ret = kdc_process_sleep(ctx, field);
		break;
	case KDC_OPERATION_DUMP:
		ret = kdc_process_dump(ctx, field);
		break;
	case KDC_OPERATION_WHILE:
		ret = kdc_process_while(ctx, field);
		break;
	case KDC_OPERATION_PRINT:
		ret = kdc_process_print(ctx, field);
		break;
	default:
		switch (field->id & KDC_OPERATION_X_MASK) {
		case KDC_OPERATION_READ_X:
			ret = kdc_process_read(ctx, field);
			break;
		case KDC_OPERATION_WRITE_X:
			ret = kdc_process_write(ctx, field);
			break;
		case KDC_OPERATION_RMW_X:
			ret = kdc_process_rmw(ctx, field);
			break;
		case KDC_OPERATION_CUSTOM_X:
		default:
			KDC_ERR("unsupported operation '0x%x'\n", field->id);
			ret = -EOPNOTSUPP;
			break;
		}
	}

	return ret;
}

static int __kdc_common_process(struct kdc_parser_ctx *ctx, int section_id)
{
	int i, size, ret = -ENOENT;
	struct kdc_section *section;
	struct kdc_field *field;
	bool in_again;
	char *name;

	in_again = ctx->depth_pos || ctx->block_pos;
	if (!in_again) {
		section_id = section_id - KDC_SECTION_INIT_0;

		if  (section_id >= KDC_SECTION_INIT_MAX) {
			KDC_ERR("invalid section '%d'\n", section_id);
			return -ENOENT;
		}
	}

	section = kdc_get_section(ctx, section_id);
	if (!section) {
		KDC_ERR("couldn't find section '%d'\n", section_id);
		return -ENOENT;
	}

	name = __kdc_get_print(ctx, section->name);
	if (name)
		KDC_DEBUG(ctx->debug, "-> entering '%s:0x%08x'\n",
			      name, section_id);

	field = (struct kdc_field *)section->data;
	for (i = 0; i < section->insts; i++) {
		__u32 *field_ptr = (__u32 *)field;

		size = sizeof(*field) / sizeof(__u32);
		size = size + KDC_SIZE_GET(field->flags);

		if (ctx->exit_found) {
			if (!ctx->exit_print) {
				KDC_WARN("stopping with error '0x%x'\n",
					     ctx->exit_code);
				ctx->exit_print = true;
			}

			ret = ctx->exit_code ? -EIO : 0;
			goto out;
		}

		if (ctx->brk_found && ctx->in_loop) {
			ret = 0;
			goto out;
		}

		ret = kdc_process_field(ctx, field);
		if (ret)
			goto out;

		if (ctx->ret_found && ctx->scope <= KDC_SCOPE_FUN) {
			ctx->ret_found = false;
			goto out;
		} else if (ctx->ret_found) {
			goto out;
		}

		field = (struct kdc_field *)(field_ptr + size);
	}

out:
	if (name) {
		KDC_DEBUG(ctx->debug, "-< leaving '%s:0x%08x'\n",
			      name, section_id);
	}

	return ret;
}

static int kdc_common_process(void *ptr, struct kdc_args *args)
{
	struct kdc_parser_ctx *ctx = (struct kdc_parser_ctx *)ptr;
	int i;

	ctx->ops = args->ops;
	ctx->call_ptr = args->call_ptr;
	ctx->debug = args->flags & KDC_PARSER_VERBOSE;

	/* Restore some settings */
	ctx->scope = KDC_SCOPE_SEC;
	ctx->depth_pos = 0;
	ctx->block_pos = 0;

	for (i = 0; i < KDC_FLAG_REGS_COUNT; i++) {
		ctx->vars[i] = args->arguments[i];
		ctx->vars_flags[i] = 0x0;
	}

	return __kdc_common_process(ctx, args->section_id);
}

static void *kdc_common_init(__u32 *data, long size32)
{
	struct kdc_parser_ctx *ctx = KDC_ZALLOC(sizeof(*ctx));
	char *version, *timestamp;
	struct kdc_header *header;

	if (!ctx)
		return NULL;

	ctx->data = data;
	ctx->data_size32 = size32;

	header = kdc_get_header(ctx);
	if (!header) {
		KDC_ERR("failed to find firmware header\n");
		goto err;
	}

	version = __kdc_get_print(ctx, header->version);
	if (!version) {
		KDC_ERR("failed to find firmware version\n");
		goto err;
	}

	timestamp = __kdc_get_print(ctx, header->timestamp);
	if (!timestamp) {
		KDC_ERR("failed to find firmware timestamp\n");
		goto err;
	}

	ctx->scope = KDC_SCOPE_SEC;
	ctx->depth_pos = 0;
	ctx->block_pos = 0;

	KDC_INFO("version '%s', timestamp '%s', crc 0x%x\n",
		     version, timestamp, header->crc);
	return ctx;
err:
	KDC_FREE(ctx);
	return NULL;
}

static void kdc_common_exit(void *ptr)
{
	KDC_FREE(ptr);
}
