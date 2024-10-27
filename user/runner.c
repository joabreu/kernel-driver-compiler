#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <lzma.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "kdc_api.h"
#include "kdc_parser.c"

#define MIN(a, b)		({	\
	typeof(a) __a = (a);		\
	typeof(b) __b = (b);		\
	(__a < __b) ? __a : __b;	\
})
#define NUM_REGIONS		4

struct kdc_user_ctx {
	__u32 base[NUM_REGIONS];
	struct kdc_args kdc_args;
	int base_cnt;
	__u32 *data;
	FILE *dest;
	long data_size32;
	int fd;
	void *ptr;
};

static __u32 kdcu_get_vaddr(struct kdc_user_ctx *ctx, __u32 addr)
{
	unsigned int p_need, p_size;
	off_t m_address, offset;
	void *v_address;
	int size = 4;
	__u32 temp;
	char *map;

	p_size = sysconf(_SC_PAGE_SIZE);

	/* mapped address, for mmap() must be page aligned */
	m_address = addr & ~(off_t)(p_size - 1);
	/* offset in one page */
	offset = addr & (p_size - 1);
	/* pages needed */
	p_need = (offset + size) & ~(p_size - 1);

	/* size needed = number of complete pages + 1 */
	if (((offset + size) & (p_size - 1)) != 0)
		p_need += p_size;

	/*
	 ************* NOTES
	 * PROT_EXEC  Pages may be executed.
	 * PROT_READ  Pages may be read.
	 * PROT_WRITE Pages may be written.
	 * PROT_NONE  Pages may not be accessed.
	 *
	 * MAP_SHARED  Changes are shared.
	 * MAP_PRIVATE Changes are private.
	 * MAP_FIXED Interpret addr exactly.
	 */
	map = mmap(NULL, p_need, PROT_READ | PROT_WRITE, MAP_SHARED,
		   ctx->fd, m_address);
	if (map == MAP_FAILED) {
		perror("mmap failed");
		exit(1);
	}

	msync(map, p_need, MS_SYNC);

	v_address = (char *)map + (unsigned int)offset;
	temp = (__u32)(*(off_t *)(v_address) & 0xffffffff);

	munmap(map, p_need);

	return temp;
}

static void kdcu_set_vaddr(struct kdc_user_ctx *ctx, __u32 addr, __u32 val)
{
	unsigned int p_need, p_size;
	off_t m_address, offset;
	void *v_address;
	int size = 4;
	char *map;

	p_size = sysconf(_SC_PAGE_SIZE);
	m_address = addr & ~(off_t)(p_size - 1);
	offset    = addr & (p_size - 1);
	p_need    = (offset + size) & ~(p_size - 1);

	if (((offset + size) & (p_size - 1)) != 0)
		p_need += p_size;

	map = mmap(NULL, p_need, PROT_READ | PROT_WRITE, MAP_SHARED,
		   ctx->fd, m_address);
	if (map == MAP_FAILED) {
		perror("mmap failed");
		exit(1);
	}

	v_address = (char *)map + (unsigned int)offset;
	*(int *)(v_address) = val;

	msync(map, p_need, MS_SYNC);
	munmap(map, p_need);
}

static int __kdcu_read(void *ptr, int bar, __u32 addr, __u32 *val)
{
	struct kdc_user_ctx *ctx = (struct kdc_user_ctx *)ptr;

	if (!ctx->base[bar]) {
		fprintf(stderr, "BAR '%d' is not available\n", bar);
		return -ENODEV;
	}

	*val = kdcu_get_vaddr(ctx, (off_t)(ctx->base[bar] + addr));
	return 0;
}

static int __kdcu_write(void *ptr, int bar, __u32 addr, __u32 val)
{
	struct kdc_user_ctx *ctx = (struct kdc_user_ctx *)ptr;

	if (!ctx->base[bar]) {
		fprintf(stderr, "BAR '%d' is not available\n", bar);
		return -ENODEV;
	}

	kdcu_set_vaddr(ctx, (off_t)(ctx->base[bar] + addr), val);
	return 0;
}

static int kdcu_read(struct kdc_cmd *cmd)
{
	int bar;

	switch (cmd->op_id) {
	case 0:
		bar = 0;
		break;
	case 1:
		bar = 1;
		break;
	case 2:
		bar = 2;
		break;
	case 3:
		bar = 3;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return __kdcu_read(cmd->call_ptr, bar, cmd->address, &cmd->data);
}

static int kdcu_write(struct kdc_cmd *cmd)
{
	int bar;

	switch (cmd->op_id) {
	case 0:
		bar = 0;
		break;
	case 1:
		bar = 1;
		break;
	case 2:
		bar = 2;
		break;
	case 3:
		bar = 3;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return __kdcu_write(cmd->call_ptr, bar, cmd->address, cmd->data);
}

static void init_decoder(lzma_stream *stream)
{
	lzma_ret ret = lzma_stream_decoder(stream, UINT64_MAX, LZMA_CONCATENATED);

	assert(ret == LZMA_OK);
}

static __u8 *lzma_run(lzma_stream *stream, FILE *fd, long *new_size)
{
	__u8 *inbuf, *outbuf, *data, *ptr;
	lzma_action action = LZMA_RUN;
	long size;

	inbuf = calloc(1, BUFSIZ);
	outbuf = calloc(1, BUFSIZ);
	assert(inbuf && outbuf);

	stream->next_in = NULL;
	stream->avail_in = 0;
	stream->next_out = outbuf;
	stream->avail_out = BUFSIZ;

	assert(fseek(fd, 0, SEEK_END) == 0);
	size = ftell(fd);
	assert(size > 0);
	data = calloc(size, sizeof(*data));
	assert(data);

	/* Compress the actual data now that everything is done */
	rewind(fd);
	ptr = data;
	while (1) {
		lzma_ret ret;

		if (stream->avail_in == 0 && !feof(fd)) {
			stream->next_in = inbuf;
			stream->avail_in = fread(inbuf, 1, BUFSIZ, fd);

			assert(!ferror(fd));

			if (feof(fd))
				action = LZMA_FINISH;
		}

		ret = lzma_code(stream, action);

		if (stream->avail_out == 0 || ret == LZMA_STREAM_END) {
			size_t write_size = BUFSIZ - stream->avail_out;
			long temp_size = *new_size + write_size;

			if (temp_size >= size) {
				ptr = realloc(data, temp_size * 2);
				assert(ptr);

				memcpy(ptr, data, *new_size);

				data = ptr;
				ptr = data + *new_size;
				size = temp_size * 2;
			}

			memcpy(ptr, outbuf, write_size);
			*new_size += write_size;
			ptr += write_size;

			stream->next_out = outbuf;
			stream->avail_out = BUFSIZ;
		}

		if (ret != LZMA_OK) {
			if (ret == LZMA_STREAM_END)
				break;
			fprintf(stderr, "compression error '%d'\n", ret);
			exit(1);
		}
	}

	lzma_end(stream);
	return data;
}

static long kdcu_get_data_xz(struct kdc_user_ctx *ctx, __u32 **ptr)
{
	lzma_stream stream = LZMA_STREAM_INIT;
	long new_size = 0;

	init_decoder(&stream);
	*ptr = (__u32 *)lzma_run(&stream, ctx->dest, &new_size);
	assert((new_size > 0) && !(new_size % sizeof(__u32)));

	return new_size / sizeof(__u32);
}

static long kdcu_get_data_hex(struct kdc_user_ctx *ctx, __u32 **ptr)
{
	size_t read_data;
	__u32 *data;
	long size32;

	if (fseek(ctx->dest, 0, SEEK_END) != 0) {
		perror("failed to seek for firmware end");
		exit(1);
	}

	size32 = ftell(ctx->dest) / sizeof(*data);
	if (size32 < 0) {
		perror("failed to read firmware size");
		exit(1);
	}

	rewind(ctx->dest);

	data = calloc(size32, sizeof(*data));
	if (!data) {
		perror("failed to allocate memory");
		exit(1);
	}

	read_data = fread(data, sizeof(*data), size32, ctx->dest);
	if (read_data != size32) {
		perror("failed to read firmware data");
		exit(1);
	}

	*ptr = data;

	return size32;
}

static struct kdc_ops kdcu_ops = {
	.read[0] = kdcu_read,
	.read[1] = kdcu_read,
	.read[2] = kdcu_read,
	.read[3] = kdcu_read,
	.write[0] = kdcu_write,
	.write[1] = kdcu_write,
	.write[2] = kdcu_write,
	.write[3] = kdcu_write,
};

int main(int argc, char **argv)
{
	struct kdc_user_ctx *ctx;
	int i, ret, section_id;
	bool debug = false;
	const char *ext;
	int base = 0;

	if (argc < 4) {
		printf("usage: %s [--verbose] <fw.hex> <fw-section>\n", argv[0]);
		printf("       <base-addr-bar0> [... <base-addr-barX>]\n");
		exit(1);
	}

	if (!strncmp(argv[1], "--verbose", strlen("--verbose"))) {
		debug = true;
		base++;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		perror("failed to allocate context");
		ret = -ENOMEM;
		goto out;
	}

	ctx->fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (ctx->fd < 0) {
		perror("failed to open /dev/mem");
		ret = -EIO;
		goto out_ctx;
	}

	for (i = 3 + base; i < MIN(argc, 3 + base + NUM_REGIONS); i++) {
		ctx->base[i - (3 + base)] = strtoul(argv[i], NULL, 0);
		if (!ctx->base[i - (3 + base)]) {
			fprintf(stderr, "failed to parse base address %d ('%s')\n",
				i - (3 + base), argv[i]);
			ret = -EINVAL;
			goto out_fd;
		}

		fprintf(stderr, "base address [%d]: 0x%08x\n",
			i - (3 + base), ctx->base[i - (3 + base)]);

		ctx->base_cnt++;
	}

	ctx->dest = fopen(argv[1 + base], "rb");
	if (!ctx->dest) {
		perror("failed to open firmware file");
		ret = -EIO;
		goto out_fd;
	}

	ext = strrchr(argv[1 + base], '.');
	if (ext && !strncmp(ext, ".xz", 3)) {
		ctx->data_size32 = kdcu_get_data_xz(ctx, &ctx->data);
		if (ctx->data_size32 < 0) {
			ret = ctx->data_size32;
			goto out_dest;
		}
	} else if (ext && !strncmp(ext, ".hex", 4)) {
		ctx->data_size32 = kdcu_get_data_hex(ctx, &ctx->data);
		if (ctx->data_size32 < 0) {
			ret = ctx->data_size32;
			goto out_dest;
		}
	} else {
		fprintf(stderr, "failed to recognize firmware file format\n");
		ret = -EINVAL;
		goto out_dest;
	}

	ctx->ptr = kdc_common_init(ctx->data, ctx->data_size32);
	if (!ctx->ptr) {
		ret = -EINVAL;
		goto out_data;
	}

	section_id = strtoul(argv[2 + base], NULL, 0);

	ctx->kdc_args.ops = &kdcu_ops;
	ctx->kdc_args.call_ptr = ctx;
	ctx->kdc_args.flags = debug ? KDC_PARSER_VERBOSE : 0;
	ctx->kdc_args.section_id = section_id;
	ctx->kdc_args.arguments[0] = (__u32)section_id;
	ctx->kdc_args.arguments[1] = (__u32)ctx->base_cnt;
	for (i = 0; i < ctx->base_cnt; i++)
		ctx->kdc_args.arguments[i + 2] = (__u32)ctx->base[i];

	ret = kdc_common_process(ctx->ptr, &ctx->kdc_args);
	kdc_common_exit(ctx->ptr);
out_data:
	free(ctx->data);
out_dest:
	fclose(ctx->dest);
out_fd:
	close(ctx->fd);
out_ctx:
	free(ctx);
out:
	exit(ret);
}
