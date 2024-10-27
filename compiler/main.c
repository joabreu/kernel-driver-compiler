#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <lzma.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include "include/stack.h"
#include "include/global.h"
#include "include/syntax.h"

int yyparse(void);
int yydebug;

struct context *ctx;

static bool check_arg(const char *arg, const char *exp)
{
	size_t len = MAX(strlen(arg), strlen(exp));

	if (!strncmp(arg, exp, len))
		return true;

	return false;
}

static void print_usage(const char *name)
{
	printf("usage: %s [--verbose] <[-d | -dt | <input.c>]> <output.xz>\n", name);
	exit(1);
}

static __u32 compute_crc(FILE *fd)
{
	__u32 crc = crc32(0, NULL, 0);
	int c;

	rewind(fd);
	while (1) {
		c = fgetc(fd);
		if (feof(fd))
			break;

		crc = crc32(crc, (unsigned char *)&c, 1);
	}
	rewind(fd);

	INF(ctx->verbose, "crc: 0x%08x\n", crc);
	return crc;
}

static void init_encoder(lzma_stream *stream)
{
	lzma_ret ret = lzma_easy_encoder(stream, 5, LZMA_CHECK_CRC32);

	assert(ret == LZMA_OK);
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
			ERR("compression error '%d'\n", ret);
		}
	}

	lzma_end(stream);
	return data;
}

static long get_kdc_raw_data(FILE *fd, __u32 **ptr)
{
	__u32 *data;
	long size;

	assert(fseek(fd, 0, SEEK_END) == 0);

	size = ftell(fd) / sizeof(*data);
	assert(size > 0);

	rewind(fd);

	data = calloc(size, sizeof(*data));
	assert(data);

	assert(fread(data, sizeof(*data), size, fd) == size);

	*ptr = data;
	return size;
}

int main(int argc, char **argv)
{
	lzma_stream stream = LZMA_STREAM_INIT;
	long new_size = 0;
	struct stat attr;
	int pos = 0;
	__u8 *ptr;

	argc--;

	if (argc < 2)
		print_usage(argv[0]);

	ctx = calloc(1, sizeof(*ctx));

	if (argc > 2 && check_arg(argv[1], "--verbose")) {
		ctx->verbose = true;
		pos = 1;
	}

	if (check_arg(argv[1 + pos], "-d")) {
		const char *ext;

		ctx->dest = fopen(argv[2 + pos], "rb");
		if (!ctx->dest)
			ERR("failed to open output file '%s'\n", argv[2 + pos]);

		ext = strrchr(argv[2 + pos], '.');
		if (ext && check_arg(ext, ".xz")) {
			init_decoder(&stream);
			ptr = lzma_run(&stream, ctx->dest, &new_size);
			assert((new_size > 0) && !(new_size % sizeof(__u32)));
			program_dump_raw((__u32 *)ptr, new_size / sizeof(__u32));
			free(ptr);
		} else if (ext && check_arg(ext, ".hex")) {
			__u32 *data;

			new_size = get_kdc_raw_data(ctx->dest, &data);
			program_dump_raw(data, new_size);
			free(data);
		} else {
			ERR("failed to recognize firmware file format\n");
		}

		goto exit_dump;
	} else if (check_arg(argv[1 + pos], "-dt")) {
		ERR("not supported yet\n");
	} else {
		yyin = fopen(argv[1 + pos], "r");
		if (!yyin)
			ERR("failed to open input file '%s'\n", argv[1 + pos]);

		ctx->dest = fopen(argv[2 + pos], "w+b");
		if (!ctx->dest)
			ERR("failed to open output file '%s'\n", argv[2 + pos]);
	}

	ctx->sections = list_new();
	ctx->defines = list_new();
	ctx->global_types = list_new();
	ctx->params = list_new();
	ctx->global_arrays = list_new();

	ctx->header.crc = compute_crc(yyin);

	if (stat(argv[1 + pos], &attr))
		ERR("failed to stat '%s'\n", argv[1 + pos]);

	yyparse();
	program_parse(ctx->head);

	if (ctx->verbose) {
		INF(1, "dumping parsed firmware:\n");
		program_dump(ctx->sections);
	}

	init_encoder(&stream);
	program_write(ctx->dest, &ctx->header, &attr.st_mtime, ctx->sections, ctx->params);
	ptr = lzma_run(&stream, ctx->dest, &new_size);
	assert(new_size > 0);

	/* Re-open for clear and write again */
	ctx->dest = freopen(argv[2 + pos], "wb", ctx->dest);
	assert(fwrite(ptr, sizeof(*ptr), new_size, ctx->dest) == new_size);

	free(ptr);
	fclose(yyin);
exit_dump:
	fclose(ctx->dest);
	exit(0);
}
