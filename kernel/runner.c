// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "kdc_api.h"
#include "kdc_parser.c"

MODULE_LICENSE("Dual BSD/GPL");

struct kdc_kernel_ctx {
	const struct firmware *fw;
	struct device *dev;
	/* Lock to prevent re-entrance when already running some section */
	struct mutex lock;
	void *ptr;
};

int kdc_process(void *ptr, struct kdc_args *args)
{
	struct kdc_kernel_ctx *ctx = (struct kdc_kernel_ctx *)ptr;
	int ret;

	WARN_ON(in_interrupt());

	mutex_lock(&ctx->lock);
	ret = kdc_common_process(ctx->ptr, args);
	mutex_unlock(&ctx->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(kdc_process);

void *kdc_parse(struct device *dev, const char *name)
{
	struct kdc_kernel_ctx *ctx;
	__u32 *data;
	long size32;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->dev = dev;
	mutex_init(&ctx->lock);

	ret = request_firmware(&ctx->fw, name, dev);
	if (ret) {
		dev_err(dev, "failed to request firmware %s\n", name);
		goto free;
	}

	if (ctx->fw->size % sizeof(u32)) {
		dev_err(dev, "invalid / corrupted firmware\n");
		ret = -EINVAL;
		goto free_req;
	}

	data = (u32 *)ctx->fw->data;
	size32 = ctx->fw->size / sizeof(u32);

	ctx->ptr = kdc_common_init(data, size32);
	if (!ctx->ptr) {
		ret = -EINVAL;
		goto free_req;
	}

	return ctx;

free_req:
	release_firmware(ctx->fw);
free:
	kfree(ctx);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(kdc_parse);

void kdc_release(void *ptr)
{
	struct kdc_kernel_ctx *ctx = (struct kdc_kernel_ctx *)ptr;

	if (ctx && ctx->ptr)
		kdc_common_exit(ctx->ptr);
	if (ctx && ctx->fw)
		release_firmware(ctx->fw);
	kfree(ctx);
}
EXPORT_SYMBOL_GPL(kdc_release);
