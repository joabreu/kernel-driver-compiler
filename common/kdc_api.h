/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __KDC_API_H__
#define __KDC_API_H__

#if !defined(__ASSEMBLY__)

#if defined(__KERNEL__)
#include <linux/types.h>
#else /* __KERNEL__ */
#include <stdint.h>
typedef uint8_t   __u8;
typedef int8_t    __s8;
typedef uint16_t  __u16;
typedef int16_t   __s16;
typedef uint32_t  __u32;
typedef int32_t   __s32;
typedef uint64_t  __u64;
typedef int64_t   __s64;
#endif /* __KERNEL__ */

#define KDC_SIZE_GET(f) \
	(((f) & KDC_FLAG_SIZE_MASK) >> KDC_FLAG_SIZE_SHIFT)
#define KDC_SIZE_SET(f) \
	(((f) << KDC_FLAG_SIZE_SHIFT) & KDC_FLAG_SIZE_MASK)

#define KDC_FIELD_INV		0xdeadbeef
#define KDC_MAX_DEPTH		20
#define KDC_SCOPE_SEC		0
#define KDC_SCOPE_FUN		1
#define KDC_SCOPE_BLK		2

/** List of sections that can be present in the binary.
 *  The section values are present in kdc_section::id.
 */
enum kdc_sections {
	/** First valid run section index */
	KDC_SECTION_INIT_0 = 0x0,
	/** Last valid run section index */
	KDC_SECTION_INIT_MAX = 0xffff,
	/** First valid resources (e.g. functions) section index */
	KDC_SECTION_RES_0 = 0x10000,
	/** Last valid resources section index */
	KDC_SECTION_RES_MAX = 0x0fff0000,
	/** Header section index */
	KDC_SECTION_HEADER = 0x10000000,
	/** First valid parameters (e.g. strings) section index */
	KDC_SECTION_PARAMS_0 = 0x10000001,
	/** Last valid parameters section index */
	KDC_SECTION_PARAMS_MAX = 0x1000ffff,
	/** Last valid section index */
	KDC_SECTION_MAX,
};

/** Flag values for instructions.
 *  The flag values are present in kdc_field::flags.
 */
enum kdc_flags {
	/** Mask for size of instruction */
	KDC_FLAG_SIZE_MASK = 0x0000000f,
	/** Shift for size of instruction */
	KDC_FLAG_SIZE_SHIFT = 0,
	/** Modifiers base value */
	KDC_FLAG_MODS = 0x10,
	/** Return instruction modifier */
	KDC_FLAG_MODS_RET = KDC_FLAG_MODS << 0,
	/** Break instruction modifier */
	KDC_FLAG_MODS_BRK = KDC_FLAG_MODS << 1,
	/** Mask for modifier of instruction */
	KDC_FLAG_MODS_MASK = 0x000000f0,
	/** Shift for modifier of instruction */
	KDC_FLAG_MODS_SHIFT = 4,
	/** Not value present bitfield base value */
	KDC_FLAG_NVAL = 0x100,
	/** Mask for not value present bitfield */
	KDC_FLAG_NVAL_MASK = 0x0000ff00,
	/** Shift for not value present bitfield */
	KDC_FLAG_NVAL_SHIFT = 8,
	/** Number of available fields */
	KDC_FLAG_NVAL_COUNT = (KDC_FLAG_NVAL_MASK >> KDC_FLAG_NVAL_SHIFT) + 1,
};

/** Field values of Non-value data
 *  These fields are only used when KDC_FLAG_NVAL is set on kdc_field::flags.
 */
enum kdc_flags_nval {
	/** Register present bitfield base value */
	KDC_FLAG_REG = 1U << 31,
	/** Variable present bitfield base value */
	KDC_FLAG_VAR = 1U << 30,
	/** Internal register present bitfield base value */
	KDC_FLAG_IREG = 1U << 29,
	/** Array pointer index */
	KDC_FLAG_IDX = 1U << 28,
	/** Not value flags mask */
	KDC_FLAG_MASK = 0xffff0000,
	/** Not value data mask */
	KDC_FLAG_DATA = 0x0000ffff,
	/** Max. number of registers / variables / internal registers */
	KDC_FLAG_REGS_COUNT = 100,
};

/** Fields for section flags which define the type of special data. */
enum kdc_flags_section {
	/** Set if section contains binary data */
	KDC_FLAG_SECTION_DATA = KDC_SECTION_MAX + 1,
	/** Set if section contains string data */
	KDC_FLAG_SECTION_STR,
};

/** Header section content */
struct kdc_header {
	/** Version field of .c file that gave origin to this firmware */
	__u32 version;
	/** Timestamp field. References 'section_id' containing string */
	__u32 timestamp;
	/** CRC32 field of the origin .c file */
	__u32 crc;
};

/** Agnostic section definition */
struct kdc_section {
	/** Section ID */
	__u32 id;
	/** Section size in words */
	__u32 size;
	/** Section name. References 'section_id' containing string or
	 *  kdc_flags_section flag
	 */
	__u32 name;
	/** Number of instructions present in this section */
	__u32 insts;
	/** Start of instructions */
	__u32 data[];
};

/** Runnable instruction */
struct kdc_field {
	/** Instruction ID */
	__u32 id;
	/** Instruction flags */
	__u32 flags;
	/** Start of instruction */
	__u32 data[];
};

/** Possible instructions ID's.
 *  The instructions ID values are present in kdc_field::id.
 */
enum kdc_operations {
	/** Invalid operation ID. Not used */
	KDC_OPERATION_INVALID = 0,
	/** Jump operation ID */
	KDC_OPERATION_JUMP = 1,
	/** Jump IF-ELSE operation ID */
	KDC_OPERATION_JUMP_IFE = 2,
	/** Set register operation ID */
	KDC_OPERATION_SET = 3,
	/** Stop execution operation ID */
	KDC_OPERATION_STOP = 4,
	/** Sleep operation ID */
	KDC_OPERATION_SLEEP = 5,
	/** Dump operation ID */
	KDC_OPERATION_DUMP = 6,
	/** While loop operation ID */
	KDC_OPERATION_WHILE = 7,
	/** Print operation ID */
	KDC_OPERATION_PRINT = 8,
	/** Mask for operation ID */
	KDC_OPERATION_MASK = 0x0000ffff,
	/** Read operation ID */
	KDC_OPERATION_READ_X = 1 << 16,
	/** Write operation ID */
	KDC_OPERATION_WRITE_X =  2 << 16,
	/** RMW operation ID */
	KDC_OPERATION_RMW_X = 3 << 16,
	/** Custom operation ID */
	KDC_OPERATION_CUSTOM_X = 4 << 16,
	/** Mask for operations type _X */
	KDC_OPERATION_X_MASK = 0x00ff0000,
};

/** Possible conditions ID's.
 *  The conditions are enconded in instructions.
 */
enum kdc_conditions {
	/** Invalid condition ID */
	KDC_COND_INVALID = 0,
	/** OR condition ID */
	KDC_COND_OR = 1,
	/** AND condition ID */
	KDC_COND_AND = 2,
	/** Logical-OR condition ID */
	KDC_COND_LOR = 3,
	/** Logical-XOR condition ID */
	KDC_COND_LXOR = 4,
	/** Logical-AND condition ID */
	KDC_COND_LAND = 5,
	/** Not-Equal condition ID */
	KDC_COND_NEQ = 6,
	/** Equal condition ID */
	KDC_COND_EQ = 7,
	/** Greater-than-equal condition ID */
	KDC_COND_GE = 8,
	/** Less-than-equal condition ID */
	KDC_COND_LE = 9,
	/** Greater-than condition ID */
	KDC_COND_GT = 10,
	/** Less-than condition ID */
	KDC_COND_LT = 11,
	/** Plus ID */
	KDC_COND_PLUS = 12,
	/** Minus ID */
	KDC_COND_MINUS = 13,
	/** Multiplication ID */
	KDC_COND_MULT = 14,
	/** Division ID */
	KDC_COND_DIV = 15,
	/** Remainder ID */
	KDC_COND_MOD = 16,
	/** Right-shift ID */
	KDC_COND_RSHIFT = 17,
	/** Left-shift ID */
	KDC_COND_LSHIFT = 18,
	/** Not ID */
	KDC_COND_NOT = 19,
	/** Negation ID */
	KDC_COND_NEG = 20,
	/** Max number of possible conditions */
	KDC_COND_MAX = 255,
};

/** Flag values for firmware parser.
 *  The flag values are present in kdc_args::flags.
 */
enum kdc_parser_flags {
	/** Flag to enable verbose mode on parsing */
	KDC_PARSER_VERBOSE = 1U << 0,
};

/** Firmware command for low-level executor */
struct kdc_cmd {
	/** Caller private pointer */
	void *call_ptr;
	/** Operation ID */
	__u32 op_id;
	/** Input value for operation */
	__u32 address;
	/** Output value for operation */
	__u32 data;
};

/** Firmware parser low-level callbacks of executor */
struct kdc_ops {
	/** Callbacks for read operations */
	int (*read[KDC_OPERATION_MASK])(struct kdc_cmd *cmd);
	/** Callbacks for write operations */
	int (*write[KDC_OPERATION_MASK])(struct kdc_cmd *cmd);
	/** Callbacks for custom operations */
	int (*custom[KDC_OPERATION_MASK])(struct kdc_cmd *cmd);
};

/** Firmware initial run arguments. */
struct kdc_args {
	/** Section ID to run */
	__u32 section_id;
	/** Input arguments for section. */
	__u32 arguments[KDC_FLAG_REGS_COUNT];
	/** Callbacks to use for run */
	struct kdc_ops *ops;
	/** Call pointer to pass to callbacks */
	void *call_ptr;
	/** Extra flags for firmware parser logic */
	__u32 flags;
};

#define KDC_ERR_LEVEL			"[KDC Bug]: "
#define KDC_WARN_LEVEL			"[KDC Warn]: "
#define KDC_INFO_LEVEL			"[KDC Info]: "
#define KDC_DEBUG_LEVEL			"[KDC Debug]: "

#if defined(__KERNEL__)

struct device;

/* Provided by fwlib */
int kdc_process(void *ptr, struct kdc_args *args);
void *kdc_parse(struct device *dev, const char *name);
void kdc_release(void *ptr);

#define KDC_ERR(__fmt, ...)		pr_err(KDC_ERR_LEVEL __fmt, ##__VA_ARGS__)
#define KDC_WARN(__fmt, ...)		pr_warn(KDC_WARN_LEVEL __fmt, ##__VA_ARGS__)
#define KDC_INFO(__fmt, ...)		pr_notice(KDC_INFO_LEVEL __fmt, ##__VA_ARGS__)
#define KDC_DEBUG(__l, __fmt, ...)	\
do { \
	if (__l) \
		pr_info(KDC_DEBUG_LEVEL __fmt, ##__VA_ARGS__); \
} while (0)
#define KDC_ZALLOC(__size)		kzalloc((__size), GFP_KERNEL)
#define KDC_FREE(__ptr)			kfree(__ptr)
#define KDC_UDELAY_MAX			10
#define KDC_USLEEP(__uval)		udelay(__uval)

#else /* __KERNEL__ */

#define KDC_ERR(__fmt, ...)		\
	fprintf(stderr, KDC_ERR_LEVEL __fmt, ##__VA_ARGS__)
#define KDC_WARN(__fmt, ...)	\
	fprintf(stderr, KDC_WARN_LEVEL __fmt, ##__VA_ARGS__)
#define KDC_INFO(__fmt, ...)	\
	fprintf(stderr, KDC_INFO_LEVEL __fmt, ##__VA_ARGS__)
#define KDC_DEBUG(__l, __fmt, ...)	\
do { \
	if (__l) \
		fprintf(stdout, KDC_DEBUG_LEVEL __fmt, ##__VA_ARGS__); \
} while (0)
#define KDC_ZALLOC(__size)		calloc((__size), 1)
#define KDC_FREE(__ptr)			free(__ptr)
#define KDC_UDELAY_MAX			(1000000 - 1)
#define KDC_USLEEP(__uval)		usleep(__uval)

#endif /* __KERNEL__ */
#endif /* __ASSEMBLY__ */

#endif /* __KDC_API_H__ */
