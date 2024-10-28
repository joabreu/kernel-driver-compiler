/* Version parameter */
__version("kdc_sample_test_v1");

/* Addresses */
#define REG_RESULT	0x00
#define REG_TEST	0x00
#define REG_1		0x04
#define REG_2		0x08
#define REG_3		0x0c
#define REG_4		0x10

/* Values */
#define VAR_SUCCESS	0x10101010
#define VAR_FAILURE	0xffffffff
#define VAR_1		0xdeadcafe
#define VAR_2		0x12340000
#define VAR_3		0xbeef0000
#define VAR_4		0x00005678
#define INDEX1          0x2
#define INDEX2          0x3
#define INDEX3		0x4

/* RMW values */
#define VAR_RMW		0x0000cafe
#define MASK_RMW	0xffff0000
#define OFFSET_RMW	16

/* Global Typedef */
typedef r00 global_reg;
int global_array[2] = {0xbeef0000,0x0000cafe};

/*
 * reg: Address to read from.
 * val: Value to compare OR place to save the value.
 */
reg_read(reg, val)	{ R_0(reg, val); }

/*
 * reg: Address to write to.
 * val: Value to write.
 */
reg_write(reg, val)	{ W_0(reg, val); }

/*
 * id: Test number.
 */
test_fail(id)
{
	reg_write(REG_RESULT, VAR_FAILURE);
	reg_write(REG_RESULT, r02);
	STOP(id);
}

/*
 * id: Test number.
 */
test_pass(id)
{
	reg_write(REG_TEST, id);
	reg_write(REG_RESULT, VAR_SUCCESS);
	reg_write(REG_RESULT, r02);
}

/*
 * Test01:
 * - Writes to register and then compares back the result.
 */
test_01(reg, val)
{
	reg_write(reg, val);
	reg_read(reg, val);
}

/*
 * Test02:
 * - Writes to register and then, depending on value, executes
 *   conditional code.
 */
test_02(reg, val)
{
	typedef __r00 value_read;

	reg_write(reg, val);
	reg_read(reg, value_read);

	if (value_read == val) {
		test_pass(2);
	} else {
		test_fail(2);
	}
}

/*
 * Test03:
 * - Saves argument to register, writes register, and then reads it back again
 *   to different register. Depending on value, executes conditional code.
 */
test_03(reg, val)
{
	typedef __r00 value_back;
	typedef __r01 value_read;

	value_back = val;

	reg_write(reg, val);
	reg_read(reg, value_read);

	if (value_back == value_read) {
		test_pass(3);
	} else {
		test_fail(3);
	}
}

/*
 * Test04:
 * - Tests different conditional operators.
 */
test_04()
{
	typedef __r00 val_1;
	typedef __r01 val_2;
	typedef __r02 val_3;

	if (1 != 0) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	if (0 != 0) {
		test_fail(4);
	} else {
		test_pass(4);
	}

	if (0 | 1) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	if (0 & 1) {
		test_fail(4);
	} else {
		test_pass(4);
	}

	if (1 != 10) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	if (1 == 10) {
		test_fail(4);
	} else {
		test_pass(4);
	}

	if (10 > 1) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	if (10 < 1) {
		test_fail(4);
	} else {
		test_pass(4);
	}

	if (10 >= 10) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	if (10 <= 10) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	val_1 = 0xdead0000;
	val_2 = 0x0000beef;

	if (val_1 | val_2) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	if (val_1 & val_2) {
		test_fail(4);
	} else {
		test_pass(4);
	}

	if (val_1 >= val_2) {
		test_pass(4);
	} else {
		test_fail(4);
	}

	val_1 = 0xdead0000 | 0x0000beef;
	if (val_1 != 0xdeadbeef) {
		test_fail(4);
	}

	val_1 = 0xdead0000;
	val_2 = 0x0000cafe;
	val_3 = val_1 | val_2;
	if (val_3 != 0xdeadcafe) {
		test_fail(4);
	}

	DUMP(val_3);
}

rmw_shifted(reg, val, mask, offset)
{
	typedef __r00 value_write;

	value_write = val << offset;
	RMW_0(reg, value_write, mask);
}

test_05(reg, val, mask, offset)
{
	typedef __r00 value_write;
	typedef __r01 value_read;
	typedef __r02 value_check;
	typedef __r03 value_tmp;

	value_write = 0xbeef;

	reg_write(reg, value_write);		/* Set default reg value */
	rmw_shifted(reg, val, mask, offset);	/* Set new value */
	reg_read(reg, value_read);

	value_tmp = val << offset;
	value_check = value_read & mask;
	if (value_check != value_tmp) {
		test_fail(5);
	} else {
		reg_write(reg, 0xcafe);
		reg_read(reg, 0xcafe);
	}

	value_check = ~mask;
	value_check = value_read & value_check;
	if (value_check != value_write) {
		test_fail(5);
	} else {
		reg_write(reg, 0xdead);
		reg_read(reg, 0xdead);
	}
}

test_06(reg1, reg2, reg3)
{
	typedef __r01 index1;
	index1 = 0;

	typedef __r02 index2;
	index2 = 5;

	typedef __r03 result;

	int a_array[4] = {1,2,3,4};
	int b_array[6] = {4,3,2,1,8,6};
	int d_array[4] = {4,2,20,4};

	result = a_array[index1];

	if (result == 1) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = a_array[1];

	if (result == 2) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = a_array[reg1];

	if (result == 3) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = a_array[reg2];

	if (result == 4) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = b_array[3];

	if (result == 1) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = b_array[reg3];

	if (result == 8) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = b_array[index2];

	if (result == 6) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = global_array[0];

	if (result == 0xbeef0000) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	result = global_array[1];

	if (result == 0xcafe) {
		test_pass(6);
	} else {
		test_fail(6);
	}

	typedef __r05 index3;
	index3 = 0;
	typedef __r06 value;
	value = 0;

	result = 0;
	__r04 = 0x1;

	while (__r04) {

		if (index3 == 4)
			break;

		value = d_array[index3];
		result = result + value;
		index3 = index3 + 1;
	}

	if (result == 30) {
		test_pass(6);
	} else {
		test_fail(6);
	}
}

test_07(val)
{
	if (global_reg != val)
		test_fail(7);
	DUMP(global_reg);
	DUMP(val);

	test_pass(7);
}

/*
 * Section 0:
 * - Executes all tests.
 */
__section(1, section_id, bar_cnt, bar0_addr)
{
	global_reg = VAR_4;

	DUMP(section_id);
	DUMP(bar_cnt);

	__r00 = bar_cnt;
	while (__r00 > 0) {
		DUMP(bar0_addr);
		__r00 = __r00 - 1;
	}

	test_01(REG_1, VAR_1);
	test_02(REG_2, VAR_2);
	test_03(REG_3, VAR_3);
	test_04();
	test_05(REG_3, VAR_RMW, MASK_RMW, OFFSET_RMW);
	test_06(INDEX1, INDEX2, INDEX3);
	test_07(VAR_4);
	SLEEP(500000); /* 0.5 sec */
	STOP(0);
}

__section(2)
{
	PRINT("hello world!");
}
