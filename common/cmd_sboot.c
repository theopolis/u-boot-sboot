/*
 * cmd_sboot.c
 */

#include <common.h>
#include <command.h>
#include <environment.h>
#include <sboot.h>

#include <sha1.h>

static int test_sboot_seal(void)
{
	uint8_t result;

	uint8_t key[20];

	memset(key, 0x10, 20);
	result = sboot_seal(key, 20, 0xd000);

	return 0;
}

/* u-boot command table (include/command.h)
 */

#define VOIDTEST(XFUNC) \
	int do_test_##XFUNC(cmd_tbl_t *cmd_tbl, int flag, int argc, \
	char * const argv[]) \
	{ \
		return test_##XFUNC(); \
	} \

	/* above blank line is a part of the macro */

#define VOIDENT(XNAME) \
  U_BOOT_CMD_MKENT(XNAME, 0, 1, do_test_##XNAME, "", "")

VOIDTEST(sboot_seal)


static cmd_tbl_t cmd_sboot_sub[] = {
	VOIDENT(sboot_seal),
};

/* u-boot shell commands
 */
static int do_sboot(cmd_tbl_t * cmdtp, int flag, int argc,
	char * const argv[])
{
	cmd_tbl_t *c;
	printf("argc = %d, argv = ", argc);
	do {
		int i = 0;
		for (i = 0; i < argc; i++)
			printf(" %s", argv[i]);
			printf("\n------\n");
		} while(0);
	argc--;
	argv++;
	c = find_cmd_tbl(argv[0], cmd_sboot_sub,
		ARRAY_SIZE(cmd_sboot_sub));
	return c ? c->cmd(cmdtp, flag, argc, argv) : cmd_usage(cmdtp);
}

U_BOOT_CMD(sboot, 2, 1, do_sboot, "SBOOT tests",
	"\n\tseal\n"
);

