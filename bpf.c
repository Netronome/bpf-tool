/*
 * Copyright (C) 2017 Netronome Systems, Inc.
 *
 * This software is dual licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree or the BSD 2-Clause License provided below.  You have the
 * option to license this software under the complete terms of either license.
 *
 * The BSD 2-Clause License:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Author: Jakub Kicinski <kubakici@wp.pl> */

#include <libbpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_tool.h"

const char *bin_name;

static void __usage(void)
{
	fprintf(stderr,
		"Usage: %s OBJECT { COMMAND | help }\n"
		"       OBJECT := { program | map }\n",
		bin_name);
}

void usage(void)
{
	__usage();

	exit(-1);
}

static int do_help(int argc, char **argv)
{
	__usage();

	return 0;
}

int cmd_select(const struct cmd *cmds, int argc, char **argv,
	       int (*help)(int argc, char **argv))
{
	unsigned int i;

	if (argc < 1 && cmds[0].func)
		return cmds[0].func(argc, argv);

	for (i = 0; cmds[i].func; i++)
		if (is_prefix(*argv, cmds[i].cmd))
			return cmds[i].func(argc - 1, argv + 1);

	help(argc - 1, argv + 1);

	return -1;
}

bool is_prefix(const char *pfx, const char *str)
{
	if (strlen(str) < strlen(pfx))
		return false;

	return !memcmp(str, pfx, strlen(pfx));
}

void print_hex(void *arg, unsigned int n, const char *sep)
{
	unsigned char *data = arg;
	unsigned int i;

	for (i = 0; i < n; i++) {
		const char *pfx = "";

		if (!i)
			/* nothing */;
		else if (!(i % 16))
			printf("\n");
		else if (!(i % 8))
			printf("  ");
		else
			pfx = sep;

		printf("%s%02hhx", i ? pfx : "", data[i]);
	}
}

static const struct cmd cmds[] = {
	{ "help",	do_help },
	{ "program",	do_prog },
	{ "map",	do_map },
	{ 0 }
};

int main(int argc, char **argv)
{
	bin_name = argv[0];
	NEXT_ARG();

	return cmd_select(cmds, argc, argv, do_help);
}
