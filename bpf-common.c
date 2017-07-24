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

#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libbpf/bpf.h>

#include "bpf_tool.h"

int do_pin_any(int argc, char **argv, int (*get_fd_by_id)(__u32))
{
	unsigned int id;
	char *endptr;
	int err;
	int fd;

	if (!is_prefix(*argv, "id")) {
		err("expected 'id' got %s\n", *argv);
		return -1;
	}
	NEXT_ARG();

	id = strtoul(*argv, &endptr, 0);
	if (*endptr) {
		err("can't parse %s as ID\n", *argv);
		return -1;
	}
	NEXT_ARG();

	if (argc != 1)
		usage();

	fd = get_fd_by_id(id);
	if (fd < 1) {
		err("can't get prog by id (%u): %s\n", id, strerror(errno));
		return -1;
	}

	err = bpf_obj_pin(fd, *argv);
	close(fd);
	if (err) {
		err("can't pin the object (%s): %s\n", *argv, strerror(errno));
		if (errno == EPERM)
			err("is %s in BPF file system?\n", dirname(*argv));
		if (errno == ENOENT)
			err("is BPF file system mounted?\n");
		return -1;
	}

	return 0;
}

/* There seem to be no way today of telling whether pinned object is a map or
 * a program.  We work around this by checking if size of info has expected
 * size.  Note: this is likely to break in the future as info struct is
 * extended!
 */
int guess_fd_type(int fd)
{
	unsigned char buf[sizeof(struct bpf_map_info) +
			  sizeof(struct bpf_prog_info)];
	__u32 len = sizeof(buf);
	int err;

	err = bpf_obj_get_info_by_fd(fd, buf, &len);
	if (err) {
		err("can't get object info: %s\n", strerror(errno));
		return -1;
	}
	if (len == sizeof(struct bpf_map_info))
		return BPF_OBJ_MAP;
	else if (len == sizeof(struct bpf_prog_info))
		return BPF_OBJ_PROG;

	return BPF_OBJ_UNKNOWN;
}
