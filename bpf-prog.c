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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libbpf/bpf.h>

#include "bpf_tool.h"

static const char *prog_type_name[] = {
	[BPF_PROG_TYPE_UNSPEC]		= "unspec",
	[BPF_PROG_TYPE_SOCKET_FILTER]	= "socket_filter",
	[BPF_PROG_TYPE_KPROBE]		= "kprobe",
	[BPF_PROG_TYPE_SCHED_CLS]	= "sched_cls",
	[BPF_PROG_TYPE_SCHED_ACT]	= "sched_act",
	[BPF_PROG_TYPE_TRACEPOINT]	= "tracepoint",
	[BPF_PROG_TYPE_XDP]		= "xdp",
	[BPF_PROG_TYPE_PERF_EVENT]	= "perf_event",
	[BPF_PROG_TYPE_CGROUP_SKB]	= "cgroup_skb",
	[BPF_PROG_TYPE_CGROUP_SOCK]	= "cgroup_sock",
	[BPF_PROG_TYPE_LWT_IN]		= "lwt_in",
	[BPF_PROG_TYPE_LWT_OUT]		= "lwt_out",
	[BPF_PROG_TYPE_LWT_XMIT]	= "lwt_xmit",
};

static int show_prog_by_id(unsigned int id, unsigned char *tag)
{
	struct bpf_prog_info info = { 0 };
	__u32 len = sizeof(info);
	int err;
	int fd;

	fd = bpf_prog_get_fd_by_id(id);
	if (fd < 1) {
		err("can't get prog by id (%u): %s\n", id, strerror(errno));
		return -1;
	}

	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	close(fd);

	if (err) {
		err("can't get prog info: %s\n", strerror(errno));
		return -1;
	}

	if (tag && memcmp(info.tag, tag, BPF_TAG_SIZE))
		return 0;

	printf("   %u: ", id);
	if (info.type < ARRAY_SIZE(prog_type_name))
		printf("%s  ", prog_type_name[info.type]);
	else
		printf("type:%u  ", info.type);

	printf("tag: ");
	print_hex(info.tag, BPF_TAG_SIZE, ":");

	printf("  jited: %uB  xlated: %uB  ",
	       info.jited_prog_len, info.xlated_prog_len);

	printf("\n");

	return 0;
}

static int do_show(int argc, char **argv)
{
	unsigned char tag[BPF_TAG_SIZE];
	bool have_tag = false;
	__u32 id = 0;
	int err;

	if (argc == 2) {
		if (is_prefix(*argv, "id")) {
			char *endptr;

			NEXT_ARG();

			id = strtoul(*argv, &endptr, 0);
			if (*endptr) {
				err("can't parse %s as ID\n", *argv);
				return -1;
			}

			return show_prog_by_id(id, NULL);
		} else if (is_prefix(*argv, "tag")) {
			NEXT_ARG();

			if (sscanf(*argv, BPF_TAG_FMT, tag, tag + 1, tag + 2,
				   tag + 3, tag + 4, tag + 5, tag + 6, tag + 7)
			    != BPF_TAG_SIZE) {
				err("can't parse tag\n");
				return -1;
			}
			have_tag = true;
		} else {
			err("what is '%s'?\n", *argv);
			return -1;
		}

		NEXT_ARG();
	}

	if (argc)
		return BAD_ARG();

	while (true) {
		err = bpf_prog_get_next_id(id, &id);
		if (err) {
			if (errno == ENOENT)
				break;
			err("can't get next prog: %s\n", strerror(errno));
			return -1;
		}

		err = show_prog_by_id(id, have_tag ? tag : NULL);
		if (err)
			return err;
	}

	return 0;
}

static int do_dump(int argc, char **argv)
{
	struct bpf_prog_info info = { 0 };
	unsigned int buf_size, id;
	__u32 len = sizeof(info);
	__u32 *member_len;
	__u64 *member_ptr;
	char *endptr;
	char *buf;
	ssize_t n;
	int err;
	int fd;

	if (is_prefix(*argv, "jited")) {
		member_len = &info.jited_prog_len;
		member_ptr = &info.jited_prog_insns;
	} else if (is_prefix(*argv, "xlated")) {
		member_len = &info.xlated_prog_len;
		member_ptr = &info.xlated_prog_insns;
	} else {
		err("expected 'xlated' or 'jited', got: %s\n", *argv);
		return -1;
	}
	NEXT_ARG();

	if (argc != 4)
		usage();

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

	if (!is_prefix(*argv, "file")) {
		err("expected 'file' got %s\n", *argv);
		return -1;
	}
	NEXT_ARG();

	fd = bpf_prog_get_fd_by_id(id);
	if (fd < 1) {
		err("can't get prog by id (%u): %s\n", id, strerror(errno));
		return -1;
	}

	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (err) {
		err("can't get prog info: %s\n", strerror(errno));
		return -1;
	}

	if (!*member_len) {
		info("no instructions returned\n");
		close(fd);
		return 0;
	}

	buf_size = *member_len;

	buf = malloc(buf_size);
	if (!buf) {
		err("mem alloc failed\n");
		close(fd);
		return -1;
	}

	memset(&info, 0, sizeof(info));

	*member_ptr = ptr_to_u64(buf);
	*member_len = buf_size;

	err = __bpf_obj_get_info_by_fd(fd, &info, &len);
	close(fd);
	if (err) {
		err("can't get prog info: %s\n", strerror(errno));
		goto err_free;
	}

	if (*member_len > buf_size) {
		info("too many instructions returned\n");
		goto err_free;
	}

	fd = open(*argv, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 1) {
		err("can't open file %s: %s\n", *argv, strerror(errno));
		goto err_free;
	}

	n = write(fd, buf, *member_len);
	close(fd);
	if (n != *member_len) {
		err("error writing output file: %s\n",
		    n < 0 ? strerror(errno) : "short write");
		goto err_free;
	}

	free(buf);

	return 0;

err_free:
	free(buf);
	return -1;
}

static int do_pin(int argc, char **argv)
{
	return do_pin_any(argc, argv, bpf_prog_get_fd_by_id);
}

static int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %s %s show\n"
		"       %s %s show id PROG_ID\n"
		"       %s %s show tag PROG_TAG\n"
		"       %s %s dump xlated id PROG_ID file FILE\n"
		"       %s %s dump jited  id PROG_ID file FILE\n"
		"       %s %s pin id PROG_ID FILE\n"
		"       %s %s help\n"
		"",
		bin_name, argv[-2], bin_name, argv[-2], bin_name, argv[-2],
		bin_name, argv[-2], bin_name, argv[-2], bin_name, argv[-2],
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "dump",	do_dump },
	{ "pin",	do_pin },
	{ 0 }
};

int do_prog(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
