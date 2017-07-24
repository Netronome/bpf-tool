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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libbpf/bpf.h>

#include "bpf_tool.h"

static const char *map_type_name[] = {
	[BPF_MAP_TYPE_UNSPEC]		= "unspec",
	[BPF_MAP_TYPE_HASH]		= "hash",
	[BPF_MAP_TYPE_ARRAY]		= "array",
	[BPF_MAP_TYPE_PROG_ARRAY]	= "prog_array",
	[BPF_MAP_TYPE_PERF_EVENT_ARRAY]	= "perf_event_array",
	[BPF_MAP_TYPE_PERCPU_HASH]	= "percpu_hash",
	[BPF_MAP_TYPE_PERCPU_ARRAY]	= "percpu_array",
	[BPF_MAP_TYPE_STACK_TRACE]	= "stack_trace",
	[BPF_MAP_TYPE_CGROUP_ARRAY]	= "cgroup_array",
	[BPF_MAP_TYPE_LRU_HASH]		= "lru_hash",
	[BPF_MAP_TYPE_LRU_PERCPU_HASH]	= "lru_percpu_hash",
	[BPF_MAP_TYPE_LPM_TRIE]		= "lpm_trie",
	[BPF_MAP_TYPE_ARRAY_OF_MAPS]	= "array_of_maps",
	[BPF_MAP_TYPE_HASH_OF_MAPS]	= "hash_of_maps",
};

static unsigned int get_possible_cpus(void)
{
	static unsigned int result;
	char buf[128];
	long int n;
	char *ptr;
	int fd;

	if (result)
		return result;

	fd = open("/sys/devices/system/cpu/possible", O_RDONLY);
	if (fd < 1) {
		err("can't open sysfs possible cpus\n");
		exit(-1);
	}

	n = read(fd, buf, sizeof(buf));
	if (n < 2) {
		err("can't read sysfs possible cpus\n");
		exit(-1);
	}
	close(fd);

	if (n == sizeof(buf)) {
		err("read sysfs possible cpus overflow\n");
		exit(-1);
	}

	ptr = buf;
	n = 0;
	while (*ptr && *ptr != '\n') {
		unsigned int a, b;

		if (sscanf(ptr, "%u-%u", &a, &b) == 2) {
			n += b - a + 1;

			ptr = strchr(ptr, '-') + 1;
		} else if (sscanf(ptr, "%u", &a) == 1) {
			n++;
		}

		while (isdigit(*ptr))
			ptr++;
		if (*ptr == ',')
			ptr++;
	}

	result = n;

	return result;
}

static bool map_is_per_cpu(__u32 type)
{
	return type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static void *alloc_value(struct bpf_map_info *info)
{
	if (map_is_per_cpu(info->type))
		return malloc(info->value_size * get_possible_cpus());
	else
		return malloc(info->value_size);
}

static int map_parse_fd(int *argc, char ***argv)
{
	int fd;

	if (is_prefix(**argv, "id")) {
		unsigned int id;
		char *endptr;

		NEXT_ARGP();

		id = strtoul(**argv, &endptr, 0);
		if (*endptr) {
			err("can't parse %s as ID\n", **argv);
			return -1;
		}
		NEXT_ARGP();

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 1)
			err("get map by id (%u): %s\n", id, strerror(errno));
		return fd;
	} else if (is_prefix(**argv, "pinned")) {
		char *path;
		int type;

		NEXT_ARGP();

		path = **argv;
		NEXT_ARGP();

		fd = bpf_obj_get(path);
		if (fd < 1) {
			err("bpf obj get (%s): %s\n", path, strerror(errno));
			return -1;
		}

		type = get_fd_type(fd);
		if (type < 0)
			return type;
		if (type != BPF_OBJ_MAP) {
			err("incorrect object type: %s\n",
			    get_fd_type_name(type));
			return -1;
		}

		return fd;
	}

	err("expected 'id' or 'pinned', got: '%s'?\n", **argv);
	return -1;
}

static int
map_parse_fd_and_info(int *argc, char ***argv, void *info, __u32 *info_len)
{
	int err;
	int fd;

	fd = map_parse_fd(argc, argv);
	if (fd < 1)
		return -1;

	err = bpf_obj_get_info_by_fd(fd, info, info_len);
	if (err) {
		err("can't get map info: %s\n", strerror(errno));
		close(fd);
		return err;
	}

	return fd;
}

static void print_entry(struct bpf_map_info *info, unsigned char *key,
			unsigned char *value)
{
	unsigned int i, n;

	if (!map_is_per_cpu(info->type)) {
		/* Single line print */
		if (info->key_size + info->value_size <= 24 &&
		    max(info->key_size, info->value_size) <= 16) {
			printf("key: ");
			print_hex(key, info->key_size, " ");
			printf("  value: ");
			print_hex(value, info->value_size, " ");
			return;
		}

		printf("key: ");
		print_hex(key, info->key_size, " ");
		printf("\nvalue: ");
		print_hex(value, info->value_size, " ");
		printf("\n");

		return;
	}

	n = get_possible_cpus();

	printf("key:\n");
	print_hex(key, info->key_size, " ");
	printf("\n");
	for (i = 0; i < n; i++) {
		printf("value (CPU %02d):%c",
		       i, info->value_size > 16 ? '\n' : ' ');
		print_hex(value + i * info->value_size, info->value_size, " ");
		printf("\n");
	}
}

static char **parse_val(char **argv, const char *name, unsigned char *val,
			unsigned int n)
{
	unsigned int i = 0;
	char *endptr;

	while (i < n && argv[i]) {
		val[i] = strtoul(argv[i], &endptr, 0);
		if (*endptr) {
			err("error parsing byte: %s\n", argv[i]);
			break;
		}
		i++;
	}

	if (i != n) {
		err("%s expected %d bytes got %d\n", name, n, i);
		return NULL;
	}

	return argv + i;
}

static int parse_elem(char **argv, void *key, void *value,
		      __u32 key_size, __u32 value_size, __u32 *flags)
{
	if (!*argv) {
		if (!key && !value)
			return 0;
		err("did not find %s\n", key ? "key" : "value");
		return -1;
	}

	if (is_prefix(*argv, "key")) {
		if (!key) {
			if (key_size)
				err("duplicate key\n");
			else
				err("unnecessary key\n");
			return -1;
		}

		argv = parse_val(argv + 1, "key", key, key_size);
		if (!argv)
			return -1;

		return parse_elem(argv,	NULL, value, key_size, value_size,
				  flags);
	} else if (is_prefix(*argv, "value")) {
		if (!value) {
			if (value_size)
				err("duplicate value\n");
			else
				err("unnecessary value\n");
			return -1;
		}

		argv = parse_val(argv + 1, "value", value, value_size);
		if (!argv)
			return -1;

		return parse_elem(argv,	key, NULL, key_size, value_size, flags);
	} else if (is_prefix(*argv, "any") || is_prefix(*argv, "noexist")||
		   is_prefix(*argv, "exist")) {
		if (!flags) {
			err("flags specified multiple times: %s\n", *argv);
			return -1;
		}

		if (is_prefix(*argv, "any"))
			*flags = BPF_ANY;
		else if (is_prefix(*argv, "noexist"))
			*flags = BPF_NOEXIST;
		else if (is_prefix(*argv, "exist"))
			*flags = BPF_EXIST;

		return parse_elem(argv + 1, key, value, key_size, value_size,
				  NULL);
	}

	err("expected key or value, got: %s\n", *argv);
	return -1;
}

static int show_map(struct bpf_map_info *info)
{
	printf("   %u: ", info->id);
	if (info->type < ARRAY_SIZE(map_type_name))
		printf("%s  ", map_type_name[info->type]);
	else
		printf("type:%u  ", info->type);

	printf("key:%uB  value:%uB  max_entries:%u  flags:0x%x\n",
	       info->key_size, info->value_size, info->max_entries,
	       info->map_flags);

	return 0;
}

static int do_show(int argc, char **argv)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	__u32 id = 0;
	int err;
	int fd;

	if (argc == 2) {
		fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
		if (fd < 0)
			return -1;

		return show_map(&info);
	}

	if (argc)
		return BAD_ARG();

	while (!(err = bpf_map_get_next_id(id, &id))) {
		fd = bpf_map_get_fd_by_id(id);
		if (fd < 1) {
			err("can't get map by id (%u): %s\n",
			    id, strerror(errno));
			return -1;
		}

		err = bpf_obj_get_info_by_fd(fd, &info, &len);
		close(fd);
		if (err) {
			err("can't get map info: %s\n", strerror(errno));
			return -1;
		}

		show_map(&info);
	}

	return errno == ENOENT ? 0 : -1;
}

static int do_dump(int argc, char **argv)
{
	void *key, *value, *prev_key;
	unsigned int num_elems = 0;
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	int err;
	int fd;

	if (argc != 2)
		usage();

	fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
	if (fd < 0)
		return -1;

	key = malloc(info.key_size);
	value = alloc_value(&info);
	if (!key || !value) {
		err("mem alloc failed\n");
		err = -1;
		goto exit_free;
	}

	prev_key = NULL;
	while (true) {
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		err = bpf_map_lookup_elem(fd, key, value);
		if (err) {
			info("can't lookup element with key: ");
			print_hex(key, info.key_size, " ");
			printf("\n");
			continue;
		}

		print_entry(&info, key, value);
		printf("\n");

		prev_key = key;
		num_elems++;
	}

	printf("Found %u element%s\n", num_elems, num_elems != 1 ? "s" : "");

exit_free:
	free(key);
	free(value);
	close(fd);

	return err;
}

static int do_update(int argc, char **argv)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	void *key, *value;
	__u32 flags;
	int err;
	int fd;

	if (argc < 2)
		usage();

	fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
	if (fd < 0)
		return -1;

	key = malloc(info.key_size);
	value = alloc_value(&info);
	if (!key || !value) {
		err("mem alloc failed");
		err = -1;
		goto exit_free;
	}

	err = parse_elem(argv, key, value, info.key_size, info.value_size,
			 &flags);
	if (err)
		goto exit_free;

	err = bpf_map_update_elem(fd, key, value, flags);
	if (err) {
		err("update failed: %s\n", strerror(errno));
		goto exit_free;
	}

exit_free:
	free(key);
	free(value);
	close(fd);

	return err;
}

static int do_lookup(int argc, char **argv)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	void *key, *value;
	int err;
	int fd;

	if (argc < 2)
		usage();

	fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
	if (fd < 0)
		return -1;

	key = malloc(info.key_size);
	value = alloc_value(&info);
	if (!key || !value) {
		err("mem alloc failed");
		err = -1;
		goto exit_free;
	}

	err = parse_elem(argv, key, NULL, info.key_size, 0, NULL);
	if (err)
		goto exit_free;

	err = bpf_map_lookup_elem(fd, key, value);
	if (!err) {
		print_entry(&info, key, value);
	} else if (errno == ENOENT) {
		printf("key:\n");
		print_hex(key, info.key_size, " ");
		printf("\n\nNot found\n");
	} else {
		err("lookup failed: %s\n", strerror(errno));
	}

exit_free:
	free(key);
	free(value);
	close(fd);

	return err;
}

static int do_getnext(int argc, char **argv)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	void *key, *nextkey;
	int err;
	int fd;

	if (argc < 2)
		usage();

	fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
	if (fd < 0)
		return -1;

	key = malloc(info.key_size);
	nextkey = malloc(info.key_size);
	if (!key || !nextkey) {
		err("mem alloc failed");
		err = -1;
		goto exit_free;
	}

	if (argc) {
		err = parse_elem(argv, key, NULL, info.key_size, 0, NULL);
		if (err)
			goto exit_free;
	} else {
		free(key);
		key = NULL;
	}

	err = bpf_map_get_next_key(fd, key, nextkey);
	if (err) {
		err("can't get next key: %s\n", strerror(errno));
		goto exit_free;
	}

	if (key) {
		printf("key:\n");
		print_hex(key, info.key_size, " ");
		printf("\n");
	} else {
		printf("key: None\n");
	}

	printf("next key:\n");
	print_hex(nextkey, info.key_size, " ");
	printf("\n");

exit_free:
	free(nextkey);
	free(key);
	close(fd);

	return err;
}

static int do_delete(int argc, char **argv)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	void *key;
	int err;
	int fd;

	if (argc < 2)
		usage();

	fd = map_parse_fd_and_info(&argc, &argv, &info, &len);
	if (fd < 0)
		return -1;

	key = malloc(info.key_size);
	if (!key) {
		err("mem alloc failed");
		err = -1;
		goto exit_free;
	}

	err = parse_elem(argv, key, NULL, info.key_size, 0, NULL);
	if (err)
		goto exit_free;

	err = bpf_map_delete_elem(fd, key);
	if (err)
		err("delete failed: %s\n", strerror(errno));

exit_free:
	free(key);
	close(fd);

	return err;
}

static int do_pin(int argc, char **argv)
{
	return do_pin_any(argc, argv, bpf_map_get_fd_by_id);
}

static int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %s %s show   [MAP]\n"
		"       %s %s dump    MAP\n"
		"       %s %s update  MAP  key BYTES value BYTES [UPDATE_FLAGS]\n"
		"       %s %s lookup  MAP  key BYTES\n"
		"       %s %s getnext MAP [key BYTES]\n"
		"       %s %s delete  MAP  key BYTES\n"
		"       %s %s pin     MAP  FILE\n"
		"       %s %s help\n"
		"\n"
		"       MAP := { id MAP_ID | pinned FILE }\n"
		"       UPDATE_FLAGS := { any | exist | noexist }\n"
		"",
		bin_name, argv[-2], bin_name, argv[-2], bin_name, argv[-2],
		bin_name, argv[-2], bin_name, argv[-2], bin_name, argv[-2],
		bin_name, argv[-2], bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "help",	do_help },
	{ "dump",	do_dump },
	{ "update",	do_update },
	{ "lookup",	do_lookup },
	{ "getnext",	do_getnext },
	{ "delete",	do_delete },
	{ "pin",	do_pin },
	{ 0 }
};

int do_map(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
