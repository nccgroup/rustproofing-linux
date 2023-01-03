// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// PoC buggy driver leaking kernel stack data.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#define u8 unsigned char
#define u64 unsigned long long

struct vuln_info {
	u8 version;
	u64 id;
	u8 _reserved;
};

#define VULN_GET_INFO _IOR('v', 2, struct vuln_info)


int main(int argc, char **argv)
{
	int fd = open("/dev/vuln_stack_leak", O_RDWR);
	if (fd < 0) {
		perror("open error");
		return -1;
	}

	struct vuln_info info = { 0 };

	if (ioctl(fd, VULN_GET_INFO, &info) < 0)
		perror("ioctl");

	struct vuln_info expected;
	memset(&expected, 0, sizeof(expected));
	expected = (struct vuln_info) {
		.version = 1,
		.id = 0x1122334455667788,
	};

	int i;
	u64 *info_ptr = (u64*)&info;
	u64 *exp_ptr = (u64*)&expected;
	for (i=0; i<sizeof(info)/sizeof(u64); i++) {
		if (info_ptr[i] != exp_ptr[i]) {
			printf("value at offset %ld differs: %#llx vs %#llx\n", i*sizeof(u64), info_ptr[i], exp_ptr[i]);
		}
	}

	return 0;
}
