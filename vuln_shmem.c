// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// C shared memory TOCTOU

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pfn.h>


struct file_state {
	struct page *page;
};

#define VULN_PROCESS_BUF _IO('v', 5)


static int vuln_open(struct inode *ino, struct file *filp)
{
	struct file_state *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (state->page == NULL)
		return -ENOMEM;

	filp->private_data = state;
	return 0;
}

static int vuln_release(struct inode *ino, struct file *filp)
{
	struct file_state *state = filp->private_data;
	__free_pages(state->page, 0);
	kfree(state);
	return 0;
}

static int vuln_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct file_state *state = filp->private_data;
	int ret = 0;

	ret = vm_map_pages_zero(vma, &state->page, 1);
	return ret;
}

static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct file_state *state = filp->private_data;
	volatile u32 *sh_buf = page_to_virt(state->page);
	u8 tmp_buf[32];

	switch (cmd) {
	case VULN_PROCESS_BUF:
		if (sh_buf[0] <= sizeof(tmp_buf)) {
			memcpy(tmp_buf, (void *)&sh_buf[1], sh_buf[0]);

			// use tmp_buf, so above memcpy isn't optimised out
			if (tmp_buf[0] == 'A')
				return 0;
			return -EINVAL;
		}
	}
	return -EINVAL;
}

static const struct file_operations vuln_fops = {
	.owner = THIS_MODULE,
	.open = vuln_open,
	.release = vuln_release,
	.mmap = vuln_mmap,
	.unlocked_ioctl = vuln_ioctl
};


static struct miscdevice vuln_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vuln_shmem",
	.fops = &vuln_fops,
};

module_misc_device(vuln_miscdev);

MODULE_AUTHOR("Domen Puncer Kugler (NCC Group)");
MODULE_LICENSE("GPL");
