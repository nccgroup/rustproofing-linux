// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// C buggy driver leaking kernel stack data.

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>


struct vuln_info {
	u8 version;
	u64 id;
	u8 _reserved;
};

#define VULN_GET_INFO _IOR('v', 2, struct vuln_info)


static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct vuln_info info;

	switch (cmd) {
	case VULN_GET_INFO:
		memset(&info, 0, sizeof(info)); // explicitly clear all "info" memory
		info = (struct vuln_info) {
			.version = 1,
			.id = 0x1122334455667788,
		};
		if (copy_to_user((void __user *)arg, &info, sizeof(info)) != 0)
			return -EFAULT;
		return 0;
	}

	pr_err("error: wrong ioctl command: %#x\n", cmd);
	return -EINVAL;
}

static const struct file_operations vuln_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = vuln_ioctl,
};


static struct miscdevice vuln_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vuln_stack_leak",
	.fops = &vuln_fops,
};

module_misc_device(vuln_miscdev);

MODULE_AUTHOR("Domen Puncer Kugler (NCC Group)");
MODULE_LICENSE("GPL");
