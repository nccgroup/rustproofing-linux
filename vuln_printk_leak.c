// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// C intentionally leaking kernel memory addresses.

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>


#define VULN_PRINT_ADDR _IO('v', 1)


static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int stack_dummy;

	switch (cmd) {
	case VULN_PRINT_ADDR:
		pr_info("%s is at address %px\n", __func__, &__func__);
		pr_info("stack is at address %px\n", &stack_dummy);
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
	.name = "vuln_printk_leak",
	.fops = &vuln_fops,
};

module_misc_device(vuln_miscdev);

MODULE_AUTHOR("Domen Puncer Kugler (NCC Group)");
MODULE_LICENSE("GPL");
