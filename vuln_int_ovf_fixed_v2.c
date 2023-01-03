// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// C integer overflow leading to data corruption.

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>


struct entry_data {
	u32 n_entries;
	u8 __user *entries;
};

#define VULN_COPY_ENTRIES _IOW('v', 4, struct entry_data)


#define MAX_ENTRY_SIZE 1024

typedef u8 entries_t[32][MAX_ENTRY_SIZE];

static int vuln_open(struct inode *ino, struct file *filp)
{
	u8 *buf = kzalloc(sizeof(entries_t), GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}

	filp->private_data = buf;
	return 0;
}

static int vuln_release(struct inode *ino, struct file *filp)
{
	kfree(filp->private_data);
	return 0;
}

static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	entries_t *entries = filp->private_data;
	struct entry_data entry_data;
	int i;

	switch (cmd) {
	case VULN_COPY_ENTRIES:
		if (copy_from_user(&entry_data, (void __user *)arg, sizeof(entry_data)) != 0)
			return -EFAULT;

		//if (entry_data.n_entries > 32) {           // nice alternative
		if (entry_data.n_entries > sizeof(entries_t) / MAX_ENTRY_SIZE) {
			pr_err("VULN_COPY_ENTRIES: too much entry data (%d)\n",
					entry_data.n_entries * MAX_ENTRY_SIZE);
			return -EINVAL;
		}

		for (i=0; i<entry_data.n_entries; i++) {
			if (copy_from_user((*entries)[i], entry_data.entries+(i*MAX_ENTRY_SIZE), MAX_ENTRY_SIZE) != 0)
				return -EFAULT;
		}
                return 0;
	}

	return -EINVAL;
}

static const struct file_operations vuln_fops = {
	.owner = THIS_MODULE,
	.open = vuln_open,
	.release = vuln_release,
	.unlocked_ioctl = vuln_ioctl,
};


static struct miscdevice vuln_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vuln_int_ovf",
	.fops = &vuln_fops,
};

module_misc_device(vuln_miscdev);

MODULE_AUTHOR("Domen Puncer Kugler (NCC Group)");
MODULE_LICENSE("GPL");
