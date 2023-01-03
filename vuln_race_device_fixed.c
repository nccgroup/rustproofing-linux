// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

// C race in shared state (buf, buf_size) accessible from multiple threads.

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>


#define VULN_SETUP_BUF _IO('v', 3)

struct file_state {
	u8 *buf;
	size_t buf_size;
	struct mutex buf_mutex;
};


static int vuln_open(struct inode *ino, struct file *filp)
{
	struct file_state *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	mutex_init(&state->buf_mutex);

	filp->private_data = state;
	return 0;
}

static int vuln_release(struct inode *ino, struct file *filp)
{
	struct file_state *state = filp->private_data;

	kfree(state->buf);
	kfree(state);
	return 0;
}

static ssize_t vuln_write(struct file *filp, const char __user *buf, size_t count, loff_t *offset)
{
	struct file_state *state = filp->private_data;

	if (count == 0)
		return 0;

	mutex_lock(&state->buf_mutex);
	if (state->buf_size < count) {
		mutex_unlock(&state->buf_mutex);
		return -ENOSPC;
	}

	if (copy_from_user(state->buf, buf, count) != 0) {
		mutex_unlock(&state->buf_mutex);
		return -EFAULT;
	}
	mutex_unlock(&state->buf_mutex);

	return count;
}

static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct file_state *state = filp->private_data;

	switch (cmd) {
	case VULN_SETUP_BUF:
		if (arg == 0)
			return -EINVAL;

		mutex_lock(&state->buf_mutex);
		state->buf = krealloc(state->buf, arg, GFP_KERNEL);
		if (state->buf == NULL) {
			mutex_unlock(&state->buf_mutex);
			return -ENOMEM;
		}

		state->buf_size = arg;
		mutex_unlock(&state->buf_mutex);
	}

	pr_err("error: wrong ioctl command: %#x\n", cmd);
	return -EINVAL;
}

static const struct file_operations vuln_fops = {
	.owner = THIS_MODULE,
	.open = vuln_open,
	.release = vuln_release,
	.write = vuln_write,
	.unlocked_ioctl = vuln_ioctl,
};


static struct miscdevice vuln_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vuln_race_device",
	.fops = &vuln_fops,
};

module_misc_device(vuln_miscdev);

MODULE_AUTHOR("Domen Puncer Kugler (NCC Group)");
MODULE_LICENSE("GPL");
