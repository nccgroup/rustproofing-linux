// Incorrect n_entries check because of integer overflow.
// Possibly a bit odd, but check_copy_size() eliminates quite a few bugs.

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>


struct entry_data {
	u32 n_entries;
	u8 __user *entries;
};

#define VULN_COPY_ENTRIES _IOW('v', 4, struct entry_data)


#define MAX_ENTRY_SIZE 1024
static u8 global_entry_data[32][MAX_ENTRY_SIZE];

static long vuln_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct entry_data entry_data;
	int i;

	switch (cmd) {
	case VULN_COPY_ENTRIES:
		if (copy_from_user(&entry_data, (void __user *)arg, sizeof(entry_data)) != 0)
			return -EFAULT;

		//if (entry_data.n_entries > 32) {                            // nice alternative
		//if (entry_data.n_entries > ARRAY_LEN(global_entry_data)) {  // nicer alternative
		if (entry_data.n_entries > sizeof(global_entry_data) / MAX_ENTRY_SIZE) {
			pr_err("VULN_COPY_ENTRIES: too many entries (%d)\n",
					entry_data.n_entries);
			return -EINVAL;
		}

		for (i=0; i<entry_data.n_entries; i++) {
			if (copy_from_user(global_entry_data[i], entry_data.entries+(i*MAX_ENTRY_SIZE), MAX_ENTRY_SIZE) != 0)
				return -EFAULT;
		}
                return 0;
	}

	return -EINVAL;
}

static const struct file_operations vuln_fops = {
	.owner = THIS_MODULE,
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
