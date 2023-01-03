// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust intentionally leaking kernel memory addresses.

use kernel::prelude::*;
use kernel::file::{self, File, IoctlCommand};


const VULN_PRINT_ADDR: u32 = 0x00007601; // _IO('v', 1)


struct RustVuln;

#[vtable]
impl file::Operations for RustVuln {
    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        Ok(())
    }

    fn ioctl(_state: (), _file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        let stack_dummy: i32 = 0;

        let (cmd, _arg) = cmd.raw();
        match cmd {
            VULN_PRINT_ADDR => {
		pr_info!("RustVuln::ioctl is at address {:p}\n", Self::ioctl as *const ());
                pr_info!("stack is at address {:p}\n", &stack_dummy);
                Ok(0)
            }
            _ => {
                pr_err!("error: wrong ioctl command: {:#x}\n", cmd);
                Err(EINVAL)
            }
        }
    }
}


module_misc_device! {
    type: RustVuln,
    name: "vuln_printk_leak",
    author: "Domen Puncer Kugler (NCC Group)",
    license: "GPL",
}
