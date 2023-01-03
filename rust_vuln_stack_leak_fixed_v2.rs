// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust buggy driver leaking kernel stack data.

use kernel::{
    file::{self, File, IoctlCommand, IoctlHandler},
    io_buffer::{IoBufferWriter, WritableToBytes},
    prelude::*,
    user_ptr::UserSlicePtrWriter,
};
use core::mem::MaybeUninit;


#[repr(C)]
struct VulnInfo {
    version: u8,
    id: u64,
    _reserved: u8,
}
unsafe impl WritableToBytes for VulnInfo { }

const VULN_GET_INFO: u32 = 0x80187602; // _IOR('v', 2, struct vuln_info)


struct RustVuln;

#[vtable]
impl file::Operations for RustVuln {
    type Data = Pin<Box<Self>>;

    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        let state = Pin::from(Box::try_new(RustVuln {
        })?);

        Ok(state)
    }

    fn ioctl(state: &Self, file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        cmd.dispatch::<Self>(state, file)
    }
}

impl IoctlHandler for RustVuln {
    type Target<'a> = &'a Self;

    fn read(_state: &Self, _: &File, cmd: u32, writer: &mut UserSlicePtrWriter) -> Result<i32> {
        match cmd {
            VULN_GET_INFO => {
                let mut info = MaybeUninit::<VulnInfo>::zeroed();
                let info = info.write(VulnInfo {
                    version: 1,
                    id: 0x1122334455667788,
                    _reserved: 0, // compiler requires an initialiser
                });

                writer.write(info)?;
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
    name: "vuln_stack_leak",
    author: "Domen Puncer Kugler (NCC Group)",
    license: "GPL",
}
