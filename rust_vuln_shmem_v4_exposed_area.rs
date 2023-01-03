// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust shared memory TOCTOU

use core::ptr::{read_volatile, copy};
use kernel::{
    bindings,
    file::{self, File, IoctlCommand},
    mm,
    prelude::*,
    sync::smutex::Mutex,
};


const VULN_PROCESS_BUF: u32 = 0x00007605; // _IO('v', 5)


struct RustVulnState {
    page: *mut bindings::page,
}
// SAFETY: after allocation in open, we don't change 'page'
unsafe impl Send for RustVulnState {}

struct RustVuln {
    mutable: Mutex<RustVulnState>,
}

// our own copy of the type, so we can access .pages
struct ExposedArea {
    vma: *mut bindings::vm_area_struct,
}

#[vtable]
impl file::Operations for RustVuln {
    type Data = Pin<Box<Self>>;

    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        let state = Pin::from(Box::try_new(RustVuln {
            mutable: Mutex::new(RustVulnState {
                page: unsafe { bindings::alloc_pages(bindings::GFP_KERNEL | bindings::__GFP_ZERO, 0) },
            })
        })?);

        Ok(state)
    }

    fn mmap(state: &Self, _file: &File, vma: &mut mm::virt::Area) -> Result {
        let start = vma.start();
        let vma: &ExposedArea = unsafe { core::mem::transmute(vma) };
        unsafe { bindings::vm_insert_page(vma.vma, start as _, state.mutable.lock().page) };

        Ok(())
    }

    fn ioctl(state: &Self, _file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        let (cmd, _arg) = cmd.raw();
        match cmd {
            VULN_PROCESS_BUF => {
                let mut tmp_buf = Box::try_new([0u8; 32])?; // on heap

                let page = state.mutable.lock().page;
                let sh_buf: *mut u32 = unsafe { bindings::kmap(page) } as _;

                if unsafe { read_volatile(sh_buf) } as usize <= tmp_buf.len() {
                    unsafe { copy(sh_buf.offset(1) as *mut u8, tmp_buf.as_mut_ptr(), read_volatile(sh_buf) as _) };

                    if tmp_buf[0] == 'A' as u8 {
                        return Ok(0);
                    }
                }

                return Err(EINVAL);
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
    name: "vuln_shmem",
    author: "Domen Puncer Kugler (NCC Group)",
    license: "GPL",
}
