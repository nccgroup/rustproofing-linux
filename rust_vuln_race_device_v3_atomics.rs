// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust race in shared state (buf, buf_size) accessible from multiple threads.

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use kernel::{
    bindings,
    file::{self, File, IoctlCommand},
    io_buffer::IoBufferReader,
    prelude::*,
};


const VULN_SETUP_BUF: u32 = 0x00007603; // _IO('v', 3)


struct RustVuln {
    buf: AtomicPtr<core::ffi::c_void>,
    buf_size: AtomicUsize,
}

#[vtable]
impl file::Operations for RustVuln {
    type Data = Pin<Box<Self>>;

    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        let state = Pin::from(Box::try_new(RustVuln {
            buf: AtomicPtr::new(core::ptr::null_mut()),
            buf_size: AtomicUsize::new(0),
        })?);
        
        Ok(state)
    }

    fn write(state: &Self, _: &File, data: &mut impl IoBufferReader, _offset: u64) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        if state.buf_size.load(Ordering::Relaxed) < data.len() {
            return Err(ENOSPC);
        }

        // SAFETY: 'buf' is allocated and big enough ('buf_size' check)
        unsafe { data.read_raw(state.buf.load(Ordering::Relaxed) as *mut u8, data.len())?; }

        Ok(data.len())
    }

    fn ioctl(state: &Self, _: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        let (cmd, arg) = cmd.raw();
        match cmd {
            VULN_SETUP_BUF => {
                if arg == 0 {
                    return Err(EINVAL)
                }

                // SAFETY: only calling C's krealloc
                let newbuf = unsafe { bindings::krealloc(state.buf.load(Ordering::Relaxed), arg, bindings::GFP_KERNEL) };
                state.buf.store(newbuf, Ordering::Relaxed);
                state.buf_size.store(arg, Ordering::Relaxed);

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
    name: "vuln_race_device",
    author: "Domen Puncer Kugler (NCC Group)",
    license: "GPL",
}
