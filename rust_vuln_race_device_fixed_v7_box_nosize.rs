// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust race in shared state (buf, buf_size) accessible from multiple threads.

use kernel::{
    file::{self, File, IoctlCommand},
    io_buffer::IoBufferReader,
    prelude::*,
    sync::Mutex,
    mutex_init,
};


const VULN_SETUP_BUF: u32 = 0x00007603; // _IO('v', 3)


struct RustVulnState {
    buf: Box<[core::mem::MaybeUninit<u8>]>,
}

struct RustVuln {
    mutable: Mutex<RustVulnState>,
}

#[vtable]
impl file::Operations for RustVuln {
    type Data = Pin<Box<Self>>;

    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        let mut state = Pin::from(Box::try_new(RustVuln {
            // SAFETY: mutex_init! called below
            mutable: unsafe {
                Mutex::new(RustVulnState {
                    buf: Box::try_new_uninit_slice(0)?,
                })
            }
        })?);

        // SAFETY: 'mutable' is pinned above
        mutex_init!(unsafe { state.as_mut().map_unchecked_mut(|s| &mut s.mutable) }, "RustVuln::mutable");
        Ok(state)
    }

    fn write(state: &Self, _: &File, data: &mut impl IoBufferReader, _offset: u64) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        let buf = &mut state.mutable.lock().buf;
        if buf.len() < data.len() {
            return Err(ENOSPC);
        }

        let buf = buf.as_mut_ptr() as *mut u8;
        // SAFETY: 'buf' is allocated and big enough ('buf.len()' check)
        unsafe { data.read_raw(buf, data.len())? };

        Ok(data.len())
    }

    fn ioctl(state: &Self, _: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        let (cmd, arg) = cmd.raw();
        match cmd {
            VULN_SETUP_BUF => {
                if arg == 0 {
                    return Err(EINVAL)
                }

                state.mutable.lock().buf = Box::try_new_uninit_slice(arg)?;

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
