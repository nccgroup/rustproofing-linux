// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust race in shared state (buf, buf_size) accessible from multiple threads.

use kernel::{
    bindings,
    file::{self, File, IoctlCommand},
    io_buffer::IoBufferReader,
    prelude::*,
    sync::Mutex,
    mutex_init,
};


const VULN_SETUP_BUF: u32 = 0x00007603; // _IO('v', 3)


struct RustVulnState {
    buf: usize,
    buf_size: usize,
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
                    buf: 0,
                    buf_size: 0,
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

        if state.mutable.lock().buf_size < data.len() {
            return Err(ENOSPC);
        }

        // SAFETY: 'buf' is allocated and big enough ('buf_size' check)
        unsafe { data.read_raw(state.mutable.lock().buf as _, data.len())?; }

        Ok(data.len())
    }

    fn ioctl(state: &Self, _: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        let (cmd, arg) = cmd.raw();
        match cmd {
            VULN_SETUP_BUF => {
                if arg == 0 {
                    return Err(EINVAL)
                }

                let mut mutable = state.mutable.lock();
                // SAFETY: only calling C's krealloc
                let newbuf = unsafe { bindings::krealloc(mutable.buf as _, arg, bindings::GFP_KERNEL) };
                mutable.buf = newbuf as _;
                mutable.buf_size = arg;

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
