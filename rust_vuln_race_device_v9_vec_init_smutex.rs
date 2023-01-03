// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust race in shared state (buf, buf_size) accessible from multiple threads.

// XXX this is not the same
// Vec::resize fills the members with values. Should use Vec::reserve_exact and Vec::truncate.

use kernel::{
    file::{self, File, IoctlCommand},
    io_buffer::IoBufferReader,
    prelude::*,
    sync::smutex::Mutex,
};


const VULN_SETUP_BUF: u32 = 0x00007603; // _IO('v', 3)


struct RustVulnState {
    buf: Vec<u8>,
}

struct RustVuln {
    mutable: Mutex<RustVulnState>,
}

#[vtable]
impl file::Operations for RustVuln {
    type Data = Pin<Box<Self>>;

    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        let state = Pin::from(Box::try_new(RustVuln {
            mutable: Mutex::new(RustVulnState {
                    buf: Vec::new(),
            })
        })?);

        Ok(state)
    }

    fn write(state: &Self, _: &File, data: &mut impl IoBufferReader, _offset: u64) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        if state.mutable.lock().buf.len() < data.len() {
            return Err(ENOSPC);
        }

        // use only data.len() bytes
        data.read_slice(state.mutable.lock().buf.split_at_mut(data.len()).0)?;

        Ok(data.len())
    }

    fn ioctl(state: &Self, _: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        let (cmd, arg) = cmd.raw();
        match cmd {
            VULN_SETUP_BUF => {
                if arg == 0 {
                    return Err(EINVAL)
                }

                state.mutable.lock().buf.try_resize(arg, 0u8)?;

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
