// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust integer overflow leading to data corruption.

use core::mem::size_of;
use kernel::{
    file::{self, File, IoctlCommand, IoctlHandler},
    io_buffer::{IoBufferReader, ReadableFromBytes},
    prelude::*,
    sync::smutex::Mutex,
    user_ptr::{UserSlicePtrReader, UserSlicePtr},
};


const VULN_COPY_ENTRIES: u32 = 0x40107604; // _IOW('v', 4, struct entry_data)

#[repr(C)] // same struct layout as in C, since we are sending it to userspace
struct EntryData {
    n_entries: u32,
    entries: *mut u8,
}
// SAFETY: all bit values are fine; pointer is checked in UserSlicePtr
unsafe impl ReadableFromBytes for EntryData { }


const MAX_ENTRY_SIZE: u32 = 1024;
type EntriesType = [[u8; MAX_ENTRY_SIZE as _]; 32];


struct RustVuln {
    entries: Mutex<EntriesType>,
}

#[vtable]
impl file::Operations for RustVuln {
    type Data = Pin<Box<Self>>;

    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        Ok(Pin::from(Box::try_new(RustVuln {
            entries: Mutex::new([[0; MAX_ENTRY_SIZE as _]; 32]),
        })?))
    }

    fn ioctl(state: &Self, file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        cmd.dispatch::<RustVuln>(state, file)
    }
}

impl IoctlHandler for RustVuln {
    type Target<'a> = &'a Self;

    fn write(state: &Self, _: &File, cmd: u32, reader: &mut UserSlicePtrReader) -> Result<i32> {
        match cmd {
            VULN_COPY_ENTRIES => {
                let entry_data: EntryData = reader.read()?;

                // CONFIG_RUST_OVERFLOW_CHECKS=y (default) will catch this
                // Note that normally 'debug' builds 'panic on overflow' and 'release' has 'wrapping' behaviour
                if entry_data.n_entries*MAX_ENTRY_SIZE > size_of::<EntriesType>() as u32 {
                    pr_err!("VULN_COPY_ENTRIES: too much entry data ({})\n", entry_data.n_entries*MAX_ENTRY_SIZE);
                    return Err(EINVAL);
                }

                // SAFETY: any source should be safe, since it goes through copy_from_user
                let entry_reader = unsafe { UserSlicePtr::new(entry_data.entries as _, entry_data.n_entries as usize * MAX_ENTRY_SIZE as usize) };
                let mut entry_reader = entry_reader.reader();

                for i in 0..entry_data.n_entries {
                    // SAFETY: destination always is within state.entries, or is it?
                    entry_reader.read_slice(unsafe { &mut *state.entries.lock().as_mut_ptr().offset(i as isize) })?;
                }
                Ok(0)
            }
            _ => {
                pr_err!("error: wrong ioctl command: {}\n", cmd);
                Err(EINVAL)
            }
        }
    }
}

module_misc_device! {
    type: RustVuln,
    name: "vuln_int_ovf",
    author: "Domen Puncer Kugler (NCC Group)",
    license: "GPL",
}
