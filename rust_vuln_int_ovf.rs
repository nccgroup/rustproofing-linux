// SPDX-License-Identifier: GPL-2.0

// Buggy code, DO NOT USE. See https://research.nccgroup.com/?p=18577

//! Rust integer overflow leading to data corruption.

use core::mem::size_of;
use kernel::{
    file::{self, File, IoctlCommand, IoctlHandler},
    io_buffer::{IoBufferReader, ReadableFromBytes},
    prelude::*,
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
static mut GLOBAL_ENTRY_DATA: EntriesType = [[0; MAX_ENTRY_SIZE as _]; 32];


struct RustVuln;

#[vtable]
impl file::Operations for RustVuln {
    type Data = Pin<Box<Self>>;

    fn open(_data: &(), _file: &File) -> Result<Self::Data> {
        Ok(Pin::from(Box::try_new(RustVuln {
        })?))
    }

    fn ioctl(state: &Self, file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        cmd.dispatch::<RustVuln>(state, file)
    }
}

impl IoctlHandler for RustVuln {
    type Target<'a> = &'a Self;

    fn write(_state: &Self, _: &File, cmd: u32, reader: &mut UserSlicePtrReader) -> Result<i32> {
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
                    //pr_err!("idx: {}, global_entry_data[i]: {:#x}\n", i, GLOBAL_ENTRY_DATA[i as usize].as_mut_ptr() as usize);
                    pr_err!("idx: {}, ptr2: {:#x}\n", i, (*GLOBAL_ENTRY_DATA.as_mut_ptr().offset(i as isize)).as_mut_ptr() as usize); // - it is the same

                    // SAFETY: we're changing a global, this isn't a good idea really
                    //entry_reader.read_slice(unsafe { &mut GLOBAL_ENTRY_DATA[i as usize] })?; // rust_kernel: panicked at 'index out of bounds: the len is 32 but the index is 32'
                    
                    // SAFETY: destination always is within GLOBAL_ENTRY_DATA, or is it?
                    unsafe { entry_reader.read_raw((*GLOBAL_ENTRY_DATA.as_mut_ptr().offset(i as isize)).as_mut_ptr(), MAX_ENTRY_SIZE as usize)? };
                    // XXX This was not caught by KASAN. Rust modules don't call __asan_register_globals(), compiler support might be missing.
                    // it overwrites __MOD (which follows GLOBAL_ENTRY_DATA in .bss)
/*
[  149.985977] BUG: KASAN: wild-memory-access in mod_find+0x91/0x100
[  149.989685] Read of size 8 at addr 4141414141414121 by task poc_vuln_int_ov/194
[  149.992788]
[  149.993411] CPU: 1 PID: 194 Comm: poc_vuln_int_ov Tainted: G    B              6.1.0-rc1-13993-gd9b2e84c0700-dirty #9
[  149.997193] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
[  150.000523] Call Trace:
[  150.001489]  <TASK>
[  150.002196]  dump_stack_lvl+0x73/0x9e
[  150.003339]  print_report+0xf9/0x210
[  150.005003]  ? mod_find+0x91/0x100
[  150.006806]  ? _printk+0x54/0x6e
[  150.008105]  ? __virt_addr_valid+0x28/0x160
[  150.009844]  ? mod_find+0x91/0x100
[  150.010841]  kasan_report+0xc1/0xf0
[  150.012139]  ? mod_find+0x91/0x100
[  150.013868] general protection fault, probably for non-canonical address 0x4141414141414121: 0000 [#1] PREEMPT SMP KASAN PTI
*/
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
