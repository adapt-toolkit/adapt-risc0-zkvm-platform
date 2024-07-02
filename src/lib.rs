// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::{ptr, slice};
use std::alloc::{handle_alloc_error, Layout};
use std::ffi::c_void;
use risc0_binfmt::tagged_struct;
use risc0_zkp::core::digest::Digest;
use risc0_zkp::core::hash::sha::guest::Impl;
use risc0_zkp::core::hash::sha::rust_crypto::{Digest as _, Sha256};
//use risc0_zkp::core::hash::blake2::
use risc0_zkvm_platform::fileno;
use risc0_zkvm_platform::syscall::{sys_halt, sys_panic, sys_read, sys_write, sys_log};

// Load the globals pointer. The program will load pointers relative to this
// register, so it must be set to the right value on startup.
// See: https://gnu-mcu-eclipse.github.io/arch/riscv/programmer/#the-gp-global-pointer-register
// Linker relaxations must be disabled to avoid the initialization beign
// relaxed with an uninitialized global pointer: mv gp, gp
//
// This will also set up the stack pointer to the _stack_top address from the linker script and
// call the main function.
//
// Note: this is slightly different than the rust program because it uses a linker script symbol to
// set the stack pointer and calls main instead of __start.
#[cfg(target_os = "zkvm")]
core::arch::global_asm!(
    r#"
.section .text._start
.global _start
_start:
    .option push;
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, _stack_top

    call main;
"#,
);

const ERR_FREED: &[u8] = b"error: sha256_state has not been initialized or has already been freed";

/// C wrapper for guest sha256 implementation.
///
/// This is used in the guest to generate any sha256
/// hash, but also to accumulate the Sha256 state of all data written to journal through
/// [commit].
///
/// Initialize with [init_sha256], and can retrieve the final hash through [sha256_finalize],
/// or pass it into [zkvm_exit] to exit the program.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sha256_state {
    inner: *mut Sha256<Impl>,
}

#[no_mangle]
pub extern "C" fn init_sha256() -> *mut sha256_state {
    Box::into_raw(Box::new(sha256_state {
        inner: Box::into_raw(Box::new(Sha256::new())),
    }))
}

// #[no_mangle]
// pub extern "C" fn init_blake2b() -> *mut sha256_state {
//     Box::into_raw(Box::new(sha256_state {
//         inner: Box::into_raw(Box::new(Blake2b::new())),
//     }))
// }

/// Update the sha256 state with the bytes passed in.
///
/// # Safety
/// This is safe assuming that pointers have not been manually modified, and len does not go past
/// the buffer of the data in memory.
#[no_mangle]
pub unsafe extern "C" fn sha256_update(hasher: *mut sha256_state, data: *const u8, len: u32) {
    if hasher.is_null() || data.is_null() || (*hasher).inner.is_null() {
        sys_panic(ERR_FREED.as_ptr(), ERR_FREED.len())
    }
    let data_slice = slice::from_raw_parts(data, len as usize);
    (*(*hasher).inner).update(data_slice);
}

// #[no_mangle]
// pub unsafe extern "C" fn blake2b_update(hasher: *mut sha256_state, data: *const u8, len: u32) {
//     if hasher.is_null() || data.is_null() || (*hasher).inner.is_null() {
//         sys_panic(ERR_FREED.as_ptr(), ERR_FREED.len())
//     }
//     let data_slice = slice::from_raw_parts(data, len as usize);
//     (*(*hasher).inner).update(data_slice);
// }

/// Finalize the hasher, returning an allocated digest of the output hash.
///
/// Note: This digest is leaked, as the zkvm currently uses a bump allocator so it does not need to
/// be freed. If switching allocator, should implement a free method for [Digest].
///
/// # Safety
/// Assumes [sha256_state] has not been freed previously.
#[no_mangle]
pub unsafe extern "C" fn sha256_finalize(hasher: *mut sha256_state) -> *mut Digest {
    if hasher.is_null() || (*hasher).inner.is_null() {
        sys_panic(ERR_FREED.as_ptr(), ERR_FREED.len())
    }
    let inner = unsafe { Box::from_raw((*hasher).inner) };
    let result = inner.finalize();
    // Free hasher to assert it is unused after finalize.
    sha256_free(hasher);
    let arr: [u8; 32] = result.into();
    Box::into_raw(Box::new(arr.into()))
}

#[no_mangle]
pub unsafe extern "C" fn sha256_finalize_to(hasher: *mut sha256_state, out: *mut u8) {
    if hasher.is_null() || (*hasher).inner.is_null() {
        sys_panic(ERR_FREED.as_ptr(), ERR_FREED.len())
    }
    let inner = unsafe { Box::from_raw((*hasher).inner) };
    let result = inner.finalize();
    // Free hasher to assert it is unused after finalize.
    sha256_free(hasher);
    let arr: [u8; 32] = result.into();
    out.copy_from_nonoverlapping(arr.as_ptr(), 32);
}

/// Free allocations from [sha256_state].
///
/// # Safety
/// This assumes the state has not already been freed or manually modified.
#[no_mangle]
pub unsafe extern "C" fn sha256_free(hasher: *mut sha256_state) {
    if !hasher.is_null() {
        let mut boxed_hasher = Box::from_raw(hasher);

        let inner = Box::from_raw(boxed_hasher.inner);
        // Set pointer to null to avoid double free. `black_box` to avoid compiler optimizing away.
        boxed_hasher.inner = ptr::null_mut();
        drop(inner);

        drop(boxed_hasher);
    }
}

/// Exit the zkvm, using the [sha256_state].
///
/// # Safety
/// Assumes hasher has not been freed.
#[no_mangle]
pub unsafe extern "C" fn env_exit(hasher: *mut sha256_state, exit_code: u8) -> ! {
    let journal_digest = sha256_finalize(hasher);
    let output_words: [u32; 8] =
        tagged_struct::<Impl>("risc0.Output", &[&*journal_digest, &Digest::ZERO], &[]).into();
    sys_halt(exit_code, &output_words)
}

/// Write data to the journal, updating the sha256 state accumulation with that data.
///
/// # Safety
/// This is safe assuming that pointers have not been manually modified, and len does not go past
/// the buffer of the data in memory.
#[no_mangle]
pub unsafe extern "C" fn env_commit(hasher: *mut sha256_state, bytes_ptr: *const u8, len: u32) {
    sha256_update(hasher, bytes_ptr, len);
    sys_write(fileno::JOURNAL, bytes_ptr, len as usize);
}

/// Reads `len` bytes into buffer from the host.
///
/// # Safety
/// Assumes that the buffer has at least `len` bytes allocated.
#[no_mangle]
pub unsafe extern "C" fn env_read(bytes_ptr: *mut u8, len: u32) {
    sys_read(fileno::STDIN, bytes_ptr, len as usize);
}

#[no_mangle]
// TODO ideally this is c_size_t, but not stabilized (not guaranteed to be usize on all archs)
unsafe extern "C" fn env_alloc(size: usize) -> *mut c_void {
    let layout = Layout::from_size_align(size, 4).expect("unable to allocate more memory");
    let ptr = std::alloc::alloc(layout);

    if ptr.is_null() {
        handle_alloc_error(layout);
    }

    ptr as *mut c_void
}



#[no_mangle]
unsafe extern "C" fn env_log(msg_ptr: *const u8, len: u32) {
    sys_log(msg_ptr, len as usize);
}

// Poseidon hash implementation
const POSEIDON_ERR_FREED: &[u8] = b"error: poseidon_state has not been initialized or has already been freed";


use std::boxed::Box;


// This is a template implementation of the poseidon hash algorithm. This template is already linked to the c++ code.

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct poseidon_state {
}

#[no_mangle]
pub extern "C" fn poseidon_init() -> *mut poseidon_state {
    Box::into_raw(Box::new(poseidon_state {
    }))
}

#[no_mangle]
pub extern "C" fn poseidon_free(ptr: *mut poseidon_state) {
}

#[no_mangle]
pub unsafe extern "C" fn poseidon_update(ptr: *mut poseidon_state, data: *const u8, length: usize) {
}

#[no_mangle]
pub unsafe extern "C" fn poseidon_digest(ptr: *mut poseidon_state, out: *mut u8) {
}
