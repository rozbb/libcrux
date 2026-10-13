//! Forces codegen of every libcrux-ml-kem operation, for both x86-64 backends.
//!
//! The crate's internals are const-generic and are instantiated per backend, so a
//! `liblibcrux_ml_kem.rlib` built on its own need not contain every instantiation. `scan-instrs.py`
//! builds this crate instead and disassembles it along with libcrux-ml-kem and its dependencies.
//!
//! The portable and AVX2 backends are called directly, not only through the top-level API that
//! picks one at runtime: with `-C target-cpu=x86-64-v3` that choice can be made at compile time,
//! and the backend not chosen would then never be compiled.
//!
//! Nothing here needs to run, or even to link. It only needs to exist in the object code.

use core::hint::black_box;

/// One exported entry point per (parameter set, backend). `#[no_mangle]` keeps each one alive;
/// the Rust ABI is fine, since nothing calls them.
macro_rules! probe {
    ($f:ident, $m:ident, $($b:ident)::*) => {
        #[no_mangle]
        pub fn $f(seed: [u8; 64], m: [u8; 32], out: &mut [u8; 32]) {
            use libcrux_ml_kem::$m::$($b)::* as b;
            use libcrux_ml_kem::$m::$($b)::*::unpacked as u;

            // Packed API, including both key validations.
            let kp = b::generate_key_pair(seed);
            let (ct, _) = b::encapsulate(kp.public_key(), m);
            out.copy_from_slice(b::decapsulate(kp.private_key(), &ct).as_slice());
            black_box(b::validate_public_key(kp.public_key()));
            black_box(b::validate_private_key(kp.private_key(), &ct));
            black_box(b::validate_private_key_only(kp.private_key()));

            // Unpacked API, including unpacking a secret key.
            black_box(u::generate_key_pair(seed));
            let mut upk = u::init_public_key();
            u::unpacked_public_key(kp.public_key(), &mut upk);
            let (ct, _) = u::encapsulate(&upk, m);
            let mut from_sk = u::init_key_pair();
            u::key_pair_from_private_mut(kp.private_key(), &mut from_sk);
            black_box(u::key_pair_serialized_private_key(&from_sk));
            black_box(u::key_pair_serialized_public_key(&from_sk));
            out.copy_from_slice(u::decapsulate(&from_sk, &ct).as_slice());
        }
    };
}

probe!(probe512_portable, mlkem512, portable);
probe!(probe768_portable, mlkem768, portable);
probe!(probe1024_portable, mlkem1024, portable);
probe!(probe512_avx2, mlkem512, avx2);
probe!(probe768_avx2, mlkem768, avx2);
probe!(probe1024_avx2, mlkem1024, avx2);

/// The top-level API, which picks a backend at runtime. Packed only: there is no top-level
/// unpacked API.
macro_rules! probe_multiplexed {
    ($f:ident, $m:ident) => {
        #[no_mangle]
        pub fn $f(seed: [u8; 64], m: [u8; 32], out: &mut [u8; 32]) {
            use libcrux_ml_kem::$m as b;

            let kp = b::generate_key_pair(seed);
            let (ct, _) = b::encapsulate(kp.public_key(), m);
            out.copy_from_slice(b::decapsulate(kp.private_key(), &ct).as_slice());
            black_box(b::validate_public_key(kp.public_key()));
            black_box(b::validate_private_key(kp.private_key(), &ct));
        }
    };
}

probe_multiplexed!(probe512, mlkem512);
probe_multiplexed!(probe768, mlkem768);
probe_multiplexed!(probe1024, mlkem1024);
