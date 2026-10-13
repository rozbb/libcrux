# Instruction-scan findings

`./ct-check.sh` as of commit `1e79e27bf`, rustc 1.98.1, 2026-10-13. The scan fails: 931
instructions in 178 (mnemonic, symbol) groups are not on Intel's DOIT list and are not
allowlisted. 619 of them operate on secret data, listed under Findings. The other 312 are false
positives that can't be allowlisted, explained in their own section.

The scan found no divides and no calls to software divide routines.

Every x86-64 build contains both backends, so each finding is labelled with the one it belongs
to. `shared` means code both backends use, such as the single-lane Keccak.

Source lines were found by rebuilding each config with `-C debuginfo=1`, which gave the same
instruction counts as the scanned builds, and asking `addr2line -i` for the inline chain of each
instruction. A line given below is the innermost frame in libcrux's own code, skipping
`libcrux-intrinsics` and `core`. Where LLVM merges neighbouring intrinsics into one instruction
sequence, the line is the one the debug info picked and may be one of several that contributed.

## Findings

| # | Instruction | Backend | Config | Source | Count |
|---|---|---|---|---|---|
| 1 | `vunpcklpd`, `vunpckhpd`, `vmovlps` | avx2 | all | libcrux-sha3 `src/simd/avx2.rs:60-63, 162-165, 182` | 113 |
| 2 | `vshufps`, `vandps` | avx2 | all | `src/vector/avx2/compress.rs:103`; `src/vector/avx2/serialize.rs:179, 379, 569` | 156 |
| 3 | `vandps` | avx2 | base, base-size | out-of-line `_mm256_and_si256` | 8 |
| 4 | `shufps` | portable | base | `src/sampling.rs:201` | 320 |
| 5 | `vshufps`, `vinsertps`, `vmovss`, `vblendps` | portable | v3 | `src/vector/portable/ntt.rs:137, 340`; `src/vector/portable/serialize.rs:385-389`; libcrux-secrets `src/int.rs:92` | 9 |
| 6 | `bzhi` | portable | v3-size | `src/vector/portable/arithmetic.rs:32` | 1 |
| 7 | `vmovlhps` | shared | v3 | libcrux-sha3 `src/simd/portable.rs:79` | 12 |

1. **libcrux-sha3's 4-way Keccak transposes.** `mm256_unpacklo_epi64`/`mm256_unpackhi_epi64` in
   the absorb (`load_block`/`load_last`, lines 60-63) and squeeze (lines 162-165) come out as the
   floating-point `vunpcklpd`/`vunpckhpd` instead of the listed `VPUNPCKLQDQ`/`VPUNPCKHQDQ`. In
   the baseline builds the intrinsics aren't inlined and the same two instructions sit in
   out-of-line `_mm256_unpack{lo,hi}_epi64` copies called from those functions (4 of the 113).
   Line 182 is the squeeze's tail copy (`copy_from_slice` of 8 bytes), done with `vmovlps`.
   These hash the secret seeds (G, PRF, J) in every AVX2 operation.

2. **AVX2 compression and serialization.** LLVM fuses `mm256_packs_epi32` +
   `mm256_permute4x64_epi64` (and in places the `mm256_madd_epi16` around them) into
   `vpshufb` + `vshufps` + `vpermpd`. It also does some of the masking ANDs as `vandps`. The
   lines are in `compress_ciphertext_coefficient` (`compress.rs:103`), `mm256_concat_pairs_n`
   (`serialize.rs:179`, used by `serialize_4`, `serialize_10` and `serialize_12`), `serialize_5`
   (`:379`) and `serialize_10_vec` (`:569`). This is secret during decapsulation's re-encryption,
   whose ciphertext must not leak when it differs from the one received, and in `serialize_12`
   of the secret key.

3. **Out-of-line `_mm256_and_si256`.** In the baseline builds LLVM doesn't inline this
   intrinsic. It calls a standalone copy, whose body is `vandps`. Callers include
   `key_pair_from_private_mut`, `serialize_unpacked_secret_key`, `decompress_1` and
   `to_unsigned_representative`, all on secret data. The same build also calls an out-of-line
   `_mm256_set_epi8`, but only with constant masks, so that one is allowlisted.

4. **Portable CBD sampling at baseline.** `sampled_i16s[8 * chunk_number + offset] = outcome_1
   - outcome_2` in `sample_from_binomial_distribution_2` is vectorized with `shufps` to narrow
   lanes, since SSE2 has no integer instruction for it. 320 instructions across 16
   instantiations. It samples the secret vectors s, e, r, e1 and e2.

5. **Portable code at x86-64-v3.** In `inv_ntt_step` (`ntt.rs:137`), `ntt_multiply_binomials`
   (`ntt.rs:340` and its `as_i32` widening, `int.rs:92`) and `serialize_10_int`
   (`serialize.rs:385-389`), LLVM uses floating-point shuffles, inserts and blends on
   integers. All three run on secret data.

6. **`get_n_least_significant_bits` with BMI2.** `value & ((1 << n) - 1)` becomes `bzhi` in the
   size-optimized v3 build. Used by the portable compression.

7. **Single-lane Keccak absorb at v3.** The XOR of a block into the state in `load_block`
   (`simd/portable.rs:79`) is vectorized with `vmovlhps`. Both backends use this Keccak for
   their non-batched hashes, which take secret inputs.

Items 1 and 2 are the instructions that differ from what the source asked for in the AVX2 code a
normal build runs on any AVX2 machine. Items 3 and 4 appear only in builds without
`-C target-cpu`, which is also what a normal build is. Item 3 also costs a function call per
intrinsic.

## False positives

Both are on public data but can't be allowlisted. They are inlined into
`decapsulate_avx2`, `encapsulate_avx2` and the other top-level functions, and an entry covering
those would hide any later finding on secret data there (`--selftest` rejects such entries).

**`popcnt` in AVX2 rejection sampling** (288 instructions, v3 and v3-size). `count_ones()` at
`src/vector/avx2/sampling.rs:66, 78` counts the accepted lanes. `rej_sample` is reached only from
`sample_from_xof` and then `sample_matrix_A`, whose input is XOF(rho). `rho` is public: it is part
of the encapsulation key.

**`vshufps` in `decompress_ciphertext_coefficient`** (24 instructions, all configs).
`src/vector/avx2/compress.rs:181` is the same fused pack as item 2, but this function only
decompresses the received ciphertext, which is public.

## Allowlisted

These are in `instr-allowlist.txt` with reasons. Listed here so the report covers every hit.

| Instructions | Where | Why |
|---|---|---|
| `cpuid`, `xchg`, `xgetbv` | `libcrux_platform::x86::init::init_slow`, `core::core_arch::x86::xsave::_xgetbv` | CPU detection; no inputs |
| scalar float arithmetic | `rand::distr::uniform::float::UniformFloat` | float distributions; libcrux-ml-kem never calls them |
| `bsr`, `lzcnt` | libcrux-sha3 `cshake::zero_bytes` | encodes a length; cSHAKE isn't used by ML-KEM |
| `vblendps`, `vcmptrueps` | out-of-line `_mm256_set_epi8` | every caller passes constant shuffle masks |

`vmovups`, `vmovaps` and `vxorps` are accepted for all code (`X86_EXTRA` in `scan-instrs.py`) as
the VEX forms of the listed `MOVUPS`, `MOVAPS` and `XORPS`.

## Not covered

The probe instantiates the default features: the packed and unpacked APIs for ML-KEM-512, -768
and -1024 through both backends, and the top-level API that picks a backend at runtime. The
`kyber`, `incremental` and `pqcp` features are not built. The NEON backend is not scanned.
libcrux commits no `Cargo.lock`, so third-party dependencies (only `rand` contributed hits) are
whatever cargo resolved on the day; libcrux's own crates are path dependencies.
