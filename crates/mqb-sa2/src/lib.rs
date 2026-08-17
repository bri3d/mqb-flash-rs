//! SA2 seed-key bytecode VM.
//!
//! Ported from `bri3d/sa2_seed_key`. The VM has:
//! - One 32-bit accumulator register
//! - One carry flag
//! - An instruction pointer
//! - A for-loop stack
//!
//! ## Opcodes
//! | Byte | Name   | Operand    | Description                                      |
//! |------|--------|------------|--------------------------------------------------|
//! | 0x68 | for    | 1 byte     | Push loop counter on stack, start for loop       |
//! | 0x49 | next   | –          | Decrement top counter, jump to matching `for`    |
//! | 0x4A | bcc    | 1 byte sig | Branch if carry clear (signed offset)            |
//! | 0x6B | bra    | 1 byte sig | Unconditional branch (signed offset)             |
//! | 0x81 | rsl    | –          | Circular left rotate; carry = old bit31          |
//! | 0x82 | rsr    | –          | Circular right rotate; carry = old bit0          |
//! | 0x84 | sub    | 4 bytes BE | accumulator -= operand; carry set on borrow      |
//! | 0x87 | xor    | 4 bytes BE | accumulator ^= operand                           |
//! | 0x93 | add    | 4 bytes BE | accumulator += operand; carry set on overflow    |
//! | 0x4C | finish | –          | Return accumulator as result                     |

use mqb_bytes::read_u32_be;

/// Maximum instructions executed before the VM aborts (guards against infinite loops).
const MAX_INSTRUCTIONS: u32 = 100_000;

/// SA2 seed-key bytecode interpreter.
pub struct Sa2Vm<'a> {
    script: &'a [u8],
}

impl<'a> Sa2Vm<'a> {
    pub fn new(script: &'a [u8]) -> Self {
        Self { script }
    }

    /// Execute the script with the given seed and return the computed key.
    ///
    /// Returns the accumulator value.  On malformed bytecode (out-of-bounds
    /// operand read, bad branch target, unknown opcode, or instruction budget
    /// exhausted) execution stops early and returns the current accumulator.
    /// Well-formed scripts always terminate via the `0x4C` (finish) opcode.
    pub fn execute(&self, seed: u32) -> u32 {
        let script = self.script;
        let mut acc: u32 = seed;
        let mut carry: bool = false;
        let mut ip: usize = 0;
        let mut budget = MAX_INSTRUCTIONS;

        // For-loop stack: (remaining_iterations, ip_of_loop_body_start)
        let mut loop_stack: Vec<(u32, usize)> = Vec::with_capacity(8);

        loop {
            if ip >= script.len() {
                break;
            }
            if budget == 0 {
                break;
            }
            budget -= 1;

            let op = script[ip];
            ip += 1;

            match op {
                0x68 => {
                    // for(count): push (count, ip_after_operand) onto stack
                    if ip >= script.len() {
                        break;
                    }
                    let count = script[ip] as u32;
                    ip += 1;
                    loop_stack.push((count, ip));
                }
                0x49 => {
                    // next: decrement top counter; if > 0, jump back to loop body
                    if let Some(top) = loop_stack.last_mut() {
                        top.0 -= 1;
                        if top.0 > 0 {
                            ip = top.1;
                        } else {
                            loop_stack.pop();
                        }
                    }
                }
                0x4A => {
                    // bcc offset: branch if carry clear
                    if ip >= script.len() {
                        break;
                    }
                    let offset = script[ip] as i8;
                    ip += 1;
                    if !carry {
                        match (ip as isize).checked_add(offset as isize) {
                            Some(new_ip) if new_ip >= 0 => ip = new_ip as usize,
                            _ => break,
                        }
                    }
                }
                0x6B => {
                    // bra offset: unconditional branch
                    if ip >= script.len() {
                        break;
                    }
                    let offset = script[ip] as i8;
                    ip += 1;
                    match (ip as isize).checked_add(offset as isize) {
                        Some(new_ip) if new_ip >= 0 => ip = new_ip as usize,
                        _ => break,
                    }
                }
                0x81 => {
                    // rsl: circular left rotate — carry = old bit31, bit0 = old bit31
                    carry = (acc >> 31) != 0;
                    acc = acc.rotate_left(1);
                }
                0x82 => {
                    // rsr: circular right rotate — carry = old bit0, bit31 = old bit0
                    carry = (acc & 1) != 0;
                    acc = acc.rotate_right(1);
                }
                0x84 => {
                    // sub operand (4 bytes BE); carry set on borrow
                    if ip + 4 > script.len() {
                        break;
                    }
                    let operand = read_u32_be(script, ip);
                    ip += 4;
                    let (result, borrowed) = acc.overflowing_sub(operand);
                    acc = result;
                    carry = borrowed;
                }
                0x87 => {
                    // xor operand (4 bytes BE)
                    if ip + 4 > script.len() {
                        break;
                    }
                    let operand = read_u32_be(script, ip);
                    ip += 4;
                    acc ^= operand;
                }
                0x93 => {
                    // add operand (4 bytes BE); carry set on overflow
                    if ip + 4 > script.len() {
                        break;
                    }
                    let operand = read_u32_be(script, ip);
                    ip += 4;
                    let (result, overflowed) = acc.overflowing_add(operand);
                    acc = result;
                    carry = overflowed;
                }
                0x4C => {
                    // finish: return accumulator
                    return acc;
                }
                _ => {
                    // Unknown opcode — abort execution
                    break;
                }
            }
        }

        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sa2_vector_script1() {
        let script = [
            0x68, 0x02, 0x81, 0x49, 0x93, 0xa5, 0x5a, 0x55, 0xaa, 0x4a, 0x05, 0x87, 0x81, 0x05,
            0x95, 0x26, 0x68, 0x05, 0x82, 0x49, 0x84, 0x5a, 0xa5, 0xaa, 0x55, 0x87, 0x03, 0xf7,
            0x80, 0x6a, 0x4c,
        ];
        assert_eq!(Sa2Vm::new(&script).execute(0x1a1b1c1d), 0x6a37f02e);
    }

    #[test]
    fn sa2_vector_script2() {
        let script = [
            0x68, 0x02, 0x81, 0x4A, 0x10, 0x68, 0x04, 0x93, 0x08, 0x08, 0x20, 0x09, 0x4A, 0x05,
            0x87, 0x22, 0x12, 0x19, 0x54, 0x82, 0x49, 0x93, 0x07, 0x12, 0x20, 0x11, 0x82, 0x4A,
            0x05, 0x87, 0x03, 0x11, 0x20, 0x10, 0x82, 0x4A, 0x01, 0x81, 0x49, 0x4C,
        ];
        assert_eq!(Sa2Vm::new(&script).execute(0xa04eb1ed), 0x3C7876D8);
    }

    #[test]
    fn sa2_simos1810_vector() {
        // S1810 SA2 script; seed from a real captured session.
        // Both Python (bri3d/sa2_seed_key) and manual trace confirm 0x4835B093.
        let script = [
            0x68u8, 0x03, 0x81, 0x4A, 0x10, 0x68, 0x02, 0x93, 0x05, 0x05, 0x20, 0x15, 0x4A, 0x05,
            0x87, 0x22, 0x12, 0x19, 0x54, 0x82, 0x49, 0x93, 0xF4, 0x23, 0xBF, 0x7D, 0x82, 0x4A,
            0x05, 0x87, 0x5A, 0x63, 0xFC, 0x5E, 0x82, 0x4A, 0x01, 0x81, 0x49, 0x4C,
        ];
        assert_eq!(Sa2Vm::new(&script).execute(0x80551824), 0x4835B093);
    }

    #[test]
    fn truncated_script_does_not_panic() {
        // Opcode 0x93 (add) needs 4 operand bytes; this script has only 2.
        let script = [0x93, 0x00, 0x00];
        assert_eq!(Sa2Vm::new(&script).execute(0xDEAD_BEEF), 0xDEAD_BEEF);
    }

    #[test]
    fn negative_branch_does_not_panic() {
        // 0x6B (bra) with offset -5 from ip=2 would underflow to a huge usize.
        let script = [0x6B, 0xFBu8]; // offset = -5 as i8
        assert_eq!(Sa2Vm::new(&script).execute(42), 42);
    }

    #[test]
    fn unknown_opcode_does_not_panic() {
        let script = [0xFF];
        assert_eq!(Sa2Vm::new(&script).execute(7), 7);
    }

    #[test]
    fn instruction_budget_terminates() {
        // Infinite loop: for(255) { next } — the VM must terminate.
        let script = [0x68, 0xFF, 0x49];
        let _ = Sa2Vm::new(&script).execute(0);
    }
}
