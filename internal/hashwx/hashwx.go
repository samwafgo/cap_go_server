// Copyright (c) 2020-2026 tevador <tevador@gmail.com>
// Pure-Go adaptation of HashWX. See NOTICE.md and LICENSE.

// Package hashwx implements the HashWX proof-of-work hash in pure Go.
// It uses an interpreter, not Cgo, JIT compilation, or a WebAssembly runtime.
// HashWX is not a general-purpose cryptographic digest.
package hashwx

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// SeedSize is the required seed length in bytes.
const SeedSize = 32

// ErrSeedSize indicates that the seed is not exactly SeedSize bytes long.
var ErrSeedSize = errors.New("hashwx: seed must be exactly 32 bytes")

// Program is an immutable HashWX instance containing 32 generated VM programs.
// Construct it with New; its zero value is not usable. A Program can be shared
// by concurrent callers: Hash keeps all mutable VM state local to each call.
type Program struct {
	code  [32][8]instruction
	key   [2]uint64
	valid bool
}

type instruction struct {
	op, dst, src, imm uint8
}

const (
	mulOr = iota
	mulXor
	mulAdd
	rmcg
	xorRor
	addRor
	subRor
	xorAsr
	addAsr
	subAsr
	xorLsr
	addLsr
	subLsr
)

// New generates a HashWX instance from exactly 32 seed bytes. It does not
// retain seed. Unlike HashX, this upstream HashWX generation algorithm has no
// rejected seeds: every seed of the correct size produces a program.
func New(seed []byte) (*Program, error) {
	if len(seed) != SeedSize {
		return nil, ErrSeedSize
	}
	p := &Program{key: [2]uint64{
		binary.LittleEndian.Uint64(seed[16:24]),
		binary.LittleEndian.Uint64(seed[24:32]),
	}, valid: true}
	gen := newRNG([2]uint64{
		binary.LittleEndian.Uint64(seed[:8]),
		binary.LittleEndian.Uint64(seed[8:16]),
	}, ^uint64(0))
	for n := range p.code {
		var random [8]uint64
		for i := range random {
			random[i] = gen.next()
		}
		code := &p.code[n]
		code[0].op = rmcg
		template := opcodeTemplates[random[7]%35]
		var dst [8]uint8
		for i := 0; i < 7; i++ {
			if template>>i&1 != 0 {
				code[i+1].op = uint8(uint32(random[i]) % 3)
			} else {
				code[i+1].op = xorRor + uint8(uint32(random[i])%9)
			}
			// The upper half selects destinations, the lower half opcodes.
			j := uint32(random[i]>>32) % uint32(i+2)
			dst[i+1] = dst[j]
			dst[j] = uint8(i + 1)
		}
		perm := shallowPermutations[random[7]%256]
		if n%6 == 0 {
			perm = deepPermutations[random[7]%24]
		}
		for i := range code {
			in := &code[i]
			in.dst = dst[i]
			if i == 0 {
				in.src = 8
			} else {
				in.src = dst[perm[i]]
			}
			selectImm := gen.next()
			switch {
			case in.op <= mulAdd:
				in.imm = [3]uint8{1, 9, 33}[selectImm%3]
			case in.op <= subRor:
				in.imm = 1 + uint8(selectImm%63)
			default:
				in.imm = 1 + uint8(selectImm%3)
			}
		}
	}
	return p, nil
}

// Hash generates an instance for seed and hashes input. For repeated hashing
// with the same seed, prefer New followed by Program.Hash to reuse generation.
func Hash(seed []byte, input uint64) (uint64, error) {
	p, err := New(seed)
	if err != nil {
		return 0, err
	}
	return p.Hash(input), nil
}

// Hash evaluates the program for a 64-bit nonce. Arithmetic wraps modulo 2^64,
// memory uses little-endian byte order and permits unaligned reads. Calling
// Hash on nil or on a Program not constructed by New panics.
func (p *Program) Hash(input uint64) uint64 {
	if p == nil || !p.valid {
		panic("hashwx: Program must be constructed with New")
	}
	gen := newRNG(p.key, input)
	var r [9]uint64
	for i := 0; i < 8; i++ {
		r[i] = gen.next()
	}
	r[8] = ((r[0] ^ r[4]) & ^uint64(7)) | 3
	var mem [16384 + 8]byte
	sp := 16384
	binary.LittleEndian.PutUint64(mem[sp:], r[8])
	for phase := 0; phase < 2; phase++ {
		for repeat := 0; repeat < 4; repeat++ {
			branches := 32
			for n := range p.code {
				code := &p.code[n]
				for {
					// STORE, omitted in the memory-read phase.
					if phase == 0 {
						sp -= 64
						for j := 0; j < 8; j++ {
							binary.LittleEndian.PutUint64(mem[sp+8*(7-j):], r[j])
						}
					}
					// RMCG always reads R8, even in the memory-read phase.
					in := code[0]
					v := bits.RotateLeft64(r[in.dst]*r[8], -int(in.imm))
					r[in.dst] = v
					branchFlag := v & 32
					for i := 1; i < 8; i++ {
						in = code[i]
						src := r[in.src]
						if phase == 1 {
							src = binary.LittleEndian.Uint64(mem[src&16383:])
						}
						dst := r[in.dst]
						switch in.op {
						case mulOr:
							dst = (dst | uint64(in.imm)) * src
						case mulXor:
							dst = (dst ^ uint64(in.imm)) * src
						case mulAdd:
							dst = (dst + uint64(in.imm)) * src
						case xorRor:
							dst = bits.RotateLeft64(dst, -int(in.imm)) ^ src
						case addRor:
							dst = bits.RotateLeft64(dst, -int(in.imm)) + src
						case subRor:
							dst = bits.RotateLeft64(dst, -int(in.imm)) - src
						case xorAsr:
							dst = uint64(int64(dst)>>in.imm) ^ src
						case addAsr:
							dst = uint64(int64(dst)>>in.imm) + src
						case subAsr:
							dst = uint64(int64(dst)>>in.imm) - src
						case xorLsr:
							dst = (dst >> in.imm) ^ src
						case addLsr:
							dst = (dst >> in.imm) + src
						case subLsr:
							dst = (dst >> in.imm) - src
						}
						r[in.dst] = dst
					}
					// CBRANCH, or UBRANCH in the last program; HALT otherwise.
					if branches == 0 || (n != 31 && branchFlag != 0) {
						break
					}
					branches--
				}
			}
		}
	}
	_, _, _, a := sipRound(r[0], r[1], r[2], r[3])
	_, _, _, b := sipRound(r[4], r[5], r[6], r[7])
	return a ^ b ^ r[8]
}
