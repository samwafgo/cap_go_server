// Copyright (c) 2020-2026 tevador <tevador@gmail.com>
// Pure-Go adaptation of HashWX. See NOTICE.md and LICENSE.

package hashwx

import "math/bits"

type rng struct {
	key   [2]uint64
	state [4]uint64
	count int
}

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v2 += v3
	v1 = bits.RotateLeft64(v1, 13)
	v3 = bits.RotateLeft64(v3, 16)
	v1 ^= v0
	v3 ^= v2
	v0 = bits.RotateLeft64(v0, 32)
	v2 += v1
	v0 += v3
	v1 = bits.RotateLeft64(v1, 17)
	v3 = bits.RotateLeft64(v3, 21)
	v1 ^= v2
	v3 ^= v0
	v2 = bits.RotateLeft64(v2, 32)
	return v0, v1, v2, v3
}

func newRNG(key [2]uint64, salt uint64) rng {
	v0 := uint64(0x736f6d6570736575) ^ key[0]
	v1 := uint64(0x646f72616e646f6d) ^ key[1]
	v2 := uint64(0x6c7967656e657261) ^ key[0]
	v3 := uint64(0x7465646279746573) ^ key[1] ^ salt
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= salt
	v2 ^= 0xbb
	for i := 0; i < 3; i++ {
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	}
	return rng{key: key, state: [4]uint64{v0, v1, v2, v3}, count: 4}
}

func (g *rng) next() uint64 {
	if g.count == 0 {
		v0 := g.state[0] ^ g.key[0]
		v1 := g.state[1] ^ g.key[1]
		v2 := g.state[2] ^ g.key[0]
		v3 := g.state[3] ^ g.key[1]
		for i := 0; i < 4; i++ {
			v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		}
		g.state = [4]uint64{v0, v1, v2, v3}
		g.count = 4
	}
	g.count--
	return g.state[g.count]
}
