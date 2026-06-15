// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package vck

import (
	"encoding/hex"
	"testing"
)

// crossCheckHex is the golden 512-byte JVCK Metadata block for a fixed input
// vector. The Rust reference encoder asserts the identical value in
// lib/common/src/jvck/metadata.rs (cross_check_vector_matches_golden), so this
// test fails if either implementation's on-disk format drifts.
const crossCheckHex = "4a56434b000000000000000001000000000002000002000000020000000000000102030405060708090a0b0c0d0e0f105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a2596594092215a84c28c512040b89465b5013606c9597f80993d82ab7ed62de7b259177923c5ef67aac93ce844eea143fd524315ee5643556e076f10056cf8d0fcc73e43af3ce790249a042f0cdb4126c9f78e5b7c854745b21a67a672e1d20769aad3fdde489426a4de635e62cef042a1882b9b748c558df412234e9f8557732be236e87fba6a2265a5be53e8b778a960c389af50380dc8a62921672fd2627c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b17a9689"

func TestCrossCheckVectorMatchesGolden(t *testing.T) {
	header := &JvckHeader{
		VendorID:           0,
		MetadataVersion:    1,
		VendorVersion:      0,
		MetadataSize:       131072,
		SectorSize:         512,
		HeaderReplicaCount: 0,
		FooterReplicaCount: 2,
		VolumeID:           [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	var fvek1, fvek2 [32]byte
	for i := range fvek1 {
		fvek1[i] = 0xA0
		fvek2[i] = 0x0B
	}
	// Fixed salt so the golden vector is deterministic (matches Rust TEST_SALT).
	var salt [SaltSize]byte
	for i := range salt {
		salt[i] = 0x5a
	}

	block, err := header.EncodeMetadataBlock(fvek1, fvek2, 12345, salt, []byte("jvck-cross-check-vmk"))
	if err != nil {
		t.Fatalf("EncodeMetadataBlock failed: %v", err)
	}
	got := hex.EncodeToString(block[:])
	if got != crossCheckHex {
		t.Fatalf("block mismatch:\n got  %s\n want %s", got, crossCheckHex)
	}
}

func TestReplicaLayoutMatchesRust(t *testing.T) {
	// 1024 sectors @ 512, footer-only with 2 replicas of 128 KiB (256 sectors).
	rs := replicaSectors(128*1024, 512)
	if rs != 256 {
		t.Fatalf("replicaSectors = %d, want 256", rs)
	}
	lbas := metadataSectorLBAs(1024, rs, 0, 2)
	// Footer replica metadata sectors are the last sector of each 256-sector
	// region: regions start at 512 and 768, so metadata at 767 and 1023.
	want := []uint64{767, 1023}
	if len(lbas) != len(want) {
		t.Fatalf("lbas = %v, want %v", lbas, want)
	}
	for i := range want {
		if lbas[i] != want[i] {
			t.Fatalf("lbas[%d] = %d, want %d", i, lbas[i], want[i])
		}
	}

	// Non-multiple metadata_size is floored: floor(131172/4096) = 32 sectors.
	if rs := replicaSectors(128*1024+100, 4096); rs != 32 {
		t.Fatalf("floored replicaSectors = %d, want 32", rs)
	}
}
