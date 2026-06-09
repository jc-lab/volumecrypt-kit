package vck

import (
	"encoding/hex"
	"testing"
)

// crossCheckHex is the golden 512-byte JVCK Metadata block for a fixed input
// vector. The Rust reference encoder asserts the identical value in
// lib/common/src/jvck/metadata.rs (cross_check_vector_matches_golden), so this
// test fails if either implementation's on-disk format drifts.
const crossCheckHex = "4a56434b000000000000000001000000000002000002000000020000000000000102030405060708090a0b0c0d0e0f10aed78456db063a76376e3d7dc9f80d78bffb7989ec8747e0880a146a239c593b3a309d9e5e689fbf3c9e78e08c7e95c56f96cc5f9f25210dcd1c42aa00577104186fbba87c3b18334e326285d956bf34adf63f9b3538664017f0003123e95cd2c601c29a849e5ea83222b36eee0b255fe94466519e64fc74506952e3916d74f909b55a6cf38846ab7bc629af2857f1628d7638ff0a2e0b7213cf0bc4bca3adc3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bd09257c"

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

	block, err := header.EncodeMetadataBlock(fvek1, fvek2, 12345, []byte("jvck-cross-check-vmk"))
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
