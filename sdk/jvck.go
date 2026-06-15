// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package vck

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// Go port of the JVCK Metadata block encoder and replica layout from
// lib/common/src/jvck. First-time encryption (metadata creation + footer write)
// is the SDK's responsibility; the kernel driver only ever opens existing
// metadata. The byte layout, key derivation, and crypto here MUST stay
// byte-for-byte compatible with the Rust implementation (see the cross-check in
// jvck_test.go).

const (
	// MetadataBlockSize is the fixed size of the on-disk Metadata block.
	MetadataBlockSize = 512
	// MinMetadataSize is the minimum size of a single replica region (Metadata
	// block + vendor data).
	MinMetadataSize = 128 * 1024

	encryptedMetadataSize = 128
	hmacSize              = 32
	// SaltSize is the per-write random salt mixed into key derivation.
	SaltSize = 16
	// VendorReservedSize is the in-block vendor-defined area (offset 304).
	VendorReservedSize = 192
)

var jvckSignature = [4]byte{'J', 'V', 'C', 'K'}

// HKDF-SHA256 info labels (must match metadata.rs).
var (
	infoMAC = []byte("EncryptedMetadata:MAC")
	infoENC = []byte("EncryptedMetadata:ENC")
	infoIV  = []byte("EncryptedMetadata:IV")
)

// Metadata block field offsets.
const (
	offSignature       = 0
	offVendorID        = 4
	offMetadataVersion = 12
	offVendorVersion   = 14
	offMetadataSize    = 16
	offSectorSize      = 20
	offHeaderCount     = 24
	offFooterCount     = 25
	offVolumeID        = 32
	offSalt            = 48
	offEncryptedMeta   = 64
	offHMAC = 192
	// Aligned tail: 224..304 Reserved (zero); 304..496 Vendor Specific Reserved
	// (192, 16-byte aligned); 496..508 Reserved (zero, 12); 508..512 Header CRC32.
	offVendorReserved = 304
	offCRC32          = 508
	crcCoverageEnd    = 508
)

// EncryptedMetadata (128-byte plaintext) field offsets.
const (
	emOffSignature       = 0
	emOffEncryptedOffset = 16
	// emOffState (u16): 0 = Encrypt, 1 = Decrypt. The app only ever creates
	// volumes in the Encrypt state, so the zero-initialized plaintext already
	// encodes it; this offset is documented here for cross-format parity.
	emOffState    = 24
	emOffFvekKey1 = 32
	emOffFvekKey2 = 64
)

// JvckHeader holds the plaintext header fields of a Metadata block.
type JvckHeader struct {
	VendorID           uint64
	MetadataVersion    uint16
	VendorVersion      uint16
	MetadataSize       uint32
	SectorSize         uint32
	HeaderReplicaCount uint8
	FooterReplicaCount uint8
	VolumeID           [16]byte
	// VendorReserved is the 192-byte in-block vendor-defined area (offset 304).
	VendorReserved [VendorReservedSize]byte
}

type derivedKeys struct {
	macKey [32]byte
	encKey [32]byte
	encIV  [16]byte
}

// hkdfExtract computes PRK = HMAC-SHA256(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// hkdfExpand expands PRK into `length` bytes of output keying material using
// `info`, per RFC 5869.
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{counter})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// deriveKeys mirrors metadata.rs `derive_keys`:
// HKDF-SHA256(salt = Volume ID || salt, ikm = VMK, info = label).
func deriveKeys(volumeID [16]byte, salt [SaltSize]byte, vmk []byte) derivedKeys {
	hkdfSalt := make([]byte, 0, 16+SaltSize)
	hkdfSalt = append(hkdfSalt, volumeID[:]...)
	hkdfSalt = append(hkdfSalt, salt[:]...)
	prk := hkdfExtract(hkdfSalt, vmk)
	var k derivedKeys
	copy(k.macKey[:], hkdfExpand(prk, infoMAC, 32))
	copy(k.encKey[:], hkdfExpand(prk, infoENC, 32))
	copy(k.encIV[:], hkdfExpand(prk, infoIV, 16))
	return k
}

// EncodeMetadataBlock serializes the header, the (sensitive) FVEK halves, and
// encryptedOffset into a 512-byte block: AES-256-CBC EncryptedMetadata,
// HMAC-SHA256 over the ciphertext, and a Header CRC32 over [0,508).
// The per-write `salt` (plaintext, offset 48) is mixed into key derivation and
// must be freshly random for each (re)encode; callers generate it with
// crypto/rand. The 192-byte Vendor Specific Reserved area (offset 316) is left
// zero by this default encoder.
func (h *JvckHeader) EncodeMetadataBlock(
	fvek1, fvek2 [32]byte,
	encryptedOffset uint64,
	salt [SaltSize]byte,
	vmk []byte,
) ([MetadataBlockSize]byte, error) {
	var out [MetadataBlockSize]byte
	copy(out[offSignature:], jvckSignature[:])
	binary.LittleEndian.PutUint64(out[offVendorID:], h.VendorID)
	binary.LittleEndian.PutUint16(out[offMetadataVersion:], h.MetadataVersion)
	binary.LittleEndian.PutUint16(out[offVendorVersion:], h.VendorVersion)
	binary.LittleEndian.PutUint32(out[offMetadataSize:], h.MetadataSize)
	binary.LittleEndian.PutUint32(out[offSectorSize:], h.SectorSize)
	out[offHeaderCount] = h.HeaderReplicaCount
	out[offFooterCount] = h.FooterReplicaCount
	copy(out[offVolumeID:], h.VolumeID[:])
	// Per-write salt (plaintext): read back at decrypt time to re-derive keys.
	copy(out[offSalt:offSalt+SaltSize], salt[:])
	// Vendor Specific Reserved area (plaintext, CRC-covered).
	copy(out[offVendorReserved:offVendorReserved+VendorReservedSize], h.VendorReserved[:])

	// 128-byte EncryptedMetadata plaintext (signature + offset + FVEK halves).
	var plain [encryptedMetadataSize]byte
	copy(plain[emOffSignature:], jvckSignature[:])
	binary.LittleEndian.PutUint64(plain[emOffEncryptedOffset:], encryptedOffset)
	copy(plain[emOffFvekKey1:], fvek1[:])
	copy(plain[emOffFvekKey2:], fvek2[:])

	keys := deriveKeys(h.VolumeID, salt, vmk)
	block, err := aes.NewCipher(keys.encKey[:])
	if err != nil {
		return out, err
	}
	// AES-256-CBC, no padding (128 is a multiple of the 16-byte block size).
	cipher.NewCBCEncrypter(block, keys.encIV[:]).CryptBlocks(plain[:], plain[:])
	copy(out[offEncryptedMeta:offEncryptedMeta+encryptedMetadataSize], plain[:])

	// HMAC-SHA256 over the (encrypted) blob.
	mac := hmac.New(sha256.New, keys.macKey[:])
	mac.Write(out[offEncryptedMeta : offEncryptedMeta+encryptedMetadataSize])
	copy(out[offHMAC:offHMAC+hmacSize], mac.Sum(nil))

	// Header CRC32 (IEEE) over [0, 508).
	binary.LittleEndian.PutUint32(out[offCRC32:], crc32.ChecksumIEEE(out[:crcCoverageEnd]))
	return out, nil
}

// verifyMetadataCRC reports whether a block carries a `JVCK` signature and a
// matching Header CRC32. This is checkable without the VMK and is used to tell a
// blank tail apart from already-initialized metadata.
func verifyMetadataCRC(block []byte) bool {
	if len(block) < MetadataBlockSize {
		return false
	}
	if !bytesEqual(block[offSignature:offSignature+4], jvckSignature[:]) {
		return false
	}
	stored := binary.LittleEndian.Uint32(block[offCRC32:])
	return crc32.ChecksumIEEE(block[:crcCoverageEnd]) == stored
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// replicaSectors returns the whole-sector size of one replica region.
//
// The 512-byte Metadata block always occupies one sector and the vendor area is
// floor((metadata_size - sector_size) / sector_size) sectors, so the total is
// floor(metadata_size / sector_size): a metadata_size that is not a multiple of
// the sector size drops the remainder (the region never exceeds metadata_size).
func replicaSectors(metadataSize, sectorSize uint32) uint64 {
	return uint64(metadataSize / sectorSize)
}

// EncryptSector encrypts a single sector in-place using AES-XTS with the given
// FVEK halves and the sector's data-region-relative sector number as the tweak.
// This matches lib/common/src/xts.rs (XtsVolumeCipher::encrypt_sector).
//
// Used by the app to pre-encrypt sector 0 (VBR) before calling PREPARE so the
// driver can write it to disk while the volume is locked+dismounted, bypassing
// PartMgr's protection for sector 0 of mounted partitions.
func EncryptSector(fvek1, fvek2 [32]byte, sectorNumber uint64, sector []byte) error {
	if len(sector) == 0 || len(sector)%16 != 0 {
		return fmt.Errorf("sector length must be a multiple of 16 bytes")
	}
	c1, err := aes.NewCipher(fvek1[:])
	if err != nil {
		return err
	}
	c2, err := aes.NewCipher(fvek2[:])
	if err != nil {
		return err
	}

	// Compute the XTS tweak for this sector: T = E_k2(sector_number_LE128)
	var tweak [16]byte
	binary.LittleEndian.PutUint64(tweak[:8], sectorNumber)
	// high 8 bytes stay zero (128-bit sector number)
	c2.Encrypt(tweak[:], tweak[:])

	blockSize := 16
	for i := 0; i < len(sector); i += blockSize {
		// XOR with tweak
		for j := 0; j < blockSize; j++ {
			sector[i+j] ^= tweak[j]
		}
		// Encrypt with k1
		c1.Encrypt(sector[i:i+blockSize], sector[i:i+blockSize])
		// XOR with tweak again
		for j := 0; j < blockSize; j++ {
			sector[i+j] ^= tweak[j]
		}
		// Multiply tweak by x (GF(2^128) with polynomial x^128+x^7+x^2+x+1)
		xtsGFMul(&tweak)
	}
	return nil
}

// xtsGFMul multiplies a 128-bit GF(2^128) element by x (the primitive element).
func xtsGFMul(t *[16]byte) {
	var carry byte
	for i := 0; i < 16; i++ {
		next := t[i] >> 7
		t[i] = (t[i] << 1) | carry
		carry = next
	}
	if carry != 0 {
		t[0] ^= 0x87 // x^128 + x^7 + x^2 + x + 1
	}
}

// metadataSectorLBAs returns the absolute LBA of every replica's Metadata sector
// (header replicas first, then footer replicas), matching store.rs.
//
// Header replica i: Metadata is the FIRST sector of the region.
// Footer replica j: Metadata is the LAST sector of the region, so the final
// footer replica's Metadata is the volume's very last sector.
func metadataSectorLBAs(volumeSectors, rs uint64, useHeader, useFooter uint32) []uint64 {
	lbas := make([]uint64, 0, int(useHeader)+int(useFooter))
	for i := uint64(0); i < uint64(useHeader); i++ {
		lbas = append(lbas, i*rs)
	}
	footerStart := volumeSectors - uint64(useFooter)*rs
	for j := uint64(0); j < uint64(useFooter); j++ {
		regionStart := footerStart + j*rs
		lbas = append(lbas, regionStart+rs-1)
	}
	return lbas
}
