// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package vck

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/sys/windows"
)

// fsctlAllowExtendedDasdIo lifts the filesystem-extent bound on a mounted
// volume handle so raw reads/writes can reach the partition tail that
// ShrinkVolumeTail freed (where the footer metadata lives).
//
// CTL_CODE(FILE_DEVICE_FILE_SYSTEM=9, 32, METHOD_NEITHER=3, FILE_ANY_ACCESS=0)
// = (9<<16) | (32<<2) | 3 = 0x00090083.
const fsctlAllowExtendedDasdIo = 0x00090083

// HasJvckMetadata returns true if the volume's last sector already contains a
// valid JVCK Metadata block (CRC check only, no VMK needed). length and
// sectorSize must be queried beforehand via VolumeLengthAndSectorSize.
func HasJvckMetadata(volumePath string, length uint64, sectorSize uint32) (bool, error) {
	if sectorSize < MetadataBlockSize {
		return false, fmt.Errorf("sector size %d smaller than %d", sectorSize, MetadataBlockSize)
	}
	handle, err := openVolumeHandle(volumePath, windows.GENERIC_READ)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(handle)
	if err := allowExtendedDasdIo(handle); err != nil {
		return false, err
	}
	volumeSectors := length / uint64(sectorSize)
	last := make([]byte, sectorSize)
	if err := readSectorAt(handle, int64(volumeSectors-1)*int64(sectorSize), last); err != nil {
		return false, fmt.Errorf("failed to probe footer metadata: %w", err)
	}
	return verifyMetadataCRC(last), nil
}

// EnsureJvckMetadata makes sure the volume carries JVCK metadata, writing it on
// first-time encryption.
//
// It opens the volume with extended-DASD access, and if the tail does not
// already hold a valid JVCK Metadata block it generates a fresh FVEK + volume id
// with the CSPRNG, encodes the seed metadata (encrypted_offset = 0), and writes
// every replica into the reserved tail. On a re-attach (metadata already
// present) it is a no-op, so it is safe to call unconditionally after
// ShrinkVolumeTail. The volume must already be shrunk by
// `useFooter * metadataSize` bytes.
//
// Returns true when it wrote new metadata, false when metadata already existed.
func EnsureJvckMetadata(
	volumePath string,
	vmk []byte,
	useHeader, useFooter, metadataSize uint32,
) (bool, error) {
	if useHeader+useFooter == 0 {
		return false, fmt.Errorf("use_header + use_footer must be >= 1")
	}
	if metadataSize < MinMetadataSize {
		return false, fmt.Errorf("metadata_size must be at least %d bytes", MinMetadataSize)
	}

	handle, err := openVolumeHandle(volumePath, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(handle)

	if err := allowExtendedDasdIo(handle); err != nil {
		return false, err
	}

	length, sectorSize, err := readVolumeLengthAndSectorSizeFromHandle(handle)
	if err != nil {
		return false, err
	}
	if sectorSize < MetadataBlockSize {
		return false, fmt.Errorf("sector size %d smaller than %d", sectorSize, MetadataBlockSize)
	}
	volumeSectors := uint64(length) / uint64(sectorSize)
	rs := replicaSectors(metadataSize, sectorSize)
	if rs == 0 {
		return false, fmt.Errorf("metadata_size smaller than one sector")
	}
	if uint64(useHeader+useFooter)*rs >= volumeSectors {
		return false, fmt.Errorf("volume too small to hold metadata replicas")
	}

	// Already initialized? The volume's last sector is always a footer Metadata
	// block; a valid CRC there (checkable without the VMK) means re-attach.
	last := make([]byte, sectorSize)
	if err := readSectorAt(handle, int64(volumeSectors-1)*int64(sectorSize), last); err != nil {
		return false, fmt.Errorf("failed to probe footer metadata: %w", err)
	}
	if verifyMetadataCRC(last) {
		return false, nil
	}

	var fvek1, fvek2 [32]byte
	var volumeID [16]byte
	var salt [SaltSize]byte
	if err := fillRandom(fvek1[:], fvek2[:], volumeID[:], salt[:]); err != nil {
		return false, err
	}

	header := &JvckHeader{
		MetadataVersion:    1,
		MetadataSize:       metadataSize,
		SectorSize:         sectorSize,
		HeaderReplicaCount: uint8(useHeader),
		FooterReplicaCount: uint8(useFooter),
		VolumeID:           volumeID,
	}
	block, err := header.EncodeMetadataBlock(fvek1, fvek2, 0, salt, vmk)
	if err != nil {
		return false, fmt.Errorf("failed to encode JVCK metadata: %w", err)
	}

	// The Metadata block sits alone in its sector (the layout is sector-aligned),
	// so the rest of the sector is zero-filled.
	sector := make([]byte, sectorSize)
	copy(sector, block[:])
	for _, lba := range metadataSectorLBAs(volumeSectors, rs, useHeader, useFooter) {
		if err := writeSectorAt(handle, int64(lba)*int64(sectorSize), sector); err != nil {
			return false, fmt.Errorf("failed to write metadata replica at lba %d: %w", lba, err)
		}
	}
	return true, nil
}

func allowExtendedDasdIo(handle windows.Handle) error {
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		handle,
		fsctlAllowExtendedDasdIo,
		nil, 0, nil, 0,
		&bytesReturned, nil,
	); err != nil {
		return fmt.Errorf("FSCTL_ALLOW_EXTENDED_DASD_IO failed: %w", err)
	}
	return nil
}

// offsetOverlapped positions a synchronous Read/WriteFile at an absolute byte
// offset. The handle is opened without FILE_FLAG_OVERLAPPED, so the call still
// completes synchronously; the OVERLAPPED only carries the offset.
func offsetOverlapped(offset int64) *windows.Overlapped {
	return &windows.Overlapped{
		Offset:     uint32(uint64(offset) & 0xFFFFFFFF),
		OffsetHigh: uint32(uint64(offset) >> 32),
	}
}

func readSectorAt(handle windows.Handle, offset int64, buf []byte) error {
	var read uint32
	if err := windows.ReadFile(handle, buf, &read, offsetOverlapped(offset)); err != nil {
		return err
	}
	if int(read) != len(buf) {
		return fmt.Errorf("short read: %d of %d bytes", read, len(buf))
	}
	return nil
}

func writeSectorAt(handle windows.Handle, offset int64, buf []byte) error {
	var written uint32
	if err := windows.WriteFile(handle, buf, &written, offsetOverlapped(offset)); err != nil {
		return err
	}
	if int(written) != len(buf) {
		return fmt.Errorf("short write: %d of %d bytes", written, len(buf))
	}
	return nil
}

func fillRandom(bufs ...[]byte) error {
	for _, b := range bufs {
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("failed to read CSPRNG: %w", err)
		}
	}
	return nil
}
