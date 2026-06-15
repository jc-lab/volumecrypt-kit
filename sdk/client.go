// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package vck

import "golang.org/x/sys/windows"

const devicePath = `\\.\VolumeCryptKitSample`

// Client represents a connection to the VolumeCryptKitSample kernel driver.
type Client struct {
	handle windows.Handle
}

// Open opens the driver device and returns a Client.
func Open() (*Client, error) {
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(devicePath),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return &Client{handle: h}, nil
}

// Close closes the driver device handle.
func (c *Client) Close() error {
	return windows.CloseHandle(c.handle)
}

// ─── Data Volume: two-phase Prepare + Attach ─────────────────────────────────

// Prepare is phase 1 of Data Volume attachment. It attaches the volume filter
// below the filesystem and activates size hiding so the footer metadata region
// is invisible to NTFS. The app must call EnsureJvckMetadata after Prepare and
// before Attach.
func (c *Client) Prepare(req *JvckVolumePrepareRequest) (*JvckVolumePrepareResponse, error) {
	r := *req
	nt, err := toNTPath(r.VolumePath)
	if err != nil {
		return nil, err
	}
	r.VolumePath = nt
	return deviceControl[JvckVolumePrepareRequest, JvckVolumePrepareResponse](
		c.handle, ioctlJvckPrepare, &r,
	)
}

// Attach activates the encryption layer on a Data Volume using the JVCK format.
// It passes the VMK and the replica configuration (use_header/use_footer/metadata_size).
// On reconnect after a reboot, encrypted_offset is restored from the volume's
// JVCK metadata. (Users with a custom format use their own IOCTL and
// EncryptedOffsetStore implementation, while the common IOCTLs exposed by this
// SDK can be reused as-is.)
func (c *Client) Attach(req *JvckVolumeAttachRequest) (*JvckVolumeAttachResponse, error) {
	r := *req
	nt, err := toNTPath(r.VolumePath)
	if err != nil {
		return nil, err
	}
	r.VolumePath = nt
	return deviceControl[JvckVolumeAttachRequest, JvckVolumeAttachResponse](
		c.handle, ioctlJvckAttach, &r,
	)
}

// Detach releases the encryption layer of a Data Volume.
// Call it when the volume is unmounted or needs to be locked.
func (c *Client) Detach(volumePath string) error {
	nt, err := toNTPath(volumePath)
	if err != nil {
		return err
	}
	_, err = deviceControl[VolumeDetachRequest, struct{}](
		c.handle, ioctlDetach,
		&VolumeDetachRequest{VolumePath: nt},
	)
	return err
}

// ─── Common (used by both OS Volume and Data Volume) ──────────────────────────

// GetStatus queries the current encryption state of the volume.
func (c *Client) GetStatus(volumePath string) (*VolumeStatus, error) {
	nt, err := toNTPath(volumePath)
	if err != nil {
		return nil, err
	}
	return deviceControl[volumeRequest, VolumeStatus](
		c.handle, ioctlGetStatus,
		&volumeRequest{VolumePath: nt},
	)
}

// ListVolumes returns every volume currently attached to the driver. It takes no
// volume path, so it doubles as a driver-connection check: a successful call
// (even with an empty list) confirms the device is reachable. Use this instead
// of GetStatus when no specific --volume is given.
func (c *Client) ListVolumes() (*VolumeListResponse, error) {
	return deviceControl[struct{}, VolumeListResponse](
		c.handle, ioctlListVolumes, &struct{}{},
	)
}

// StartEncrypt starts incremental encryption of an attached volume.
// Keys are already set at Attach time (or via ACPI handover for an OS Volume).
func (c *Client) StartEncrypt(req *EncryptRequest) error {
	r := *req
	nt, err := toNTPath(r.VolumePath)
	if err != nil {
		return err
	}
	r.VolumePath = nt
	_, err = deviceControl[EncryptRequest, struct{}](
		c.handle, ioctlStartEncrypt, &r,
	)
	return err
}

// StartDecrypt starts incremental decryption of an attached volume.
func (c *Client) StartDecrypt(req *DecryptRequest) error {
	r := *req
	nt, err := toNTPath(r.VolumePath)
	if err != nil {
		return err
	}
	r.VolumePath = nt
	_, err = deviceControl[DecryptRequest, struct{}](
		c.handle, ioctlStartDecrypt, &r,
	)
	return err
}

// Pause pauses an in-progress encryption/decryption.
func (c *Client) Pause(volumePath string) error {
	nt, err := toNTPath(volumePath)
	if err != nil {
		return err
	}
	_, err = deviceControl[volumeRequest, struct{}](
		c.handle, ioctlPause,
		&volumeRequest{VolumePath: nt},
	)
	return err
}

// BenchAes runs the in-kernel AES-256-XTS benchmark and returns encrypt and
// decrypt throughput in MiB/s. sizeBytes is the number of bytes to process per
// direction; pass 0 to use the default (1 GiB).
func (c *Client) BenchAes(sizeBytes uint64) (*BenchAesResponse, error) {
	return deviceControl[BenchAesRequest, BenchAesResponse](
		c.handle, ioctlBenchAes,
		&BenchAesRequest{SizeBytes: sizeBytes},
	)
}
