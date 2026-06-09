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
	return deviceControl[JvckVolumePrepareRequest, JvckVolumePrepareResponse](
		c.handle, ioctlJvckPrepare, req,
	)
}

// Attach activates the encryption layer on a Data Volume using the JVCK format.
// It passes the VMK and the replica configuration (use_header/use_footer/metadata_size).
// On reconnect after a reboot, encrypted_offset is restored from the volume's
// JVCK metadata. (Users with a custom format use their own IOCTL and
// EncryptedOffsetStore implementation, while the common IOCTLs exposed by this
// SDK can be reused as-is.)
func (c *Client) Attach(req *JvckVolumeAttachRequest) (*JvckVolumeAttachResponse, error) {
	return deviceControl[JvckVolumeAttachRequest, JvckVolumeAttachResponse](
		c.handle, ioctlJvckAttach, req,
	)
}

// Detach releases the encryption layer of a Data Volume.
// Call it when the volume is unmounted or needs to be locked.
func (c *Client) Detach(volumePath string) error {
	_, err := deviceControl[VolumeDetachRequest, struct{}](
		c.handle, ioctlDetach,
		&VolumeDetachRequest{VolumePath: volumePath},
	)
	return err
}

// ─── Common (used by both OS Volume and Data Volume) ──────────────────────────

// GetStatus queries the current encryption state of the volume.
func (c *Client) GetStatus(volumePath string) (*VolumeStatus, error) {
	return deviceControl[volumeRequest, VolumeStatus](
		c.handle, ioctlGetStatus,
		&volumeRequest{VolumePath: volumePath},
	)
}

// StartEncrypt starts incremental encryption of an attached volume.
// Keys are already set at Attach time (or via ACPI handover for an OS Volume).
func (c *Client) StartEncrypt(req *EncryptRequest) error {
	_, err := deviceControl[EncryptRequest, struct{}](
		c.handle, ioctlStartEncrypt, req,
	)
	return err
}

// StartDecrypt starts incremental decryption of an attached volume.
func (c *Client) StartDecrypt(req *DecryptRequest) error {
	_, err := deviceControl[DecryptRequest, struct{}](
		c.handle, ioctlStartDecrypt, req,
	)
	return err
}

// Pause pauses an in-progress encryption/decryption.
func (c *Client) Pause(volumePath string) error {
	_, err := deviceControl[volumeRequest, struct{}](
		c.handle, ioctlPause,
		&volumeRequest{VolumePath: volumePath},
	)
	return err
}
