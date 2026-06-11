//go:build windows

package vck

import (
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/sys/windows"
)

// IOCTL codes, identical to the values in lib/windrv/src/ioctl/codes.rs.
const (
	ioctlGetStatus    = 0x0022_2000
	ioctlStartEncrypt = 0x0022_2004
	ioctlStartDecrypt = 0x0022_2008
	ioctlGetProgress  = 0x0022_200c
	ioctlPause        = 0x0022_2010
	ioctlJvckPrepare  = 0x0022_201c // JVCK phase-1: attach filter + hide metadata region
	ioctlJvckAttach   = 0x0022_2014 // JVCK phase-2: read metadata + complete encryption setup
	ioctlDetach       = 0x0022_2018 // Data Volume: release encryption layer
	// Driver-internal (self-sent on shutdown/unload); listed here to keep the
	// IOCTL value space in sync with lib/windrv/src/ioctl/codes.rs.
	ioctlPauseOsVolume    = 0x0022_2020 // pause OS volume sweep (waits for in-flight batch)
	ioctlDetachAllVolumes = 0x0022_2024 // detach all data volumes
)

// deviceControl wraps DeviceIoControl with msgpack serialization.
func deviceControl[Req any, Resp any](
	handle windows.Handle,
	code uint32,
	req *Req,
) (*Resp, error) {
	inBuf, err := msgpack.Marshal(req)
	if err != nil {
		return nil, err
	}
	outBuf := make([]byte, 65536)
	var bytesReturned uint32

	err = windows.DeviceIoControl(
		handle, code,
		&inBuf[0], uint32(len(inBuf)),
		&outBuf[0], uint32(len(outBuf)),
		&bytesReturned, nil,
	)
	if err != nil {
		return nil, err
	}
	var resp Resp
	if err := msgpack.Unmarshal(outBuf[:bytesReturned], &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
