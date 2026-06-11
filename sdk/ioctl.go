// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package vck

import (
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/sys/windows"
)

// IOCTL codes, identical to the values in lib/windrv/src/ioctl/codes.rs.
//
// These are CTL_CODE(FILE_DEVICE_VCK=0x22, function, METHOD_BUFFERED, access)
// values. The access field (bits 15..14) is FILE_READ_ACCESS (0x4000) for
// read-only queries and FILE_WRITE_ACCESS (0x8000) for state-mutating commands.
// The exact hex below is verified by the Rust unit tests in
// lib/common/src/ioctl.rs and pinned by const assertions in codes.rs; copy them
// verbatim, do not recompute here.
const (
	// Read-only queries (FILE_READ_ACCESS).
	ioctlGetStatus   = 0x0022_6000
	ioctlGetProgress = 0x0022_600c
	// State-mutating commands (FILE_WRITE_ACCESS).
	ioctlStartEncrypt = 0x0022_a004
	ioctlStartDecrypt = 0x0022_a008
	ioctlPause        = 0x0022_a010
	ioctlJvckAttach   = 0x0022_a014 // JVCK phase-2: read metadata + complete encryption setup
	ioctlDetach       = 0x0022_a018 // Data Volume: release encryption layer
	ioctlJvckPrepare  = 0x0022_a01c // JVCK phase-1: attach filter + hide metadata region
	// Driver-internal (self-sent on shutdown/unload); listed here to keep the
	// IOCTL value space in sync with lib/windrv/src/ioctl/codes.rs.
	ioctlPauseOsVolume    = 0x0022_a020 // pause OS volume sweep (waits for in-flight batch)
	ioctlDetachAllVolumes = 0x0022_a024 // detach all data volumes
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
