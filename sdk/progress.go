//go:build windows

package vck

import "context"

// WatchProgress returns the encryption/decryption progress as a channel stream.
// Internally it polls IOCTL_VCK_GET_PROGRESS periodically from a goroutine.
// The channel is closed on ctx cancellation, completion (StateIdle), or pause
// (StatePaused).
func (c *Client) WatchProgress(
	ctx context.Context,
	volumePath string,
) (<-chan ProgressEvent, <-chan error) {
	evCh := make(chan ProgressEvent, 16)
	errCh := make(chan error, 1)

	go func() {
		defer close(evCh)
		defer close(errCh)
		req := &volumeRequest{VolumePath: volumePath}
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			ev, err := deviceControl[volumeRequest, ProgressEvent](
				c.handle, ioctlGetProgress, req,
			)
			if err != nil {
				errCh <- err
				return
			}
			evCh <- *ev
			if ev.State == StateIdle || ev.State == StatePaused {
				// Completed (Idle) or paused (Paused) -> stop polling.
				return
			}
		}
	}()

	return evCh, errCh
}
