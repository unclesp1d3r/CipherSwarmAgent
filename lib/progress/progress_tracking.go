// Package progress provides utility functions for progress tracking and other common tasks.
package progress

// Source: https://raw.githubusercontent.com/hashicorp/go-getter/main/cmd/go-getter/progress_tracking.go
// Progress tracking for downloads.
// Borrowed from hashicorp/go-getter

import (
	"io"
	"path/filepath"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-getter"
)

// DefaultProgressBar is the default instance of a cheggaaa progress bar.
var DefaultProgressBar getter.ProgressTracker = &progressBar{} //nolint:gochecknoglobals // Default progress bar instance

// progressBar wraps a github.com/cheggaaa/pb.Pool
// in order to display download progress for one or multiple
// downloads.
//
// If two different instance of progressBar try to
// display a progress only one will be displayed.
// It is therefore recommended to use DefaultProgressBar.
type progressBar struct {
	// lock everything below
	lock sync.Mutex

	pool *pb.Pool

	pbs int
}

func progressBarConfig(bar *pb.ProgressBar, prefix string) {
	bar.Set(pb.Bytes, true)
	bar.Set("prefix", prefix)
}

// TrackProgress instantiates a new progress bar that will
// display the progress of stream until closed.
// total can be 0.
func (cpb *progressBar) TrackProgress(src string, currentSize, totalSize int64, stream io.ReadCloser) io.ReadCloser {
	cpb.lock.Lock()
	defer cpb.lock.Unlock()

	newPb := pb.New64(totalSize)
	newPb.SetCurrent(currentSize)
	progressBarConfig(newPb, filepath.Base(src))

	if cpb.pool == nil {
		cpb.pool = pb.NewPool()
		_ = cpb.pool.Start() //nolint:errcheck // Progress bar start failure not critical
	}

	cpb.pool.Add(newPb)
	reader := newPb.NewProxyReader(stream)

	cpb.pbs++

	return &readCloser{
		Reader: reader,
		close: func() error {
			cpb.lock.Lock()
			defer cpb.lock.Unlock()

			newPb.Finish()
			cpb.pbs--
			if cpb.pbs <= 0 {
				_ = cpb.pool.Stop() //nolint:errcheck // Progress bar stop failure not critical
				cpb.pool = nil
			}

			return nil
		},
	}
}

type readCloser struct {
	io.Reader
	close func() error
}

func (c *readCloser) Close() error { return c.close() }
