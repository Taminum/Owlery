//go:build !linux

package awgsensor

import (
	"errors"
	"time"
)

var errUnsupported = errors.New("awgsensor: packet capture needs Linux")

func OpenCapture(int, string) (int, error) { return -1, errUnsupported }
func DropPrivileges() error                { return errUnsupported }
func Read(int, *Aggregator, time.Duration, func(time.Time, time.Time, []Flow, uint64), <-chan struct{}) error {
	return errUnsupported
}
