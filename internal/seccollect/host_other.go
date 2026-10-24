//go:build !linux

package seccollect

import "errors"

func diskUsage(string) (int64, int64, error) { return 0, 0, errors.New("not supported on this system") }
