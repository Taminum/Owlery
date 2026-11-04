//go:build !linux && !windows

package seccollect

import (
	"context"

	"github.com/Taminum/Owlery/internal/secproto"
)

func readHardware(context.Context, Runner) (secproto.Hardware, error) {
	return secproto.Hardware{}, errHardwareUnsupported
}
