//go:build !windows

package seccollect

func (h *HostReader) pulseOS() pulseRaw { return h.pulseProcfs() }
