//go:build !windows

package adminops

import (
	"context"
	"encoding/json"
)

func run(context.Context, string, json.RawMessage) (any, error) { return nil, ErrUnsupported }
