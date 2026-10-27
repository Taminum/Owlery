package store_test

import (
	"os"
	"testing"

	"github.com/Taminum/Owlery/internal/store"
)

// The tests change data between two identical questions, so the analytics answers are not kept.
func TestMain(m *testing.M) {
	store.SetAnalyticsCacheTTL(0)
	os.Exit(m.Run())
}
