// Package migrations embeds the SQL files so the API binary can migrate its own database.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
