module github.com/ovander/backendkit

go 1.25.0

// Build/release with a patched toolchain to pick up Go standard-library security
// fixes (govulncheck GO-2026-4599…GO-2026-5039). The go directive above stays at
// 1.25.0 so the module remains importable by consumers on Go 1.25; this toolchain
// directive only governs builds where backendkit is the main module.
toolchain go1.26.6

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_golang v1.24.1
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/sync v0.22.0
	golang.org/x/time v0.15.0
	gorm.io/gorm v1.25.11
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
