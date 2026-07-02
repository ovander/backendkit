module github.com/ovander/backendkit

go 1.25.0

// Build/release with a patched toolchain to pick up Go standard-library security
// fixes (govulncheck GO-2026-4599…GO-2026-5039). The go directive above stays at
// 1.25.0 so the module remains importable by consumers on Go 1.25; this toolchain
// directive only governs builds where backendkit is the main module.
toolchain go1.26.4

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/uuid v1.6.0
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/sync v0.21.0
	golang.org/x/time v0.15.0
	gorm.io/gorm v1.25.11
)

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)
