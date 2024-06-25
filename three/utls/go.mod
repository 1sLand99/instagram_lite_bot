module github.com/bogdanfinn/utls

go 1.20

replace (
	github.com/bogdanfinn/fhttp => ../fhttp
	github.com/bogdanfinn/tls-client => ../tls-client
)

require (
	github.com/andybalholm/brotli v1.0.5
	github.com/klauspost/compress v1.16.7
	golang.org/x/crypto v0.12.0
)

require golang.org/x/sys v0.11.0 // indirect
