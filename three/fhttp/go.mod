module github.com/bogdanfinn/fhttp

go 1.18

replace (
	github.com/bogdanfinn/fhttp => ../fhttp
	github.com/bogdanfinn/tls-client => ../tls-client
	github.com/bogdanfinn/utls => ../utls
)

require (
	github.com/andybalholm/brotli v1.0.5
	github.com/bogdanfinn/utls v1.5.16
	golang.org/x/net v0.10.0
	golang.org/x/term v0.11.0
)

require (
	github.com/klauspost/compress v1.16.7 // indirect
	golang.org/x/crypto v0.12.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
)

// replace github.com/bogdanfinn/utls => ../utls
