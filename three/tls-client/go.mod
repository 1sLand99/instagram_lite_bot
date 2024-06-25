module github.com/bogdanfinn/tls-client

go 1.20

replace (
	github.com/bogdanfinn/fhttp => ../fhttp
	github.com/bogdanfinn/utls => ../utls
)

require (
	github.com/bogdanfinn/fhttp v0.5.23
	github.com/bogdanfinn/utls v1.5.16
	github.com/google/uuid v1.3.0
	github.com/stretchr/testify v1.8.4
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5
	golang.org/x/net v0.14.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.12.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace github.com/bogdanfinn/utls => ../utls

// replace github.com/bogdanfinn/fhttp => ../fhttp
