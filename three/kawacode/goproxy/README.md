# Goproxy
This Library helps you to create a proxy dialer and use it, I made this proxy library because i could not find any library that supports all proxy types that are common. (http/s, socks4, socks5, socks4a)

# 🚀 Supported types

```markdown
- SOCKS4
- SOCKS4a
- HTTP/s
- SOCKS5
```
# ⬇️ How to install it?
```
go get github.com/kawacode/goproxy
```
# 🪧 How to use it?
### Simple HTTP Request using the proxy dialer
```go
package main

import (
	"github.com/kawacode/goproxy"
)
func main() {
	RegisterProxyDialers() // Register the types
	proxy := "type://example.com:port:username:password"
	client := &fhttp.Client{
		Transport: &fhttp2.Transport{
			DialTLS: func(network, addr string, cfg *utls.Config) (net.Conn, error) {
				dialer, err := CreateProxyDialer(proxy) // Create the proxy dealer from Goproxy
				if err != nil {
					panic(err)
				}
				conn, err := dialer.Dial(network, addr)
				if err != nil {
					panic(err)
				}
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				config := &tls.Config{ServerName: host}
				uconn := tls.UClient(conn, config, tls.HelloChrome_Auto)
				return uconn, nil
			},
		},
	}
	req, err := fhttp.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		panic(err)
	}
	req.Header = map[string][]string{
		"Accept-Encoding": {"gzip, deflate"},
		"Accept-Language": {"en-us"},
		"User-Agent":      {"Mozilla/Golang"},
		"PHeader-Order:": {
			":method",
			":authority",
			":scheme",
			":path",
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	client.CloseIdleConnections()
	log.Println(string(response))
}


```
## LICENSE
### GPL3 LICENSE SYNOPSIS

**_TL;DR_*** Here's what the GPL3 license entails:

```markdown
1. Anyone can copy, modify and distribute this software.
2. You have to include the license and copyright notice with each and every distribution.
3. You can use this software privately.
4. You can use this software for commercial purposes.
5. Source code MUST be made available when the software is distributed.
6. Any modifications of this code base MUST be distributed with the same license, GPLv3.
7. This software is provided without warranty.
8. The software author or license can not be held liable for any damages inflicted by the software.
```

More information on about the [LICENSE can be found here](http://choosealicense.com/licenses/gpl-3.0/)
