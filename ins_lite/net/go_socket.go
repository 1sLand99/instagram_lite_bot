// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package net

import (
	"CentralizedControl/common/proxys"
	"crypto/tls"
	"net"
)

func CreateGoTls(host, port string, p proxys.Proxy) (net.Conn, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	var conn net.Conn
	var err error
	if p != nil {
		conn, err = p.GetDialer().Dial("tcp", host+":"+port)
	} else {
		conn, err = net.Dial("tcp", host+":"+port)
	}
	if err != nil {
		return nil, err
	}
	return tls.Client(conn, config), err
}
