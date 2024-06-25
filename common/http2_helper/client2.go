// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package http2_helper

import (
	"CentralizedControl/common/proxys"
	"crypto/sha256"
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
	"net"
	"time"
)

type HttpConfigFun func(c *http.Client)

var DefaultPseudoHeaderOrder = []string{
	":method",
	":authority",
	":scheme",
	":path",
}
var DefaultFacebookClientHelloID = &tls.ClientHelloID{
	Client:  "fb",
	Version: "1",
	Seed:    nil,
	SpecFactory: func() (tls.ClientHelloSpec, error) {
		ciphers := []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
		ogext := []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.SessionTicketExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1},
			},
			&tls.StatusRequestExtension{},
			&tls.SCTExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.FakeChannelIDExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.CurveID(tls.GREASE_PLACEHOLDER),
				tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		}
		var clienthellospec = tls.ClientHelloSpec{
			TLSVersMax:         tls.VersionTLS12,
			TLSVersMin:         tls.VersionTLS10,
			CipherSuites:       ciphers,
			CompressionMethods: []byte{tls.CompressionNone},
			Extensions:         ogext,
			GetSessionID:       sha256.Sum256,
		}
		return clienthellospec, nil
	},
}

func HttpPseudoHeaderOrder(header []string) HttpConfigFun {
	return func(c *http.Client) {
		tr := c.Transport.(*http2.Transport)
		tr.PseudoHeaderOrder = header
	}
}

func DisableHttpSslPinng() HttpConfigFun {
	return func(c *http.Client) {
		tr := c.Transport.(*http2.Transport)
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
}

func DisableRedirect() HttpConfigFun {
	return func(c *http.Client) {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
}

func HttpTimeout(sec int) HttpConfigFun {
	return func(c *http.Client) {
		c.Timeout = time.Duration(sec) * time.Second
	}
}

func HttpSetProxy(proxy proxys.Proxy) HttpConfigFun {
	return func(c *http.Client) {
		tr := c.Transport.(*http2.Transport)
		tr.DialTLS = func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			var err error
			var conn net.Conn
			conn, err = proxy.GetDialer().Dial(network, addr)
			if err != nil {
				return nil, err
			}
			var uconn *tls.UConn
			uconn = tls.UClient(conn, cfg, *DefaultFacebookClientHelloID, false, false)
			if err := uconn.Handshake(); err != nil {
				return nil, err
			}
			return uconn, nil
		}
	}
}

func CreateHttp2Client(httpConfigs ...HttpConfigFun) *http.Client {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{},
	}

	httpClient := &http.Client{
		Transport: tr,
	}

	for _, config := range httpConfigs {
		config(httpClient)
	}
	if tr.PseudoHeaderOrder == nil || len(tr.PseudoHeaderOrder) <= 0 {
		tr.PseudoHeaderOrder = DefaultPseudoHeaderOrder
	}

	return httpClient
}
