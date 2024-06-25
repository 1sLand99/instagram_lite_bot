package gotools

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"math/rand"
	"strings"
	"time"

	http2 "github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
	regexp2 "github.com/dlclark/regexp2"
	fiber "github.com/gofiber/fiber/v2"
	gostruct "github.com/kawacode/gostruct"
)

// It takes a JA3 string and returns a tls.ClientHelloSpec
func ParseJA3(Ja3 string, Protocol string) (*tls.ClientHelloSpec, error) {
	var (
		tlsspec    tls.ClientHelloSpec
		tlsinfo    tls.ClientHelloInfo
		extensions string
	)
	for i, v := range strings.SplitN(Ja3, ",", 5) {
		switch i {
		case 0:
			_, err := fmt.Sscan(v, &tlsspec.TLSVersMax)
			if err != nil {
				return nil, err
			}
		case 1:
			tlsspec.CipherSuites = append(tlsspec.CipherSuites, tls.GREASE_PLACEHOLDER)
			for _, chiperkey := range strings.Split(v, "-") {
				var cipher uint16
				_, err := fmt.Sscan(chiperkey, &cipher)
				if err != nil {
					return nil, err
				}
				tlsspec.CipherSuites = append(tlsspec.CipherSuites, cipher)
			}
		case 2:
			extensions = v
		case 3:
			tlsinfo.SupportedCurves = append(tlsinfo.SupportedCurves, tls.GREASE_PLACEHOLDER)
			for _, curveid := range strings.Split(v, "-") {
				var curves tls.CurveID
				_, err := fmt.Sscan(curveid, &curves)
				if err != nil {
					return nil, err
				}
				tlsinfo.SupportedCurves = append(tlsinfo.SupportedCurves, curves)
			}
		case 4:
			for _, point := range strings.Split(v, "-") {
				var points uint8
				_, err := fmt.Sscan(point, &points)
				if err != nil {
					return nil, err
				}
				tlsinfo.SupportedPoints = append(tlsinfo.SupportedPoints, points)
			}
		}
	}
	tlsspec.Extensions = append(tlsspec.Extensions, &tls.UtlsGREASEExtension{})
	for _, extenionsvalue := range strings.Split(extensions, "-") {
		var tlsext tls.TLSExtension
		switch extenionsvalue {
		case "0":
			tlsext = &tls.SNIExtension{}
		case "5":
			tlsext = &tls.StatusRequestExtension{}
		case "10":
			tlsext = &tls.SupportedCurvesExtension{Curves: tlsinfo.SupportedCurves}
		case "11":
			tlsext = &tls.SupportedPointsExtension{SupportedPoints: tlsinfo.SupportedPoints}
		case "13":
			tlsext = &tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					1027,
					2052,
					1025,
					1283,
					2053,
					1281,
					2054,
					1537,
				},
			}
		case "16":
			if Protocol == "1" {
				tlsext = &tls.ALPNExtension{
					AlpnProtocols: []string{"http/1.1"},
				}
			} else {
				tlsext = &tls.ALPNExtension{
					AlpnProtocols: []string{"h2"},
				}
			}
		case "18":
			tlsext = &tls.SCTExtension{}
		case "21":
			tlsspec.Extensions = append(tlsspec.Extensions, &tls.UtlsGREASEExtension{})
			tlsext = &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}
		case "22":
			tlsext = &tls.GenericExtension{Id: 22}
		case "23":
			tlsext = &tls.UtlsExtendedMasterSecretExtension{}
		case "27":
			tlsext = &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli, tls.CertCompressionZlib}}
		case "28":
			tlsext = &tls.FakeRecordSizeLimitExtension{}
		case "34":
			tlsext = &tls.DelegatedCredentialsExtension{
				AlgorithmsSignature: []tls.SignatureScheme{
					1027,
					2052,
					1025,
					1283,
					2053,
					1281,
					2054,
					1537,
				},
			}
		case "35":
			tlsext = &tls.SessionTicketExtension{}
		case "43":
			tlsext = &tls.SupportedVersionsExtension{Versions: []uint16{tlsspec.TLSVersMax}}
		case "45":
			tlsext = &tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{tls.PskModeDHE},
			}
		case "49":
			tlsext = &tls.GenericExtension{Id: 49}
		case "50":
			tlsext = &tls.GenericExtension{Id: 50}
		case "51":
			tlsext = &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: 29, Data: []byte{32}},
				{Group: 23, Data: []byte{65}},
			}}
		case "13172":
			tlsext = &tls.NPNExtension{}
		case "17513":
			if Protocol == "1" {
				tlsext = &tls.ALPSExtension{SupportedProtocols: []string{"http/1.1"}}
			} else {
				tlsext = &tls.ALPSExtension{SupportedProtocols: []string{"h2"}}
			}
		case "30032":
			tlsext = &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}
		case "65281":
			tlsext = &tls.RenegotiationInfoExtension{
				Renegotiation: tls.RenegotiateOnceAsClient,
			}
		case "41":
			tlsext = &tls.PreSharedKeyExtension{}
		case "42":
			tlsext = &tls.GenericExtension{Id: tls.ExtensionEarlyData}
		case "44":
			tlsext = &tls.CookieExtension{}
		default:
			var id uint16
			_, err := fmt.Sscan(extenionsvalue, &id)
			if err != nil {
				return nil, err
			}
			tlsext = &tls.GenericExtension{Id: id}
		}
		tlsspec.Extensions = append(tlsspec.Extensions, tlsext)
	}
	tlsspec.TLSVersMin = tls.VersionTLS10
	return &tlsspec, nil
}
func ParseExtensions(extensions string, ogextensions []tls.TLSExtension) ([]tls.TLSExtension, error) {
	var Extensions []tls.TLSExtension
	for _, extenionsvalue := range strings.Split(extensions, "-") {
		var tlsext tls.TLSExtension
		switch extenionsvalue {
		case "0":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.SNIExtension); found {
					tlsext = ext
					break
				}
			}
		case "5":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.StatusRequestExtension); found {
					tlsext = ext
					break
				}
			}
		case "10":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.SupportedCurvesExtension); found {
					tlsext = ext
					break
				}
			}
		case "11":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.SupportedPointsExtension); found {
					tlsext = ext
					break
				}
			}
		case "13":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.SignatureAlgorithmsExtension); found {
					tlsext = ext
					break
				}
			}
		case "16":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.ALPNExtension); found {
					tlsext = ext
					break
				}
			}
		case "18":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.SCTExtension); found {
					tlsext = ext
					break
				}
			}
		case "21":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.UtlsPaddingExtension); found {
					tlsext = ext
					break
				}
			}
		case "22":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.GenericExtension); found {
					tlsext = ext
					break
				}
			}
		case "23":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.UtlsExtendedMasterSecretExtension); found {
					tlsext = ext
					break
				}
			}
		case "27":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.UtlsCompressCertExtension); found {
					tlsext = ext
					break
				}
			}
		case "28":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.FakeRecordSizeLimitExtension); found {
					tlsext = ext
					break
				}
			}
		case "34":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.DelegatedCredentialsExtension); found {
					tlsext = ext
					break
				}
			}
		case "35":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.SessionTicketExtension); found {
					tlsext = ext
					break
				}
			}
		case "43":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.SupportedVersionsExtension); found {
					tlsext = ext
					break
				}
			}
		case "45":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.PSKKeyExchangeModesExtension); found {
					tlsext = ext
					break
				}
			}
		case "49":
			tlsext = &tls.GenericExtension{Id: 49}
		case "50":
			tlsext = &tls.GenericExtension{Id: 50}
		case "51":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.KeyShareExtension); found {
					tlsext = ext
					break
				}
			}
		case "13172":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.NPNExtension); found {
					tlsext = ext
					break
				}
			}
		case "17513":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.ALPSExtension); found {
					tlsext = ext
					break
				}
			}
		case "30032":
			tlsext = &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}
		case "65281":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.RenegotiationInfoExtension); found {
					tlsext = ext
					break
				}
			}
		case "41":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.PreSharedKeyExtension); found {
					tlsext = ext
					break
				}
			}
		case "42":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.GenericExtension); found {
					tlsext = ext
					break
				}
			}
		case "44":
			for _, ext := range ogextensions {
				if ext, found := ext.(*tls.CookieExtension); found {
					tlsext = ext
					break
				}
			}
		default:
			var id uint16
			_, err := fmt.Sscan(extenionsvalue, &id)
			if err != nil {
				return nil, err
			}
			tlsext = &tls.GenericExtension{Id: id}
		}
		Extensions = append(Extensions, tlsext)
	}
	return Extensions, nil
}

// `GetHelloClient` is a function that takes a string as an argument and returns a pointer to a
func GetHelloClient(bot *gostruct.BotData, client string) *tls.ClientHelloID {
	switch strings.ToUpper(client) {
	case strings.ToUpper("HelloCustom"):
		return &tls.HelloCustom
	case strings.ToUpper("HelloChrome_58"), strings.ToUpper("HelloChrome_62"):
		return &tls.ClientHelloID{
			Client:  client,
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
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax:         tls.VersionTLS12,
						TLSVersMin:         tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax:         tls.VersionTLS12,
						TLSVersMin:         tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_70"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.SCTExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.FakeChannelIDExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin:         tls.VersionTLS10,
						TLSVersMax:         tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin:         tls.VersionTLS10,
						TLSVersMax:         tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_72"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {

				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
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
					},
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.SessionTicketExtension{},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
							tls.VersionTLS11,
							tls.VersionTLS10,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						}},
						&tls.UtlsGREASEExtension{},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					},
				}, nil
			},
		}
	case strings.ToUpper("HelloChrome_83"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_87"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_96"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2"}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_100"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPSExtension{SupportedProtocols: []string{"h2"}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_102"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_103"), strings.ToUpper("HelloChrome_104"), strings.ToUpper("HelloChrome_105"), strings.ToUpper("HelloChrome_106"), strings.ToUpper("HelloChrome_107"), strings.ToUpper("HelloChrome_108"), strings.ToUpper("HelloChrome_109"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPSExtension{SupportedProtocols: []string{"h2"}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloChrome_110"), strings.ToUpper("HelloChrome_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.ALPSExtension{SupportedProtocols: []string{"h2"}},
					&tls.SNIExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SessionTicketExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.StatusRequestExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       sha256.Sum256,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       sha256.Sum256,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloFirefox_55"), strings.ToUpper("HelloFirefox_56"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1},
					},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax:         tls.VersionTLS12,
						TLSVersMin:         tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       nil,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax:         tls.VersionTLS12,
						TLSVersMin:         tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       nil,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloFirefox_63"), strings.ToUpper("HelloFirefox_65"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.CurveID(tls.FakeFFDHE2048),
						tls.CurveID(tls.FakeFFDHE3072),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       nil,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       nil,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloFirefox_99"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},                      //server_name
					&tls.UtlsExtendedMasterSecretExtension{}, //extended_master_secret
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, //extensionRenegotiationInfo
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{ //supported_groups
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.CurveID(tls.FakeFFDHE2048),
						tls.CurveID(tls.FakeFFDHE3072),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{ //ec_point_formats
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, //application_layer_protocol_negotiation
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						AlgorithmsSignature: []tls.SignatureScheme{ //signature_algorithms
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256}, //key_share
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13, //supported_versions
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{ //signature_algorithms
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{ //psk_key_exchange_modes
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},                 //record_size_limit
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}, //padding
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       nil,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       nil,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloFirefox_102"), strings.ToUpper("HelloFirefox_104"), strings.ToUpper("HelloFirefox_105"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.CurveID(tls.FakeFFDHE2048),
						tls.CurveID(tls.FakeFFDHE3072),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						AlgorithmsSignature: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
						GetSessionID:       nil,
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
						GetSessionID:       nil,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloFirefox_106"), strings.ToUpper("HelloFirefox_108"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.CurveID(tls.FakeFFDHE2048),
						tls.CurveID(tls.FakeFFDHE3072),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						AlgorithmsSignature: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloFirefox_110"), strings.ToUpper("HelloFirefox_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.CurveID(tls.FakeFFDHE2048),
						tls.CurveID(tls.FakeFFDHE3072),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						AlgorithmsSignature: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						tls.ECDSAWithSHA1,
						tls.PKCS1WithSHA1,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloAndroid_11_OkHttp"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					0xcca9, // Cipher Suite: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					0xcca8, // Cipher Suite: tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{},
					// supported_groups
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloIOS_11_1"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.NPNExtension{},
					&tls.SCTExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloIOS_12_1"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					0xc008,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithSHA1,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.NPNExtension{},
					&tls.SCTExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloIOS_13"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					0xc008,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithSHA1,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.SCTExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloIOS_14"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					0xc008,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithSHA1,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloIOS_15_5"), strings.ToUpper("HelloIOS_15_6"), strings.ToUpper("HelloIOS_16_0"), strings.ToUpper("HelloIOS_Auto"), strings.ToUpper("HelloIPad_15_6"), strings.ToUpper("HelloIPad_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithSHA1,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloSafari_15_6_1"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithSHA1,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []byte{tls.CompressionNone},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{tls.CompressionNone},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloSafari_16_0"), strings.ToUpper("HelloSafari_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
						},
					},
					&tls.SupportedPointsExtension{
						SupportedPoints: []uint8{
							0x0, // uncompressed
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h2",
							"http/1.1",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithSHA1,
							tls.PSSWithSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.GREASE_PLACEHOLDER,
								Data: []byte{
									0,
								},
							},
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
							tls.VersionTLS11,
							tls.VersionTLS10,
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						},
					},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloGolang"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{}, nil
			},
		}
	case strings.ToUpper("HelloOpera_89"), strings.ToUpper("HelloOpera_90"), strings.ToUpper("HelloOpera_91"), strings.ToUpper("HelloOpera_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, // ExtensionRenegotiationInfo (boringssl) (65281)
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						0x00, // tls.PointFormatUncompressed
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPSExtension{SupportedProtocols: []string{"h2"}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []uint8{
							0x00,
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloEdge_85"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers :=  []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						},
					},
					&tls.SupportedPointsExtension{
						SupportedPoints: []uint8{
							0x0, // tls.PointFormatUncompressed
						},
					},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h2",
							"http/1.1",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
						},
					},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.GREASE_PLACEHOLDER,
								Data: []byte{
									0,
								},
							},
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
							tls.VersionTLS11,
							tls.VersionTLS10,
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMax: tls.VersionTLS12,
						TLSVersMin: tls.VersionTLS10,
						CipherSuites:       ciphers,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloEdge_106"), strings.ToUpper("HelloEdge_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						},
					},
					&tls.SupportedPointsExtension{
						SupportedPoints: []uint8{
							0x0, // uncompressed
						},
					},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h2",
							"http/1.1",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
						},
					},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.GREASE_PLACEHOLDER,
								Data: []byte{
									0,
								},
							},
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{
							"h2",
						},
					},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS12,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS12,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("Hello360_7_5"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
					tls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_RC4_128_SHA,
					tls.FAKE_TLS_RSA_WITH_RC4_128_MD5,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
						},
					},
					&tls.SupportedPointsExtension{
						SupportedPoints: []uint8{
							0x0, // tls.PointFormatUncompressed
						},
					},
					&tls.SessionTicketExtension{},
					&tls.NPNExtension{},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"spdy/2",
							"spdy/3",
							"spdy/3.1",
							"http/1.1",
						},
					},
					&tls.FakeChannelIDExtension{
						OldExtensionID: true,
					},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA1,
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithSHA1,
							tls.FakeSHA256WithDSA,
							tls.FakeSHA1WithDSA,
						},
					},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						CipherSuites:       ciphers,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("Hello360_11_0"), strings.ToUpper("Hello360_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						},
					},
					&tls.SupportedPointsExtension{
						SupportedPoints: []uint8{
							0x0, // uncompressed
						},
					},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h2",
							"http/1.1",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.SCTExtension{},
					&tls.FakeChannelIDExtension{
						OldExtensionID: false,
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.GREASE_PLACEHOLDER,
								Data: []byte{
									0,
								},
							},
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
							tls.VersionTLS11,
							tls.VersionTLS10,
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloQQ_11_1"), strings.ToUpper("HelloQQ_Auto"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
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
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						},
					},
					&tls.SupportedPointsExtension{
						SupportedPoints: []uint8{
							0x0, // uncompressed
						},
					},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h2",
							"http/1.1",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
						},
					},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.GREASE_PLACEHOLDER,
								Data: []byte{
									0,
								},
							},
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
							tls.VersionTLS11,
							tls.VersionTLS10,
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{
							"h2",
						},
					},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("HelloRandomizedALPN"):
		return &tls.ClientHelloID{
			Client:  tls.HelloRandomizedALPN.Client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{}, nil
			},
		}
	case strings.ToUpper("HelloRandomizedNoALPN"):
		return &tls.ClientHelloID{
			Client:  tls.HelloRandomizedNoALPN.Client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{}, nil
			},
		}
	case strings.ToUpper("ZalandoAndroidCustom"):
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{
							tls.CompressionNone,
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("ZalandoIosCustom"):
		return &tls.ClientHelloID{
			Client:  "ZalandoIosCustom",
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers := []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithSHA1,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{
							tls.CompressionNone,
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("NikeIosCustom"):
		return &tls.ClientHelloID{
			Client:  "NikeIosCustom",
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers :=[]uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithSHA1,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{
							tls.CompressionNone,
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("NikeAndroidCustom"):
		return &tls.ClientHelloID{
			Client:  "NikeAndroidCustom",
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers :=[]uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{
							tls.CompressionNone,
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("CloudflareCustom"):
		return &tls.ClientHelloID{
			Client:  "CloudflareCustom",
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers :=[]uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
						1, // ansiX962_compressed_prime
						2, // ansiX962_compressed_char2
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(0x0017),
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
					&tls.GenericExtension{Id: 22}, // encrypt_then_mac
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						0x0807,
						0x0808,
						0x0809,
						0x080a,
						0x080b,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						0x0303,
						0x0203,
						0x0301,
						0x0201,
						0x0302,
						0x0202,
						0x0402,
						0x0502,
						0x0602,
					}},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{
							tls.CompressionNone,
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("MMSIOS"):
		return &tls.ClientHelloID{
			Client:  "MMSIOS",
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				ciphers :=[]uint16{
					0x1303,
					0x1301,
					0x1302,
					0xcca9,
					0xcca8,
					0xc02b,
					0xc02f,
					0xc02c,
					0xc030,
					0xc009,
					0xc013,
					0xc00a,
					0xc014,
					0x009c,
					0x009d,
					0x002f,
					0x0035,
					0x000a,
				}
				ogext := []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.UtlsExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(0x001d),
						tls.CurveID(0x0017),
						tls.CurveID(0x0018),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						0x0403,
						0x0804,
						0x0401,
						0x0503,
						0x0805,
						0x0501,
						0x0806,
						0x0601,
						0x0201,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
				}
				var clienthellospec tls.ClientHelloSpec
				if bot.HttpRequest.Request.ClientProfile.Tlsextension != "" {
					extensions, err := ParseExtensions(bot.HttpRequest.Request.ClientProfile.Tlsextension, ogext)
					if err != nil {
						return tls.ClientHelloSpec{}, err
					}
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						Extensions:         extensions,
						CompressionMethods: []uint8{
							0x0, // no compression
						},
					}
				} else {
					clienthellospec = tls.ClientHelloSpec{
						TLSVersMin: tls.VersionTLS10,
						TLSVersMax: tls.VersionTLS13,
						CipherSuites:       ciphers,
						CompressionMethods: []byte{
							tls.CompressionNone,
						},
						Extensions:         ogext,
					}
				}
				return clienthellospec, nil
			},
		}
	case strings.ToUpper("MeshIOS"):
		return &tls.ClientHelloID{
			Client:  "MeshIOS",
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						0x1301,
						0x1302,
						0x1303,
						0xc02c,
						0xc02b,
						0xcca9,
						0xc030,
						0xc02f,
						0xcca8,
						0xc00a,
						0xc009,
						0xc014,
						0xc013,
					},
					CompressionMethods: []uint8{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							tls.CurveID(0x001d),
							tls.CurveID(0x0017),
							tls.CurveID(0x0018),
							tls.CurveID(0x0019),
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []uint8{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							0x0403,
							0x0804,
							0x0401,
							0x0503,
							0x0203,
							0x0805,
							0x0805,
							0x0501,
							0x0806,
							0x0601,
							0x0201,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						}},
						&tls.UtlsGREASEExtension{},
						&tls.UtlsPaddingExtension{},
					},
				}, nil
			},
		}
	default:
		return &tls.ClientHelloID{
			Client:  client,
			Version: "1",
			Seed:    nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
					CompressionMethods: []uint8{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.UtlsExtendedMasterSecretExtension{},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519},
						}},
						&tls.ALPSExtension{SupportedProtocols: []string{"h2"}},
						&tls.SNIExtension{},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.SessionTicketExtension{},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.StatusRequestExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						}},
						&tls.UtlsGREASEExtension{},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					},
				}, nil
			},
		}
	};
	
}

// Convert a map of string slices to a map of strings.
func MapStringSliceToMapString(bot *gostruct.BotData, headers map[string][]string) map[string]string {
	var result = make(map[string]string)
	var hasEncodingContent = false
	for key, value := range headers {
		for _, value := range value {
			if bot.HttpRequest.Request.GzipCompression {
				result[key] = value
				if strings.Contains(key, "Content-Encoding") {
					hasEncodingContent = true
				}
			} else {
				hasEncodingContent = true
				if !strings.Contains(key, "Content-Encoding") {
					result[key] = value
				}
			}
		}
	}
	if !hasEncodingContent {
		result["Content-Encoding"] = "gzip"
	}
	return result
}

// It checks if the header exists in the request and if it does, it checks if the value is empty. If
// the value is empty, it returns false. If the value is not empty, it returns true
func HasHeaderValue(headerkey string, request *fiber.Ctx) bool {
	hasHeaderValue := true
	for key, value := range request.GetReqHeaders() {
		emptyregex := regexp2.MustCompile(`^\s*$`, 0)
		header := strings.ReplaceAll(headerkey, " ", "")
		headerregex := regexp2.MustCompile(`(?i)\b`+header+`\b`, 0)
		if isMatch, _ := headerregex.MatchString(key); isMatch {
			if isEmpty, _ := emptyregex.MatchString(value); isEmpty {
				hasHeaderValue = false
			}
		}
	}
	return hasHeaderValue
}

// It takes a map of strings and returns a map of strings with removed kawacode headers
func RemoveKawaCodeHeaders(headers map[string]string, bot *gostruct.BotData) map[string]string {
	returnheaders := make(map[string]string)
	hostregex := regexp2.MustCompile(`(?i)(?<!-|\S)(?!X-)(host)(?!\S)`, 0)
	xkcregex := regexp2.MustCompile(`^(?i)x-kc-\w+$`, 0)
	for k, v := range headers {
		if isMatch, _ := hostregex.MatchString(k); isMatch {
			returnheaders[k] = strings.Split(bot.HttpRequest.Request.URL, "/")[2]
		} else if isMatch, _ := xkcregex.MatchString(k); !isMatch {
			returnheaders[k] = v
		}
	}
	return returnheaders
}

// > Converts a map of strings to a map of string slices
func MapStringToMapStringSlice(MapString map[string]string, bot *gostruct.BotData) map[string][]string {
	var result = make(map[string][]string)
	contentlengtregex := regexp2.MustCompile(`(?i)(?<!-|\S)(?!X-)(content-length)(?!\S)`, 0)
	connectionregex := regexp2.MustCompile(`(?i)(?<!-|\S)(?!X-)(connection)(?!\S)`, 0)
	for key, value := range MapString {
		if isMatch, _ := contentlengtregex.MatchString(key); isMatch {
		} else if isMatch, _ := connectionregex.MatchString(key); isMatch {
			keepaliveregex := regexp2.MustCompile(`(?i)(?<!-|\S)(?!X-)(keep-alive)(?!\S)`, 0)
			if isMatch, _ := keepaliveregex.MatchString(value); isMatch {
				bot.HttpRequest.Request.DisableKeepAlive = false
				result[key] = []string{value}
			} else {
				bot.HttpRequest.Request.DisableKeepAlive = true
				result[key] = []string{value}
			}
		} else {
			result[key] = []string{value}
		}
	}
	if len(bot.HttpRequest.Request.HeaderOrderKey) > 1 {
		var HeaderOrderKey []string
		for _, v := range bot.HttpRequest.Request.HeaderOrderKey {
			HeaderOrderKey = append(HeaderOrderKey, strings.ReplaceAll(v, " ", ""))
		}
		result["Header-Order:"] = HeaderOrderKey
	}
	if len(bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder) > 1 {
		var PHeaderOrderKey []string
		for _, v := range bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder {
			PHeaderOrderKey = append(PHeaderOrderKey, strings.ReplaceAll(v, " ", ""))
		}
		result["PHeader-Order:"] = PHeaderOrderKey
	} else {
		result["PHeader-Order:"] = []string{
			":method",
			":authority",
			":scheme",
			":path",
		}
	}
	return result
}

// It takes two integers, min and max, and returns a random integer between min and max
func RandomInt(min int, max int) int {
	rand.NewSource(time.Now().UnixNano())
	return (min + rand.Intn(max-min))
}

// It takes a string, converts it to a byte array, creates a new gzip reader, reads the gzip reader,
// and returns the result as a string
func DecompressGzip(Gzip string) (string, error) {
	res, err := gzip.NewReader(bytes.NewReader([]byte(Gzip)))
	if err != nil {
		return Gzip, nil
	}
	defer res.Close()
	read, err := io.ReadAll(res)
	if err != nil {
		return "", err
	}
	return string(read), nil
}

// It creates a new gzip writer, writes the string to it, flushes it, closes it, and returns the bytes
func CompressGzip(s string) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(s)); err != nil {
		return nil, err
	}
	if err := gz.Flush(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// It returns true if the string is made up of digits, false otherwise
func IsInt(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// It takes a Go request and sets the Fiber request to match it
func SetGoRequestToFiber(request *fiber.Ctx, bot *gostruct.BotData) {
	request.SendStatus(bot.HttpRequest.Response.StatusCode)
	request.SendString(bot.HttpRequest.Response.Source)
	for k, v := range bot.HttpRequest.Response.Cookies {
		cookie := new(fiber.Cookie)
		cookie.Name = k
		cookie.Value = v
		cookie.Expires = time.Now().Add(time.Duration(24 * time.Hour))
		request.Cookie(cookie)
	}
	for k, v := range bot.HttpRequest.Response.Headers {
		if !strings.Contains(strings.ToLower(strings.ReplaceAll(k, " ", "")), "set-cookie") {
			request.Set(k, v)
		}
	}
}

func SetUpProfile(bot *gostruct.BotData) {
	type ClientProfile struct {
		Client            tls.ClientHelloID          `json:"clientid"`
		ClientString      string                     `json:"client"`
		Settings          map[http2.SettingID]uint32 `json:"settings"`
		SettingsOrder     []http2.SettingID          `json:"settingsorder"`
		PseudoHeaderOrder []string                   `json:"pseudoheaderorder"`
		ConnectionFlow    uint32                     `json:"connectionflow"`
		Priorities        []http2.Priority           `json:"priorities"`
		HeaderPriority    *http2.PriorityParam       `json:"headerpriority"`
	}
	var Chrome_110 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_110"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_109 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_109"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_108 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_108"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_107 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_107"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_106 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_106"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_105 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_105"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_104 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_104"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Chrome_103 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloChrome_103"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Safari_15_6_1 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloSafari_15_6_1"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    4194304,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_16_0 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloSafari_16_0"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    4194304,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_Ipad_15_6 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloIPad_15_6"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_IOS_16_0 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloIOS_16_0"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_IOS_15_5 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloIOS_15_5"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Safari_IOS_15_6 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloIOS_15_6"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 10485760,
	}

	var Firefox_110 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloFirefox_110"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_108 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloFirefox_108"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_106 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloFirefox_106"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_105 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloFirefox_105"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_104 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloFirefox_104"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Firefox_102 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloFirefox_102"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 12517377,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41,
		},
		Priorities: []http2.Priority{
			{StreamID: 3, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    200,
			}},
			{StreamID: 5, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    100,
			}},
			{StreamID: 7, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 9, PriorityParam: http2.PriorityParam{
				StreamDep: 7,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 11, PriorityParam: http2.PriorityParam{
				StreamDep: 3,
				Exclusive: false,
				Weight:    0,
			}},
			{StreamID: 13, PriorityParam: http2.PriorityParam{
				StreamDep: 0,
				Exclusive: false,
				Weight:    240,
			}},
		},
	}

	var Opera_90 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloOpera_90"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Opera_91 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloOpera_91"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}

	var Opera_89 = ClientProfile{
		Client: *GetHelloClient(bot, "HelloOpera_89"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		ConnectionFlow: 15663105,
	}
	var ZalandoAndroidMobile = ClientProfile{
		Client: *GetHelloClient(bot, "ZalandoAndroidCustom"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: math.MaxUint32,
			http2.SettingInitialWindowSize:    16777216,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}

	var ZalandoIosMobile = ClientProfile{
		Client: *GetHelloClient(bot, "ZalandoIosCustom"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}

	var NikeIosMobile = ClientProfile{
		Client: *GetHelloClient(bot, "NikeIosCustom"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 15663105,
	}

	var NikeAndroidMobile = ClientProfile{
		Client: *GetHelloClient(bot, "NikeAndroidCustom"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: math.MaxUint32,
			http2.SettingInitialWindowSize:    16777216,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}

	var CloudflareCustom = ClientProfile{
		Client: *GetHelloClient(bot, "CloudflareCustom"),

		//actually the h2 settings are not relevant, because this client does only support http1
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingMaxConcurrentStreams: math.MaxUint32,
			http2.SettingInitialWindowSize:    16777216,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		ConnectionFlow: 15663105,
	}

	var MMSIos = ClientProfile{
		Client: *GetHelloClient(bot, "MMSIOS"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingEnablePush:           1,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 15663105,
	}

	var MeshIos = ClientProfile{
		Client: *GetHelloClient(bot, "MeshIOS"),
		Settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      4096,
			http2.SettingEnablePush:           1,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    math.MaxUint32,
		},
		SettingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		ConnectionFlow: 15663105,
	}
	var TLSClients = map[string]ClientProfile{
		tls.HelloChrome_103.Str():    Chrome_103,
		tls.HelloChrome_104.Str():    Chrome_104,
		tls.HelloChrome_105.Str():    Chrome_105,
		tls.HelloChrome_106.Str():    Chrome_106,
		tls.HelloChrome_107.Str():    Chrome_107,
		tls.HelloChrome_108.Str():    Chrome_108,
		tls.HelloChrome_109.Str():    Chrome_109,
		tls.HelloChrome_110.Str():    Chrome_110,
		tls.HelloSafari_15_6_1.Str(): Safari_15_6_1,
		tls.HelloSafari_16_0.Str():   Safari_16_0,
		tls.HelloIPad_15_6.Str():     Safari_Ipad_15_6,
		tls.HelloIOS_15_5.Str():      Safari_IOS_15_5,
		tls.HelloIOS_15_6.Str():      Safari_IOS_15_6,
		tls.HelloIOS_16_0.Str():      Safari_IOS_16_0,
		tls.HelloFirefox_102.Str():   Firefox_102,
		tls.HelloFirefox_104.Str():   Firefox_104,
		tls.HelloFirefox_105.Str():   Firefox_105,
		tls.HelloFirefox_106.Str():   Firefox_106,
		tls.HelloFirefox_108.Str():   Firefox_108,
		tls.HelloFirefox_110.Str():   Firefox_110,
		tls.HelloOpera_89.Str():      Opera_89,
		tls.HelloOpera_90.Str():      Opera_90,
		tls.HelloOpera_91.Str():      Opera_91,
		"HelloZalandoAndrodMobile":   ZalandoAndroidMobile,
		"HelloZalandoIosMobile":      ZalandoIosMobile,
		"HelloNikeIosMobile":         NikeIosMobile,
		"HelloNikeAndroidMobile":     NikeAndroidMobile,
		"HelloCloudflareCustom":      CloudflareCustom,
		"HelloMMSIOS":                MMSIos,
		"HelloMESHIOS":               MeshIos,
	}
	tlsclient := *GetHelloClient(bot, bot.HttpRequest.Request.ClientProfile.ClientString)
	if bot.HttpRequest.Request.ClientProfile.H2profile != "" {
		if profile, exist := TLSClients[bot.HttpRequest.Request.ClientProfile.H2profile]; exist {
			bot.HttpRequest.Request.ClientProfile.Client = profile.Client
			if bot.HttpRequest.Request.ClientProfile.Settings == nil {
				bot.HttpRequest.Request.ClientProfile.Settings = profile.Settings
			}
			if bot.HttpRequest.Request.ClientProfile.SettingsOrder == nil {
				bot.HttpRequest.Request.ClientProfile.SettingsOrder = profile.SettingsOrder
			}
			if bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder == nil {
				bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder = profile.PseudoHeaderOrder
			}
			if bot.HttpRequest.Request.ClientProfile.ConnectionFlow == 0 {
				bot.HttpRequest.Request.ClientProfile.ConnectionFlow = profile.ConnectionFlow
			}
			if bot.HttpRequest.Request.ClientProfile.Priorities != nil {
				bot.HttpRequest.Request.ClientProfile.Priorities = profile.Priorities
			}
			if bot.HttpRequest.Request.ClientProfile.HeaderPriority != nil {
				bot.HttpRequest.Request.ClientProfile.HeaderPriority = profile.HeaderPriority
			}
		} else {
			if bot.HttpRequest.Request.ClientProfile.ClientString == "" {
				bot.HttpRequest.Request.ClientProfile.Client = Chrome_110.Client
			} else {
				bot.HttpRequest.Request.ClientProfile.Client = *GetHelloClient(bot, bot.HttpRequest.Request.ClientProfile.ClientString)
			}
			if bot.HttpRequest.Request.ClientProfile.Settings == nil {
				bot.HttpRequest.Request.ClientProfile.Settings = Chrome_110.Settings
			}
			if bot.HttpRequest.Request.ClientProfile.SettingsOrder == nil {
				bot.HttpRequest.Request.ClientProfile.SettingsOrder = Chrome_110.SettingsOrder
			}
			if bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder == nil {
				bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder = Chrome_110.PseudoHeaderOrder
			}
			if bot.HttpRequest.Request.ClientProfile.ConnectionFlow == 0 {
				bot.HttpRequest.Request.ClientProfile.ConnectionFlow = Chrome_110.ConnectionFlow
			}
			if bot.HttpRequest.Request.ClientProfile.Priorities == nil {
				bot.HttpRequest.Request.ClientProfile.Priorities = Chrome_110.Priorities
			}
			if bot.HttpRequest.Request.ClientProfile.HeaderPriority == nil {
				bot.HttpRequest.Request.ClientProfile.HeaderPriority = Chrome_110.HeaderPriority
			}
		}
	} else {
		if profile, exist := TLSClients[tlsclient.Str()]; exist {
			bot.HttpRequest.Request.ClientProfile.Client = profile.Client
			if bot.HttpRequest.Request.ClientProfile.Settings == nil {
				bot.HttpRequest.Request.ClientProfile.Settings = profile.Settings
			}
			if bot.HttpRequest.Request.ClientProfile.SettingsOrder == nil {
				bot.HttpRequest.Request.ClientProfile.SettingsOrder = profile.SettingsOrder
			}
			if bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder == nil {
				bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder = profile.PseudoHeaderOrder
			}
			if bot.HttpRequest.Request.ClientProfile.ConnectionFlow == 0 {
				bot.HttpRequest.Request.ClientProfile.ConnectionFlow = profile.ConnectionFlow
			}
			if bot.HttpRequest.Request.ClientProfile.Priorities != nil {
				bot.HttpRequest.Request.ClientProfile.Priorities = profile.Priorities
			}
			if bot.HttpRequest.Request.ClientProfile.HeaderPriority != nil {
				bot.HttpRequest.Request.ClientProfile.HeaderPriority = profile.HeaderPriority
			}
		} else {
			if bot.HttpRequest.Request.ClientProfile.ClientString == "" {
				bot.HttpRequest.Request.ClientProfile.Client = Chrome_110.Client
			} else {
				bot.HttpRequest.Request.ClientProfile.Client = *GetHelloClient(bot, bot.HttpRequest.Request.ClientProfile.ClientString)
			}
			if bot.HttpRequest.Request.ClientProfile.Settings == nil {
				bot.HttpRequest.Request.ClientProfile.Settings = Chrome_110.Settings
			}
			if bot.HttpRequest.Request.ClientProfile.SettingsOrder == nil {
				bot.HttpRequest.Request.ClientProfile.SettingsOrder = Chrome_110.SettingsOrder
			}
			if bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder == nil {
				bot.HttpRequest.Request.ClientProfile.PseudoHeaderOrder = Chrome_110.PseudoHeaderOrder
			}
			if bot.HttpRequest.Request.ClientProfile.ConnectionFlow == 0 {
				bot.HttpRequest.Request.ClientProfile.ConnectionFlow = Chrome_110.ConnectionFlow
			}
			if bot.HttpRequest.Request.ClientProfile.Priorities == nil {
				bot.HttpRequest.Request.ClientProfile.Priorities = Chrome_110.Priorities
			}
			if bot.HttpRequest.Request.ClientProfile.HeaderPriority == nil {
				bot.HttpRequest.Request.ClientProfile.HeaderPriority = Chrome_110.HeaderPriority
			}
		}
	}
}
