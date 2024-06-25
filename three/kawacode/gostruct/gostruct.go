package gostruct

import (
	"net/url"

	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

// Creating a new type called `BotData` that is a struct.
type BotData struct {
	// A struct that is used to store the data that is sent to the bot.
	HttpRequest struct {
		Response struct {
			Location        url.URL           `json:"location"`
			Status          string            `json:"status"`
			StatusCode      int               `json:"statuscode"`
			Headers         map[string]string `json:"headers"`
			Cookies         map[string]string `json:"cookies"`
			Protocol        string            `json:"protocol"`
			ContentLength   int64             `json:"contentlength"`
			Source          string            `json:"source"`
			ProtoMajor      int               `json:"protomajor"`
			ProtoMinor      int               `json:"protominor"`
			WasUncompressed bool              `json:"isuncompressed"`
		}
		Request struct {
			InsecureSkipVerify  bool              `json:"insecureskipverify"`
			Proxy               string            `json:"proxy"`
			URL                 string            `json:"url"`
			ReadResponseBody    bool              `json:"readresponse"`
			ReadResponseHeaders bool              `json:"readheaders"`
			ReadResponseCookies bool              `json:"readcookies"`
			Method              string            `json:"method"`
			Headers             map[string]string `json:"headers"`
			Payload             string            `json:"payload"`
			// Default 2.0
			Protocol                string   `json:"protocol"`
			Timeout                 string   `json:"timeout"`
			MaxRedirects            string   `json:"maxredirects"`
			HeaderOrderKey          []string `json:"headerorderkey"`
			GzipCompression         bool     `json:"gzipcompression"`
			DisableKeepAlive               bool     `json:"disablekeepalive"`
			ForceHttp1              bool     `json:"forcehttp1"`
			RandomTLSExtensionOrder bool     `json:"tlsextensionorder"`
			ForceAttemptHTTP2       bool     `json:"forceattempthttp2"`
			ClientProfile           struct {
				Client            tls.ClientHelloID          `json:"clientid"`
				ClientSpec        string                     `json:"clientspec"`
				ClientString      string                     `json:"client"`
				Tlsextension      string                     `json:"tlsextensions"`
				H2profile         string                     `json:"h2profile"`
				Settings          map[http2.SettingID]uint32 `json:"settings"`
				SettingsOrder     []http2.SettingID          `json:"settingsorder"`
				PseudoHeaderOrder []string                   `json:"pseudoheaderorder"`
				ConnectionFlow    uint32                     `json:"connectionflow"`
				Priorities        []http2.Priority           `json:"priorities"`
				HeaderPriority    *http2.PriorityParam       `json:"headerpriority"`
			}
		}
	}
}
