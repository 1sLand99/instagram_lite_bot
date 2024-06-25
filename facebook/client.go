// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package facebook

import (
	"CentralizedControl/common/http2_helper"
	"CentralizedControl/common/proxys"
	http "github.com/bogdanfinn/fhttp"
	"strconv"
)

type Facebook struct {
	ck         *Cookies
	tmpCk      *TempCookies
	httpClient *http.Client
	proxy      proxys.Proxy
}

func (this *Facebook) GetCookies() *Cookies {
	return this.ck
}

func (this *Facebook) GetSelfUserId() uint64 {
	id, _ := strconv.ParseInt(this.ck.AccountId, 10, 64)
	return uint64(id)
}

func (this *Facebook) newApiRequest(api string, bodyTempKey string) *ApiRequest {
	return newApiRequest(this, api, bodyTempKey)
}

func (this *Facebook) SetProxy(proxy proxys.Proxy) {
	if proxy == proxys.DebugHttpProxy {
		http2_helper.DisableHttpSslPinng()(this.httpClient)
	}
	http2_helper.HttpSetProxy(proxy)(this.httpClient)
}

func CreateFacebook(cookies *Cookies) *Facebook {
	msg := &Facebook{
		ck:         cookies,
		tmpCk:      &TempCookies{},
		httpClient: http2_helper.CreateHttp2Client(http2_helper.DisableRedirect()),
	}
	return msg
}

//func (this *Facebook) UpdateCookiesValue(key string, value string) {
//	DbCtrl.UpdateCookiesValue(this, key, value)
//}
