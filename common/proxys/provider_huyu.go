// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package proxys

import (
	"CentralizedControl/common/log"
	"CentralizedControl/common/utils"
	"fmt"
)

type HuyuProvider struct {
	Url string
}

func CreateHuyuProvider() *HuyuProvider {
	return &HuyuProvider{
		Url: "",
	}
}

func (this *HuyuProvider) GetProxy(region string, asn string) Proxy {
	proxy, err := CreateSocks5Proxy(fmt.Sprintf("socks://%:@192...:", utils.GenString(utils.CharSet_123, 6)))
	if err != nil {
		log.Error("rola CreateSocks5Proxy error: %v", err)
		return nil
	}
	return proxy
}
