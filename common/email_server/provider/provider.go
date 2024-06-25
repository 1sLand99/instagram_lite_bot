// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package provider

import (
	"CentralizedControl/common/email_server/base"
)

const (
	ProviderDebugName       = "debug"
	ProviderYX1024Name      = "yx1024"
	ProviderLinShiName      = "linshiyou"
	ProviderYouXiang555Name = "youxiang555"
	EmailCacheProviderName  = "db_cache"
)

//SADEfb.y31531
//ddsdew323323s

type Provider interface {
	GetType() string
	GetEmail() (base.EmailInterface, error)
}
