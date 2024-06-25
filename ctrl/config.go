// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package ctrl

import (
	"CentralizedControl/common/email_server/provider"
)

var (
	MessengerAccountTable = "messenger_cookies"
	FacebookAccountTable  = "facebook_cookies"
	InstagramAccountTable = "instagram_cookies"
)

var (
	ConfigProxyTypeSubscribe = 0
	ConfigProxyTypeLuminati  = 1
	ConfigProxyTypeOxylabs   = 2
	ConfigProxyTypeZenoo     = 2

	ConfigProxyUse = ConfigProxyTypeSubscribe
)

var (
	ConfigEmailUse = provider.ProviderYX1024Name
)
