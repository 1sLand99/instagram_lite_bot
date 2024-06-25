// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package provider

import (
	"CentralizedControl/common/email_server/base"
	"CentralizedControl/common/utils"
	"sync"
)

type ProviderDebug struct {
	Provider
}

func CreateEmailProviderDebug() Provider {
	return &ProviderDebug{}
}

func (this *ProviderDebug) GetEmail() (base.EmailInterface, error) {
	return &base.BaseEmail{
		Account: &base.Account{
			Username:       utils.GenString(utils.CharSet_abc, 10) + "@outlook.com",
			Password:       "",
			SourceUsername: "",
		},
		Config:         nil,
		Lock:           sync.Mutex{},
		EmailInterface: nil,
		OnUsed:         0,
	}, nil
}

func (this *ProviderDebug) GetType() string {
	return ProviderDebugName
}
