// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package main

import (
	"CentralizedControl/common/proxys"
	"CentralizedControl/facebook"
	"testing"
)

func TestFb(t *testing.T) {
	facebook.InitFacebook(nil, nil)
	r := facebook.CreateRegister()
	r.Fb.SetProxy(proxys.DebugHttpProxy)
	r.FamilyDeviceIDAppScopedDeviceIDSyncMutation()
	r.ZeroHeadersPingParamsV2()
}
