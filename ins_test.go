// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package main

import (
	"CentralizedControl/common/proxys"
	"CentralizedControl/instagram"
	"os"
	"testing"
)

func TestIns(t *testing.T) {
	instagram.InitInstagram(nil, nil)
	ckStr, _ := os.ReadFile("./ins_ck.json")
	ck := instagram.ConvDeviceFile2Cookies(string(ckStr))
	ins := instagram.CreateInstagram(ck)
	ins.SetProxy(proxys.DebugHttpProxy)
	//info, err := ins.GetUserInfo(ins.GetSelfUserId())
	//if err != nil {
	//	return
	//}
	//_ = info
	//err := ins.FollowUserByQrCode("https://instagram.com/kaphlenaroiez?igshid=ZGUzMzM3NWJiOQ==")
	err := ins.FollowUserByQrCode("https://instagram.com/rodrigueznovan?igshid=ZGUzMzM3NWJiOQ==")
	if err != nil {
		return
	}
}
