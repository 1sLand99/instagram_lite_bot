// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package main

import (
	"CentralizedControl/common/email_server"
	"CentralizedControl/common/log"
	"CentralizedControl/common/proxys"
	"CentralizedControl/ctrl"
)

func main() {
	log.InitDefaultLog("ctrl", true, true)
	log.Info("ctrl server start...")
	ctrl.InitMysql()
	http := ctrl.RunHttpServer(
		email_server.CreateEmailServer(nil, ctrl.ConfigEmailUse),
		proxys.CreateProxysManage(),
	)
	http.Run()
}
