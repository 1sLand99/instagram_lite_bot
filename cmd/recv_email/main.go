// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package main

import (
	"CentralizedControl/common/email_server"
	"CentralizedControl/common/email_server/base"
	"CentralizedControl/common/email_server/provider"
	"CentralizedControl/common/log"
	"time"
)

func main() {
	log.DisAbleDebugLog()
	log.InitDefaultLog("", true, true)
	emailServer := email_server.CreateEmailServer(&base.RetryConfig{
		LastReqTime:          time.Time{},
		RetryTimeoutDuration: 10 * 60 * time.Second,
		RetryDelayDuration:   1 * time.Second,
	}, provider.ProviderYX1024Name)
	email, err := emailServer.GetEmail(email_server.ProjectInstagramLite, false)
	if err != nil {
		log.Error("error: %s", err.Error())
		return
	}
	log.Info("email: %s", email)
	code, err := emailServer.SyncGetCode(email.Username, email_server.ProjectInstagramLite)
	if err != nil {
		log.Error("error: %s", err.Error())
	}
	log.Info("code: %s", code)
}
