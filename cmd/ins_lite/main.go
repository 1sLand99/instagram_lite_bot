// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package main

import (
	"CentralizedControl/common/email_server"
	"CentralizedControl/common/log"
	"CentralizedControl/common/phone"
	"CentralizedControl/common/proxys"
	"CentralizedControl/ins_lite"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

type RegisterResult struct {
	IsSuccess    bool                    `json:"is_success"`
	Error        string                  `json:"error"`
	RegisterType string                  `json:"register_type"`
	PhoneNumber  string                  `json:"phone_number"`
	AreaCode     string                  `json:"area_code"`
	Email        string                  `json:"email"`
	EmailPasswd  string                  `json:"email_passwd"`
	HadSendCode  bool                    `json:"had_send_code"`
	HadGetCode   bool                    `json:"had_get_code"`
	Username     string                  `json:"username"`
	Passwd       string                  `json:"passwd"`
	DeviceName   string                  `json:"device_name"`
	Client       *ins_lite.InsLiteClient `json:"-"`
	Cookies      *ins_lite.Cookies       `json:"cookies"`
}

var AccountFile *os.File = nil
var AccountFileLock sync.Mutex

func saveAccount(result *RegisterResult) {
	AccountFileLock.Lock()
	defer AccountFileLock.Unlock()

	if AccountFile == nil {
		var err error
		AccountFile, err = os.OpenFile("./accounts.json", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			panic(fmt.Sprintf("open account file error: %v", err))
		}
		AccountFile.Write([]byte("\n-----------------\n"))
	}

	marshal, _ := json.Marshal(result)
	log.Info("reg result: %s", string(marshal))
	AccountFile.Write(marshal)
	AccountFile.Write([]byte("\n"))
	AccountFile.Sync()
}

// var ConfigPath = flag.String("config", "./ins_lite_register.json", "")
var UseProxy = flag.Bool("p", true, "")
var RegisterCount = flag.Int("count", 1, "")
var RegType = flag.String("reg_type", "email", "")
var Country = flag.String("country", "in", "")

// var EmailProvider = flag.String("email_provider", "yx1024", "")
var EmailProvider = flag.String("email_provider", "yx1024", "")
var Asn = flag.String("asn", "AS45271", "")

func main() {
	//defer func() {
	//	r := recover()
	//	if r != nil {
	//		log.Error("exit error: %v", r)
	//	}
	//}()
	log.DisAbleDebugLog()
	log.InitDefaultLog("", true, true)
	flag.Parse()

	var testProxy proxys.Proxy = nil
	//var err error
	//testProxy, err = proxys.CreateSocks5Proxy("socks://:@185.130.105.112:10000")
	//if err != nil {
	//	panic(err)
	//}
	//proxy := proxys.CreateMangoProxy()
	//proxy := proxys.CreateRolaPool(proxys.PhoneNet)
	proxy := proxys.CreateHuyuProvider()
	emailServer := email_server.CreateEmailServer(nil, *EmailProvider)
	smsHub := phone.CreateSmsHub(phone.Instagram, *Country)

	getProxy := func() proxys.Proxy {
		if testProxy != nil {
			return testProxy
		}
		var p proxys.Proxy = nil
		if *UseProxy {
			for {
				p = proxy.GetProxy(*Country, *Asn)
				if p == nil {
					time.Sleep(10 * time.Second)
					continue
				}
				info, _ := json.Marshal(p.Test())
				log.Info("proxy ip: %s", info)
				if info != nil {
					break
				}
			}
		}
		return p
	}
	getPhone := func() *phone.Number {
		for true {
			number := smsHub.GetPhoneNumber()
			if number == nil {
				time.Sleep(10 * time.Second)
				continue
			}
			return number
		}
		return nil
	}
	registers := make([]RegisterResult, 0)
	//for count := 0; count < *RegisterCount; count++ {
	for true {
		var result RegisterResult
		if *RegType == "email" {
			result = registerEmail(emailServer, getProxy(), *Country)
			//result := registerEmail(emailServer, nil, RegConfig.County)
			registers = append(registers, result)
			saveAccount(&result)
		} else {
			number := getPhone()
			for i := 0; i < 1; i++ {
				result = registerPhone(number, getProxy(), *Country)
				registers = append(registers, result)
				saveAccount(&result)
				err := smsHub.Continue(number)
				if err != nil {
					break
				}
				//time.Sleep(1 * time.Minute)
			}
			smsHub.Release(number)
		}
	}
	successCount := 0
	errorCount := 0
	for idx := range registers {
		if registers[idx].IsSuccess {
			successCount++
		} else {
			errorCount++
		}
	}
	log.Info("all finish, success: %d, error: %d", successCount, errorCount)
}
