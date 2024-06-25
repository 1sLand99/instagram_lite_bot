// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package base

import (
	"CentralizedControl/common"
	"CentralizedControl/common/log"
	"errors"
	"fmt"
	"net/mail"
	"sync"
	"sync/atomic"
	"time"
)

type Account struct {
	Username       string `db:"username" json:"username"`
	Password       string `db:"password" json:"password"`
	SourceUsername string
}

type RetryConfig struct {
	LastReqTime          time.Time
	RetryTimeoutDuration time.Duration
	RetryDelayDuration   time.Duration
}

type Config struct {
	Server      string `json:"server"`
	Port        string `json:"port"`
	RetryConfig *RetryConfig
}

type RespEmail struct {
	To     string
	Header mail.Header
	Body   string
}

const (
	StatusNoLogin = iota
	StatusLogin
	StatusPasswdError
	StatusBan
)

var (
	NotRecvError    = common.NerError("not recv")
	NeedLoginError  = common.NerError("need login")
	NeedPasswdError = common.NerError("Passwd Error")
	NeedBanError    = common.NerError("Ban Error")
)

type ExtractEmailCallback func(_email *BaseEmail, resp *RespEmail) (string, error)

type EmailInterface interface {
	GetAccount() *Account
	Login() error
	RequireEmail(sender string, to string, fetchSeen bool) ([]*RespEmail, error)
	WaitForCode(sender string, to string, fetchSeen bool, callback ExtractEmailCallback) (string, error)
	Close()
	AddUsed(num int) int32
	GetStatus() int
}

type BaseEmail struct {
	EmailInterface
	*Account
	*Config
	Lock   sync.Mutex
	OnUsed int32
	Status int
}

func (this *BaseEmail) GetStatus() int {
	return this.Status
}

func (this *BaseEmail) AddUsed(num int) int32 {
	return atomic.AddInt32(&this.OnUsed, int32(num))
}

func (this *BaseEmail) GetAccount() *Account {
	return this.Account
}

func (this *BaseEmail) WaitForCode(sender string, to string, fetchSeen bool, callback ExtractEmailCallback) (string, error) {
	this.Lock.Lock()
	defer this.Lock.Unlock()

	retry := 0
	start := time.Now()
	for time.Since(start) < this.RetryConfig.RetryTimeoutDuration {
		var emails []*RespEmail
		var err error

		switch this.Status {
		case StatusLogin:
			emails, err = this.RequireEmail(sender, to, fetchSeen)
			if emails != nil {
				for _, item := range emails {
					var code string
					code, err = callback(this, item)
					if err == nil && code != "" {
						return code, nil
					}
				}
				return "", errors.New("no one accept")
			}
			retry = 0
		case StatusNoLogin:
			err = this.Login()
			if err != nil {
				log.Warn("email: %s login error: %v", this.Username, err)
				if retry > 3 {
					log.Warn("email: %s login retry more than 3 so exit!", this.Username)
					return "", errors.New(fmt.Sprintf("email: %s login retry more than 3 so exit!", this.Username))
				}
			}
			retry++
		case StatusBan:
			return "", NeedBanError
		case StatusPasswdError:
			return "", NeedPasswdError
		}
		log.Warn("wait for %s code...error: %v", this.Username, err)
		time.Sleep(this.RetryConfig.RetryDelayDuration)
	}
	return "", errors.New("require code timeout")
}
