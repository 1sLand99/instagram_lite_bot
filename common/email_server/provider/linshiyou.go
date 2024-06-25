// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package provider

import (
	"CentralizedControl/common/email_server/base"
	"CentralizedControl/common/http_helper"
	"CentralizedControl/common/utils"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

type WebEmail struct {
	*base.BaseEmail
	client                *http.Client
	PHPSESSID             string
	logglytrackingsession string
	tmail                 string
}

func (this *WebEmail) Login() error {
	_url, _ := url.Parse("https://linshiyou.com/")
	ck := make([]*http.Cookie, 3)
	ck[0] = &http.Cookie{
		Name:  "PHPSESSID",
		Value: this.PHPSESSID,
	}
	ck[1] = &http.Cookie{
		Name:  "logglytrackingsession",
		Value: this.logglytrackingsession,
	}
	ck[2] = &http.Cookie{
		Name:  "tmail-emails",
		Value: utils.EncodeQueryPath(fmt.Sprintf("a:1:{i:0;s:20:\"%s\";}", this.Username)),
	}
	this.client.Jar.SetCookies(_url, ck)

	do, err := http_helper.HttpDo(this.client, &http_helper.RequestOpt{
		Params: map[string]string{
			"user": this.Username,
		},
		Header: map[string]string{
			"referer":          "https://linshiyou.com/",
			"x-requested-with": "XMLHttpRequest",
			"accept":           "*/*",
		},
		IsPost: false,
		ReqUrl: "https://linshiyou.com/user.php",
	})
	if err != nil {
		return err
	}
	if do != this.Username {
		return errors.New("not match email username")
	}
	this.Status = base.StatusLogin
	return nil
}

func (this *WebEmail) RequireEmail(sender string, to string, _ bool) ([]*base.RespEmail, error) {
	do, err := http_helper.HttpDo(this.client, &http_helper.RequestOpt{
		Params: map[string]string{
			"unseen": "1",
		},
		Header: map[string]string{
			"referer":          "https://linshiyou.com/",
			"x-requested-with": "XMLHttpRequest",
			"accept":           "*/*",
		},
		IsPost: false,
		ReqUrl: "https://linshiyou.com/mail.php",
	})
	if err != nil {
		return nil, err
	}
	if len(do) == 0 {
		return nil, nil
	}
	if do == "DIE" {
		return nil, errors.New("email die")
	}
	return []*base.RespEmail{&base.RespEmail{
		Header: nil,
		Body:   do,
	}}, nil
}

func (this *WebEmail) Close() {
	this.client.CloseIdleConnections()
}

type ProviderLingshi struct {
	Provider
	retry *base.RetryConfig
}

func (this *ProviderLingshi) GetType() string {
	return ProviderLinShiName
}

func (this *ProviderLingshi) GetEmail() (base.EmailInterface, error) {
	//acc := &Account{Username: common.GenString(common.CharSet_abc, 10) + "@linshiyou.com"}
	acc := &base.Account{Username: utils.GenString(utils.CharSet_abc, 10) + "@youxiang.dev"}
	var client = &WebEmail{
		BaseEmail: &base.BaseEmail{
			Account: acc,
			Config: &base.Config{
				RetryConfig: this.retry,
			},
			EmailInterface: nil,
		},
		client: http_helper.CreateGoHttpClient(http_helper.EnableHttp2(),
			http_helper.HttpTimeout(20),
			http_helper.NeedJar()),
		PHPSESSID:             utils.GenString(utils.CharSet_All, 26),
		logglytrackingsession: utils.GenUUID(),
		tmail:                 utils.Escape(acc.Username, utils.EscapeEncodePathSegment),
	}
	client.BaseEmail.EmailInterface = client

	go func() {
		client.Lock.Lock()
		defer client.Lock.Unlock()
		client.Login()
	}()
	return client, nil
}

func CreateProviderLingshi(retry *base.RetryConfig) Provider {
	return &ProviderLingshi{
		retry: retry,
	}
}
