// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package email_server

import (
	"CentralizedControl/common"
	"CentralizedControl/common/email_server/base"
	"CentralizedControl/common/email_server/provider"
	"CentralizedControl/common/utils"
	"encoding/base64"
	"strings"
)

type FuncWaitCodeFunc = func(provider string, emailClient base.EmailInterface, fetchSeen bool) (string, error)

func DecodeEmailUtf8(text string) (string, error) {
	if !strings.HasPrefix(text, "=?UTF-8?B?") {
		return text, nil
	}
	ret := ""
	parts := strings.Split(text, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "=?UTF-8?B?") && strings.HasSuffix(part, "?=") {
			encodedText := part[10 : len(part)-2]
			decodedBytes, err := base64.StdEncoding.DecodeString(encodedText)
			if err != nil {
				return ret, err
			}
			ret += string(decodedBytes)
		}
	}
	return ret, nil
}

func WaitForCodeMessenger(providerName string, emailClient base.EmailInterface, fetchSeen bool) (string, error) {
	switch providerName {
	case provider.ProviderLinShiName:
		return emailClient.WaitForCode("registration@facebookmail.com",
			emailClient.GetAccount().Username, fetchSeen,
			func(_email *base.BaseEmail, resp *base.RespEmail) (string, error) {
				if resp == nil {
					return "", common.NerError("not recv")
				}
				return utils.GetMidString(resp.Body, "subject\">", " is your"), nil
			})
	case provider.ProviderYX1024Name:
		return emailClient.WaitForCode("registration@facebookmail.com",
			emailClient.GetAccount().Username, fetchSeen,
			func(_email *base.BaseEmail, resp *base.RespEmail) (string, error) {
				if resp == nil {
					return "", common.NerError("not recv")
				}
				subject := resp.Header.Get("Subject")
				if len(subject) <= 5 {
					return "", common.NerError("subject error!")
				}
				decodeSubject, err := DecodeEmailUtf8(subject)
				if err != nil {
					return "", err
				}
				return decodeSubject[:5], nil
			})
	default:
		panic("unknow provider")
	}
}

func WaitForCodeFacebook(provider string, emailClient base.EmailInterface, fetchSeen bool) (string, error) {
	return emailClient.WaitForCode("registration@facebookmail.com",
		emailClient.GetAccount().Username, fetchSeen,
		func(_email *base.BaseEmail, resp *base.RespEmail) (string, error) {
			if resp == nil {
				return "", common.NerError("not recv")
			}
			code := utils.GetMidString(resp.Body, "=E8=BE=93=E5=85=A5=E9=AA=8C=E8=AF=81=E7=A0=81=EF=BC=9A", "=E4=BD=A0=E5=8F=AF=E4=BB=A5=E5=9C=A8")
			code = strings.ReplaceAll(code, "\r", "")
			code = strings.ReplaceAll(code, "\n", "")
			return code, nil
		})
}

func WaitForInstagram(provider string, emailClient base.EmailInterface, fetchSeen bool) (string, error) {
	return emailClient.WaitForCode("no-reply@mail.instagram.com",
		emailClient.GetAccount().Username, fetchSeen,
		func(_email *base.BaseEmail, resp *base.RespEmail) (string, error) {
			if resp == nil {
				return "", common.NerError("not recv")
			}
			//"897350 is your Instagram code"
			subject := resp.Header.Get("Subject")
			if len(subject) <= 6 {
				return "", common.NerError("subject error!")
			}
			return subject[:6], nil
		})
}
