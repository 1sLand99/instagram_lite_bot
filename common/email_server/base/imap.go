// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package base

import (
	"CentralizedControl/common/log"
	"CentralizedControl/common/utils"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"io/ioutil"
	"net/mail"
	"strings"
	"sync"
)

type Imap struct {
	*BaseEmail
	client *client.Client
}

func (this *Imap) CheckError(err error) error {
	if err == nil {
		return nil
	}
	switch err.Error() {
	case client.ErrAlreadyLoggedIn.Error():
		this.Status = StatusLogin
		return nil
	case "LOGIN failed.":
		this.Status = StatusPasswdError
		return NeedPasswdError
	case "User is authenticated but not connected.":
		this.Status = StatusBan
		return NeedBanError
	case "connection closed":
		this.Status = StatusNoLogin
		return NeedLoginError
	default:
		if strings.Contains(err.Error(), "An established connection was aborted by the software in your host machine.") {
			this.Status = StatusNoLogin
			return NeedLoginError
		}
		return nil
	}
}

func (this *Imap) RequireEmail(sender string, to string, fetchSeen bool) ([]*RespEmail, error) {
	email, err := this.requireEmail(sender, to, fetchSeen)
	if err != nil {
		log.Error("imap %s error: %v", this.Username, err)
		return nil, this.CheckError(err)
	}
	if email == nil {
		return nil, NotRecvError
	}
	return email, nil
}

func (this *Imap) requireEmail(from string, to string, fetchSeen bool) ([]*RespEmail, error) {
	_, err := this.client.Select("INBOX", false)
	if err != nil {
		return nil, err
	}

	criteria := imap.NewSearchCriteria()
	if fetchSeen {
		criteria.WithFlags = []string{imap.SeenFlag}
	} else {
		criteria.WithFlags = []string{imap.RecentFlag}
	}
	//criteria.Text = []string{to}
	//criteria.WithoutFlags = []string{imap.RecentFlag}
	//criteria.Header.Add("Delivered-To", to)
	//criteria.Header.Add("To", to)
	criteria.Header.Add("From", from)
	ids, err := this.client.Search(criteria)
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		seqset := &imap.SeqSet{}
		seqset.AddNum(ids[len(ids)-1])
		//seqset.AddNum(ids[0])

		messages := make(chan *imap.Message, 2)
		section := &imap.BodySectionName{}
		err = this.client.Fetch(seqset, []imap.FetchItem{section.FetchItem()}, messages)
		if err != nil {
			return nil, err
		}
		var emails []*RespEmail
		for msg := range messages {
			r := msg.GetBody(section)
			m, err := mail.ReadMessage(r)
			if err != nil {
				return nil, err
			}
			body, err := ioutil.ReadAll(m.Body)
			if err != nil {
				return nil, err
			}

			emails = append(emails, &RespEmail{
				To:     utils.GetMidString(m.Header.Get("To"), "<", ">"),
				Header: m.Header,
				Body:   string(body),
			})
		}
		return emails, nil
	}

	return nil, nil
}

func (this *Imap) Close() {
	this.client.Close()
}

func (this *Imap) Login() error {
	var err error
	defer func() {
		if err != nil {
			log.Error("email %s login error:%v", this.Username, err)
		} else {
			log.Info("email %s login success", this.Username)
		}
	}()
	if this.client != nil {
		if this.Status == StatusNoLogin {
			this.client.Close()
		}
		if this.Status == StatusLogin {
			return nil
		}
	}
	this.client, err = client.DialTLS(this.Server+":"+this.Port, nil)
	if err != nil {
		log.Error("imap create client error: %v", err)
		this.Status = StatusNoLogin
		return nil
	}
	err = this.client.Login(this.Username, this.Password)
	if err != nil {
		return this.CheckError(err)
	}
	this.Status = StatusLogin
	return nil
}

func (this *Imap) Test() error {
	this.Lock.Lock()
	defer this.Lock.Unlock()
	for true {
		switch this.Status {
		case StatusLogin:
			_, _ = this.RequireEmail("no-reply@microsoft.com", this.Username, true)
			if this.Status == StatusLogin {
				return nil
			}
		case StatusNoLogin:
			this.Login()
		case StatusBan:
			return NeedBanError
		case StatusPasswdError:
			return NeedPasswdError
		}
	}
	return nil
}

func CreateImapEmail(config *Config, acc *Account) *Imap {
	imap := &Imap{
		BaseEmail: &BaseEmail{
			Account:        acc,
			Config:         config,
			Lock:           sync.Mutex{},
			Status:         StatusNoLogin,
			EmailInterface: nil,
			OnUsed:         0,
		},
		client: nil,
	}
	imap.BaseEmail.EmailInterface = imap
	go func() {
		imap.Lock.Lock()
		defer imap.Lock.Unlock()
		err := imap.Login()
		if err != nil {
			log.Error("email %s login error: %v", imap.Username, err)
		}
	}()
	return imap
}
