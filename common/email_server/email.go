// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package email_server

import (
	"CentralizedControl/common"
	"CentralizedControl/common/email_server/base"
	"CentralizedControl/common/email_server/provider"
	"CentralizedControl/common/fastjson"
	"CentralizedControl/common/log"
	"gorm.io/gorm"
	"sync"
	"time"
)

const (
	pendingStateJustGet = iota
	pendingStateRequesting
	pendingStateFinish
	pendingStateError
)

const (
	ProjectFacebook      = "facebook"
	ProjectFacebookLite  = "facebook_lite"
	ProjectInstagram     = "instagram"
	ProjectInstagramLite = "instagram_lite"
	ProjectMessenger     = "messenger"
)

var DefaultRetryConfig = &base.RetryConfig{
	RetryTimeoutDuration: 1 * time.Minute,
	RetryDelayDuration:   5 * time.Second,
}

var DefaultOutlookConfig = &base.Config{
	Server:      "outlook.office365.com",
	Port:        "993",
	RetryConfig: DefaultRetryConfig,
}

type PendingAccount struct {
	lock         sync.Mutex
	Email        base.EmailInterface `json:"-"`
	EmailAccount *base.Account       `json:"email"`
	State        int                 `json:"state"`
	Code         string              `json:"code"`
	Error        error               `json:"error"`
	Project      string              `json:"project"`
	Type         string              `json:"type"`
	StartTime    time.Time           `json:"startTime"`
}

type EmailServer struct {
	pendingEmail     map[string]*PendingAccount
	pendingLock      sync.Mutex
	curProvider      provider.Provider
	extractEmailFunc map[string]FuncWaitCodeFunc
	emailRetryConfig *base.RetryConfig
	cache            *EmailCache
}

var yx1024Url = "https://api.yx1024.cc/getAccountApi.aspx?uid=55436&type=69&token=&count=1"
var youxiang555Url = "https://www.youxiang555.com/api/pub/email.html?type=33&token=&count=1"

func CreateEmailServer(emailConfig *base.RetryConfig, providerName string) *EmailServer {
	log.Info("email server start...")
	if emailConfig == nil {
		emailConfig = DefaultRetryConfig
	}
	es := &EmailServer{
		pendingEmail:     make(map[string]*PendingAccount),
		emailRetryConfig: emailConfig,
		extractEmailFunc: map[string]FuncWaitCodeFunc{
			ProjectFacebookLite:  WaitForCodeFacebook,
			ProjectInstagramLite: WaitForInstagram,
			ProjectMessenger:     WaitForCodeMessenger,
		},
	}
	switch providerName {
	case provider.ProviderDebugName:
		es.curProvider = provider.CreateEmailProviderDebug()
	case provider.ProviderYX1024Name:
		es.curProvider = provider.CreateEmailProviderYX1024(yx1024Url, emailConfig)
	case provider.ProviderLinShiName:
		es.curProvider = provider.CreateProviderLingshi(emailConfig)
	case provider.ProviderYouXiang555Name:
		es.curProvider = provider.CreateEmailProviderYouXiang555(youxiang555Url, emailConfig)
	}
	return es
}

func (this *EmailServer) SetDB(DB *gorm.DB) {
	this.cache = CreateDbCacheEmailProvider(DB)
}

func (this *EmailServer) CreatePendingEmail(email base.EmailInterface, project string) {
	username := email.GetAccount().Username
	var pending = &PendingAccount{
		Email:        email,
		EmailAccount: email.GetAccount(),
		Project:      project,
		Type:         this.curProvider.GetType(),
		State:        pendingStateJustGet,
		StartTime:    time.Now(),
	}
	this.pendingLock.Lock()
	defer this.pendingLock.Unlock()
	this.pendingEmail[username] = pending
}

func (this *EmailServer) GetServerStatus() (string, error) {
	this.pendingLock.Lock()
	defer this.pendingLock.Unlock()
	resp := fastjson.MustParse("[]")
	idx := 0
	for _, v := range this.pendingEmail {
		item := fastjson.MustParse("{}")
		item.Set("state", fastjson.AutoParse(v.State))
		item.Set("code", fastjson.AutoParse(v.Code))
		item.Set("error", fastjson.AutoParse(v.Error))
		item.Set("project", fastjson.AutoParse(v.Project))
		item.Set("type", fastjson.AutoParse(v.Type))
		item.Set("startTime", fastjson.AutoParse(v.StartTime))
		item.Set("email", fastjson.AutoParse(v.Email.GetAccount().Username))
		item.Set("passwd", fastjson.AutoParse(v.Email.GetAccount().Password))
		item.Set("login", fastjson.AutoParse(v.Email.GetStatus()))
		resp.SetArrayItem(idx, item)
		idx++
	}
	return resp.String(), nil
}

func (this *EmailServer) GetEmail(project string, useCache bool) (*base.Account, error) {
	var _email base.EmailInterface
	var err error
	if useCache && this.cache != nil {
		_email, err = this.cache.GetEmailByProject(project)
		if err != nil {
			log.Error("get email form cache error: %v", err)
		}
	}

	if _email == nil {
		_email, err = this.curProvider.GetEmail()
		if err == nil && this.cache != nil {
			err = this.cache.SaveNewEmailDb(_email, project, this.curProvider.GetType())
			if err != nil {
				log.Error("save email error: %v", err)
			}
		} else {
			log.Error("get email form provider %s error: %v", this.curProvider.GetType(), err)
		}
	}

	if _email == nil {
		log.Error("get email failed!")
		return nil, err
	}

	this.CreatePendingEmail(_email, project)
	return _email.GetAccount(), nil
}

func (this *EmailServer) doGetCode(pending *PendingAccount, project string) {
	pending.State = pendingStateRequesting
	log.Info("go get code coro: %s", pending.EmailAccount.Username)
	if this.extractEmailFunc[project] != nil {
		pending.Code, pending.Error = this.extractEmailFunc[project](this.curProvider.GetType(), pending.Email, false)
		if pending.Error != nil {
			log.Error("email: %s, get code error: %v", pending.EmailAccount.Username, pending.Error)
		} else {
			log.Info("email: %s, get code: %v", pending.EmailAccount.Username, pending.Code)
		}
	} else {
		pending.Error = common.NerError("extractEmailFunc not exist")
	}

	pending.lock.Lock()
	if pending.Code != "" {
		pending.State = pendingStateFinish
	}
	if pending.Error != nil {
		pending.State = pendingStateError
	}
	pending.lock.Unlock()
}

func (this *EmailServer) SyncGetCode(email string, project string) (string, error) {
	this.pendingLock.Lock()
	var pending = this.pendingEmail[email]
	this.pendingLock.Unlock()
	if pending == nil {
		return "", common.NerError("not in pending")
	}

	switch pending.State {
	case pendingStateJustGet:
		pending.lock.Lock()
		pending.State = pendingStateRequesting
		pending.lock.Unlock()
		this.doGetCode(pending, project)
		if pending.Error != nil {
			log.Error("email: %s, project: %s, get code error: %v",
				email, project, pending.Error)
		}
		this.releasePendingEmail(pending, project)
		return pending.Code, pending.Error
	case pendingStateRequesting:
		return "", common.NerError("rein")
	case pendingStateFinish, pendingStateError:
		return pending.Code, pending.Error
	}
	return "", common.NerError("wtf?")
}

func (this *EmailServer) AsyncGetCode(email string, project string) (string, error) {
	this.pendingLock.Lock()
	defer this.pendingLock.Unlock()

	var pending = this.pendingEmail[email]
	if pending == nil {
		return "", common.NerError("not in pending")
	}

	pending.lock.Lock()
	defer pending.lock.Unlock()

	switch pending.State {
	case pendingStateJustGet:
		pending.State = pendingStateRequesting
		go this.doGetCode(pending, project)
		return "", common.NerError("commit")
	case pendingStateRequesting:
		return "", common.NerError("commit")
	case pendingStateFinish, pendingStateError:
		if pending.Error != nil {
			log.Error("email: %s, project: %s, get code error: %v",
				email, project, pending.Error)
		}
		this.releasePendingEmail(pending, project)
		return pending.Code, pending.Error
	}
	return "", common.NerError("wtf?")
}

func (this *EmailServer) ReleaseEmail(email string, project string, opt string) error {
	this.pendingLock.Lock()
	defer this.pendingLock.Unlock()
	this.releasePendingEmail(this.pendingEmail[email], project)
	if this.cache != nil {
		err := this.cache.UpdateEmailProject(email, project, opt)
		if err != nil {
		}
	}
	return nil
}

func (this *EmailServer) releasePendingEmail(pending *PendingAccount, project string) {
	if pending != nil {
		delete(this.pendingEmail, pending.EmailAccount.Username)
		pending.Email.Close()
	}
}
