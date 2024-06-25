// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package ins_lite

import (
	"CentralizedControl/common/log"
	"CentralizedControl/ins_lite/proto/msg/recver"
	"CentralizedControl/ins_lite/tools"
	"encoding/json"
)

func (this *InsLiteClient) TestAddScreen(data string) *recver.ScreenReceived {
	parse := tools.ParseLiteRecvStr(data)
	this.addScreen(parse.Body.(*recver.ScreenReceived))
	return parse.Body.(*recver.ScreenReceived)
}

func (this *InsLiteClient) TestUpdateScreen(data string) *recver.ScreenReceived {
	p := tools.ParseLiteRecvStr(data)
	body := p.Body.(*recver.ScreenDiff)
	s := this.getScreenById(body.ScreenId)
	if s == nil {
		panic("")
	}
	s.DecodeBody.ReadChange(p.Reader, 0, nil)
	log.Info("TestUpdateScreen remain %d", len(p.Reader.PeekRemain()))
	return s
}

func (this *InsLiteClient) TestScreen2Json() string {
	marshal, err := json.Marshal(this.Screen)
	if err != nil {
		panic(err)
	}
	return string(marshal)
}
