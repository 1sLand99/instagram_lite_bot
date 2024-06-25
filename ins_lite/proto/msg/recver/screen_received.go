// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package recver

import (
	"CentralizedControl/ins_lite/proto/io"
	"CentralizedControl/ins_lite/proto/types"
	"fmt"
)

var (
	//NavigationData.Flags  & 0xFFFFFF7F & 0xFF & -17 & 0xFF
	RecvNavigationData_BACK                = 0
	RecvNavigationData_REPLACE             = 8
	RecvNavigationData_EXIT_FLOW           = 6
	RecvNavigationData_FORWARD             = 1
	RecvNavigationData_FORWARD_OR_COLLAPSE = 5
	RecvNavigationData_ENTER_FLOW          = 3
	RecvNavigationData_RESET               = 3
	RecvNavigationData_EXIT_AND_FORWARD    = 5
	RecvNavigationData_EXIT_AND_REPLACE    = 5
	RecvNavigationData_IGNORE              = 9
)

type NavigationData struct {
	Flags   byte
	Flags2  types.VarUInt32 `ins:"(Flags & 16) != 0"`
	Unknow2 int16           `ins:"((Flags & 16) != 0) && ((Flags2 & 16) != 0)"`
	Unknow3 int16           `ins:"((Flags & 16) != 0) && ((Flags2 & 32) != 0)"`
	Unknow4 byte            `ins:"((Flags & 16) != 0) && ((Flags2 & 64) != 0)"`
}

func (this *NavigationData) GetNavigation() byte {
	return this.Flags & 0x7F & 0xEF
}

type ScreenReceivedHeader struct {
	ScreenId       int32
	PartNumber     types.VarUInt32
	Unknow3        int32
	DisplayNow     bool
	Flags          int32
	UnknowFlag1    byte            `ins:"(Flags & 64) != 0"`
	UnknowFlag2    types.VarUInt32 `ins:"(Flags & 256) != 0"`
	Unknow8        string          `ins:"(Flags & 1024) != 0"`
	Unknow9        string          `ins:"(Flags & 2048) != 0"`
	NavigationData NavigationData  `ins:"DisplayNow && (Flags & 512) != 0 "`
}

// X.screen_msg_deal_0KW.deal_recv_msg_AO5(X.0Ig) : void 11
type ScreenReceived struct {
	ScreenReceivedHeader
	DecodeBody         ScreenDecode
	DecodeBodyDataSize int `ins:"false"`
}

func (this *ScreenReceived) GetUnknowFlag() uint32 {
	var UnknowFlag uint32
	if this.Flags&64 != 0 {
		UnknowFlag = uint32(this.UnknowFlag1)
	}
	if this.Flags&0x100 != 0 {
		UnknowFlag = this.UnknowFlag2.Value
	}
	return UnknowFlag
}

func (this *ScreenReceived) GetRunScreenCode() int32 {
	return this.DecodeBody.ScreenDecodeBody.RunScreenCode.Value
}

func (this *ScreenReceived) GetScreenName() string {
	return this.DecodeBody.ScreenDecodeBody.ScreenName.Value
}

func (this *ScreenReceived) GetScreenId() int32 {
	return this.ScreenId
}

func (this *ScreenReceived) GetScreenCmdByIdx(idx int32) (uint32, []byte) {
	code, data := this.DecodeBody.ScreenCmdArray.GetScreenCmdByIdx(idx)
	if code == 0 {
		panic(fmt.Sprintf("not find cmd by idx: %d", idx))
	}
	return code, data
}

func (this *ScreenReceived) GetScreenByWindowId(id string) *SubScreen {
	allScreen := this.GetAllSubScreen()
	for idx := range allScreen.SubScreen {
		sub := allScreen.Get(idx)
		if sub.GetBaseScreen().WindowId.Value == id {
			return sub
		}
	}
	return nil
}

func (this *ScreenReceived) GetAllSubScreen() *SubScreenArray {
	return this.DecodeBody.GetAllSubScreen()
}

func (this *ScreenReceived) Write(to io.BufferWriter) {

}

func (this *ScreenReceived) Read(from io.BufferReader) {
	types.ReadMsg(from, &this.ScreenReceivedHeader)
	this.DecodeBodyDataSize = len(from.PeekRemain())
	types.ReadMsg(from, &this.DecodeBody)
}
