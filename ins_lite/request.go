// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package ins_lite

import (
	"CentralizedControl/common/android"
	"CentralizedControl/common/utils"
	"CentralizedControl/ins_lite/proto"
	"CentralizedControl/ins_lite/proto/msg/recver"
	"CentralizedControl/ins_lite/proto/msg/sender"
	"CentralizedControl/ins_lite/proto/types"
	"time"
)

func (this *InsLiteClient) SendLoggedUserIdChange() {
	change := &proto.Message[sender.LoggedUserIdChange]{}
	this.SendMsg(change)
}

func (this *InsLiteClient) FetchImage(imageId uint64) error {
	image := &proto.Message[sender.FetchImage]{}
	image.Body.ImageId = imageId
	image.Body.Part = 0
	this.SendMsg(image)
	return nil
}

func (this *InsLiteClient) ReporterNetworkTypeChange() {
	reporter := &proto.Message[sender.NetworkTypeChangeReporter]{}
	body := &reporter.Body
	body.ChangeType = sender.ChangeType_STABLE
	body.NowTime = time.Now().UnixMilli()
	switch this.Cookies.Network.NetworkType {
	case android.NetworkTypeTypeWifi:
		body.NetworkType = "WIFI"
		body.NetworkSubType = "NONE"
	case android.NetworkTypeTypeMobile:
		body.NetworkType = "MOBILE"
		body.NetworkSubType = android.NetworkSubType2Name(this.Cookies.Network.NetworkSubType)
	}
	body.IsActiveNetworkMetered = sender.ActiveNetworkMetered_False
	body.TimeInterval = 0
	body.Unkonw2 = 0
	this.SendMsg(reporter)
}

func (this *InsLiteClient) sendNetworkInfo(newScreenId int32, oldScreenId int32, decodeBodyDataSize int) {
	s := &proto.Message[sender.NetworkInfo]{
		Body: sender.NetworkInfo{
			Const1_0: 0,
			Const2_5: 5,
			Const3_0: 0,
			Const4_1: 1,
			Const5_2: 2,
			Const6_3: 3,
			Const7_4: 4,
		},
	}
	flag1 := true
	flag2 := false
	flag := 2
	if flag1 {
		flag |= 4
	}
	if flag2 {
		flag |= 1
	}
	body := &s.Body
	body.OldScreenId1 = int64(oldScreenId)
	body.TimeInterval1 = int32(utils.GenNumber(500, 5000))
	body.Flag = byte(flag)
	body.DecodeBodyDataSize = int32(decodeBodyDataSize)
	body.QualityType = int32(this.Cookies.Temp.NetQualityType)
	if this.Cookies.Network.IsWifi() {
		body.WifiIsConnected = 3
	} else {
		body.WifiIsConnected = 1
	}
	body.NetworkSubType = int32(this.Cookies.Network.NetworkSubType)
	body.PhoneType = int32(this.Cookies.Phone.PhoneType)
	body.TimeInterval2 = int64(utils.GenNumber(5000, 30000))
	body.NewScreenId = int64(newScreenId)
	body.OldScreenId2 = oldScreenId
	this.SendMsg(s)
}

func (this *InsLiteClient) sendBrowserAction(screen *recver.ScreenReceived, navigationData *recver.NavigationData,
	likeExistMainScreenOrCanShow bool, bloksScreenName string, constFlag uint32, someConfig string) {
	msg := &proto.Message[sender.BrowserAction]{}
	var flags uint32
	if likeExistMainScreenOrCanShow {
		flags |= 16
	}
	if navigationData != nil {
		flags |= 0x80
	}
	if screen.DecodeBody.ScreenDecodeBodyItem73.IsNull() {
		flags |= 0x200
	} else {
		flags |= 0x200 | 0x400
	}
	if someConfig == "" { //some_key_map_str_A00
		flags |= 0x800 | 0x1000
	} else {
		flags |= 0x800 | 0x1000 | 0x2000
	}
	if bloksScreenName != "" {
		flags |= 0x4000
	}

	var Unknow5 uint32
	if flags&4 != 0 {
		Unknow5 = screen.GetUnknowFlag()
	}
	var navigation byte
	if flags&80 != 0 {
		navigation = navigationData.GetNavigation() & 0xFD
	}
	var HasScreenDecodeBodyItem73 byte
	var screenDecodeBodyItem73 types.ListValue[sender.BrowserAboutItem1, types.VarUInt32]
	if flags&0x400 != 0 {
		if screen.DecodeBody.ScreenDecodeBodyItem73.IsValueEmpty() {
			HasScreenDecodeBodyItem73 = 2
		} else {
			HasScreenDecodeBodyItem73 = 1
			//....screenDecodeBodyItem73
		}
	} else {
		HasScreenDecodeBodyItem73 = 0
	}

	msg.Body = sender.BrowserAction{
		ScreenId:                   screen.GetScreenId(),
		Time:                       time.Now().UnixMilli(),
		Const0:                     0,
		Flags:                      *types.CreateVarUInt32(flags),
		Unknow5:                    *types.CreateVarUInt32(Unknow5),
		Navigation:                 navigation,
		ConstFlag:                  *types.CreateVarUInt32(constFlag),
		HasScreenDecodeBodyItem73:  HasScreenDecodeBodyItem73,
		ScreenDecodeBodyItem73Data: screenDecodeBodyItem73,
		Const0_2:                   0,
		IsBackground:               0,
		GenDeviceTimeId:            this.Cookies.GenDeviceTimeId,
		SomeConfig:                 someConfig,
		BloksScreenName:            bloksScreenName,
	}
	this.SendMsg(msg)
}

func bool2byte(b bool) byte {
	if b {
		return 1
	} else {
		return 0
	}
}

func (this *InsLiteClient) sendPermResult(pkgIdx int32, b1, isAllow, DontShowRequestPermissionDialog bool) {
	msg := &proto.Message[sender.PermResult]{}
	body := &msg.Body
	body.Idx = pkgIdx
	body.Unknow1 = bool2byte(b1)
	body.IsAllow = bool2byte(isAllow)
	body.DontShowRequestPermissionDialog = bool2byte(DontShowRequestPermissionDialog)
	this.SendMsg(msg)
}
