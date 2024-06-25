// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package types

import (
	"CentralizedControl/ins_lite/proto/io"
	"reflect"
)

func WriteMsg(to io.BufferWriter, msg any) {
	v := reflect.ValueOf(msg)
	GetWriteFunc(v.Type())(to, v)
}

func ReadMsg(from io.BufferReader, msg any) {
	v := reflect.ValueOf(msg)
	GetReadFunc(v.Type())(from, v)
}
