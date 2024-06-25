// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package main

import (
	"fmt"

	"github.com/bytedance/sonic"
)

var V int

var Obj map[string]string

func init() {
	if err := sonic.UnmarshalString(`{"a":"b"}`, &Obj); err != nil {
		panic(err)
	}
}

func F() { fmt.Printf("Hello, number %d\n", V) }

func Unmarshal(json string, val interface{}) error {
	return sonic.UnmarshalString(json, val)
}
