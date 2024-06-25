// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package main

import (
	"github.com/pquerna/otp/totp"
	"strings"
	"testing"
	"time"
)

func Test2fa(t *testing.T) {
	c, _ := totp.GenerateCode(strings.ReplaceAll("UAYH 3Q3S GTYL W5L7 7562 TV3J OPRQ MUDZ", " ", ""), time.Now())
	println(c)
}
