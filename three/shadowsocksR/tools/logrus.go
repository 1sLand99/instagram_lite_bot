// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package tools

import "github.com/sirupsen/logrus"

func NewFatalLogger() *logrus.Logger {
	log := logrus.New()
	log.Level = logrus.FatalLevel
	return log
}
