// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package proxys

type Provider interface {
	GetProxy(region string, asn string) Proxy
}
