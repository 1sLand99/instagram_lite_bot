// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package facebook

import "gorm.io/gorm"

type TableName struct {
	AccountTable string
}

func InitFacebook(accountDB *gorm.DB, tableName *TableName) {
	InitApiConfig("")
	InitDb(accountDB, tableName)
}
