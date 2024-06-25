// Please let author have a drink, usdt trc20: TEpSxaE3kexE4e5igqmCZRMJNoDiQeWx29
// tg: @fuckins996
package instagram

import "gorm.io/gorm"

type TableName struct {
	AccountTable string
}

func InitInstagram(accountDB *gorm.DB, tableName *TableName) {
	InitApiConfig("")
	InitDb(accountDB, tableName)
}
