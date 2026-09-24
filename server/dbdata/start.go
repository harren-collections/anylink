package dbdata

func Start() {
	initDb()
	initData()
	SyncLdapUsers()
}

func Stop() error {
	return xdb.Close()
}
