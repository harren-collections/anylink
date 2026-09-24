package dbdata

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/pkg/utils"
	"github.com/go-ldap/ldap"
	"github.com/xlzd/gotp"
)

type AuthLdap struct {
	Addr           string `json:"addr"`
	Tls            bool   `json:"tls"`
	BindName       string `json:"bind_name"`
	BindPwd        string `json:"bind_pwd"`
	BaseDn         string `json:"base_dn"`
	ObjectClass    string `json:"object_class"`
	SearchAttr     string `json:"search_attr"`
	MemberOf       string `json:"member_of"`
	EnableOTP      bool   `json:"enable_otp"`
	SyncUserStatus bool   `json:"sync_user_status"`
}

func init() {
	authRegistry["ldap"] = reflect.TypeOf(AuthLdap{})
}

// 建立 LDAP 连接
func (auth AuthLdap) Connect() (*ldap.Conn, error) {
	// 检测服务器和端口的可用性
	con, err := net.DialTimeout("tcp", auth.Addr, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("LDAP服务器连接异常, 请检测服务器和端口: %s", err.Error())
	}
	con.Close()

	// 连接LDAP
	l, err := ldap.Dial("tcp", auth.Addr)
	if err != nil {
		return nil, fmt.Errorf("LDAP连接失败 %s %s", auth.Addr, err.Error())
	}

	if auth.Tls {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("LDAP TLS连接失败 %s", err.Error())
		}
	}

	err = l.Bind(auth.BindName, auth.BindPwd)
	if err != nil {
		return nil, fmt.Errorf("LDAP 管理员 DN或密码填写有误 %s", err.Error())
	}

	return l, nil
}

// 构建LDAP搜索过滤器
func (auth AuthLdap) SearchFilter(username string) string {
	filterAttr := "(objectClass=" + auth.ObjectClass + ")"

	if username != "" {
		filterAttr += "(" + auth.SearchAttr + "=" + username + ")"
	} else {
		filterAttr += "(" + auth.SearchAttr + "=*)"
	}

	if auth.MemberOf != "" {
		filterAttr += "(memberOf:=" + auth.MemberOf + ")"
	}

	return fmt.Sprintf("(&%s)", filterAttr)
}

// 从组配置中解析LDAP认证配置
func (auth *AuthLdap) ParseGroup(g *Group) error {
	authType := g.Auth["type"].(string)
	if _, ok := g.Auth[authType]; !ok {
		return fmt.Errorf("LDAP的ldap值不存在")
	}

	bodyBytes, err := json.Marshal(g.Auth[authType])
	if err != nil {
		return fmt.Errorf("LDAP Marshal出现错误: %s", err.Error())
	}

	err = json.Unmarshal(bodyBytes, auth)
	if err != nil {
		return fmt.Errorf("LDAP Unmarshal出现错误: %s", err.Error())
	}

	// 设置默认值
	if auth.ObjectClass == "" {
		auth.ObjectClass = "person"
	}

	return nil
}

// 搜索用户
func (auth AuthLdap) SearchUsers(l *ldap.Conn, username string, attributes []string) (*ldap.SearchResult, error) {
	filter := auth.SearchFilter(username)
	// 创建分页控制，每页1000条记录
	pagingControl := ldap.NewControlPaging(100)

	searchRequest := ldap.NewSearchRequest(
		auth.BaseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		filter,
		attributes,
		[]ldap.Control{pagingControl}, // 添加分页控制
	)

	// 使用分页搜索
	sr, err := l.SearchWithPaging(searchRequest, 100)
	if err != nil {
		return nil, fmt.Errorf("LDAP 查询失败 %s %s %s", auth.BaseDn, filter, err.Error())
	}

	return sr, nil
}

func (auth AuthLdap) SaveUsers(g *Group) error {
	// 解析LDAP配置
	if err := auth.ParseGroup(g); err != nil {
		return fmt.Errorf("LDAP配置填写有误: %s", err.Error())
	}

	// 建立LDAP连接
	l, err := auth.Connect()
	if err != nil {
		return err
	}
	defer l.Close()

	// 搜索所有用户
	sr, err := auth.SearchUsers(l, "", []string{
		"displayName",
		"mail",
		"userAccountControl", // AD用户状态
		"accountExpires",     // AD账号过期时间
		"shadowExpire",       // Linux LDAP用户状态
		auth.SearchAttr,
	})
	if err != nil {
		return err
	}
	// 创建LDAP用户映射
	ldapUserMap := make(map[string]bool)
	// 处理搜索结果
	for _, entry := range sr.Entries {
		if auth.SyncUserStatus {
			// 检查用户状态，只同步正常用户
			if err := parseEntries(&ldap.SearchResult{Entries: []*ldap.Entry{entry}}); err != nil {
				continue
			}
		}
		var groups []string
		ldapuser := &User{
			Type:       "ldap",
			Username:   entry.GetAttributeValue(auth.SearchAttr),
			Nickname:   entry.GetAttributeValue("displayName"),
			Email:      entry.GetAttributeValue("mail"),
			Groups:     append(groups, g.Name),
			DisableOtp: !auth.EnableOTP,
			OtpSecret:  gotp.RandomSecret(32),
			SendEmail:  false,
			Status:     1,
		}
		ldapUserMap[ldapuser.Username] = true // 添加LDAP用户到映射中
		// 新增或更新ldap用户
		u := &User{}
		if err := One("username", ldapuser.Username, u); err != nil {
			if CheckErrNotFound(err) {
				if err := Add(ldapuser); err != nil {
					base.Error("新增ldap用户失败", ldapuser.Username, err)
					continue
				}
				continue
			}
			base.Error("查询用户失败", ldapuser.Username, err)
			continue
		}
		if u.Type != "ldap" {
			base.Warn("已存在本地同名用户:", ldapuser.Username)
			continue
		}
		// 现有LDAP用户，更新字段
		u.Nickname = entry.GetAttributeValue("displayName")
		u.DisableOtp = !auth.EnableOTP
		if u.OtpSecret == "" {
			u.OtpSecret = gotp.RandomSecret(32)
		}
		if u.Email == "" {
			u.Email = entry.GetAttributeValue("mail")
		}
		if !utils.InArrStr(u.Groups, g.Name) {
			u.Groups = append(u.Groups, g.Name)
		}

		if err := Set(u); err != nil {
			return fmt.Errorf("更新ldap用户%s失败:%v", u.Username, err.Error())
		}
	}
	// 查询本地LDAP用户
	var localLdapUsers []User
	if err := FindWhere(&localLdapUsers, 0, 0, "type = 'ldap'"); err != nil {
		base.Error("查询本地LDAP用户失败:", err)
		return nil
	}

	// 删除LDAP中不存在的本地用户
	for _, localUser := range localLdapUsers {
		// 确保只处理属于当前组的本地用户
		if !utils.InArrStr(localUser.Groups, g.Name) {
			continue
		}
		// 如果用户不在 ldapUserMap 中，则执行删除或组移除操作。
		if !ldapUserMap[localUser.Username] {
			// 从用户的组列表中移除当前组
			localUser.Groups = utils.RemoveStrFromArr(localUser.Groups, g.Name)
			if len(localUser.Groups) == 0 {
				// 如果移除当前组后，用户不再属于任何组，则执行完整删除。
				if err := Del(&localUser); err != nil {
					base.Error("删除本地LDAP用户失败:", localUser.Username, err)
				} else {
					base.Info("成功删除本地LDAP用户:", localUser.Username)
				}
			} else {
				// 如果用户仍属于其他组，则更新 Groups 字段。
				if err := Set(&localUser); err != nil {
					base.Error("更新用户组失败:", localUser.Username, err)
				} else {
					base.Info("成功从组 '"+g.Name+"' 移除用户:", localUser.Username)
				}
			}
		}
	}
	return nil
}

func (auth AuthLdap) checkData(authData map[string]interface{}) error {
	authType := authData["type"].(string)
	bodyBytes, err := json.Marshal(authData[authType])
	if err != nil {
		return errors.New("LDAP配置填写有误")
	}
	json.Unmarshal(bodyBytes, &auth)
	// 支持域名和IP, 必须填写端口
	if !ValidateIpPort(auth.Addr) && !ValidateDomainPort(auth.Addr) {
		return errors.New("LDAP的服务器地址(含端口)填写有误")
	}
	if auth.BindName == "" {
		return errors.New("LDAP的管理员 DN不能为空")
	}
	if auth.BindPwd == "" {
		return errors.New("LDAP的管理员密码不能为空")
	}
	if auth.BaseDn == "" || !ValidateDN(auth.BaseDn) {
		return errors.New("LDAP的Base DN填写有误")
	}
	if auth.ObjectClass == "" {
		return errors.New("LDAP的用户对象类填写有误")
	}
	if auth.SearchAttr == "" {
		return errors.New("LDAP的用户唯一ID不能为空")
	}
	if auth.MemberOf != "" && !ValidateDN(auth.MemberOf) {
		return errors.New("LDAP的受限用户组填写有误")
	}
	return nil
}

func (auth AuthLdap) checkUser(name, pwd string, g *Group, ext map[string]interface{}) error {
	if name == "" || len(pwd) < 1 {
		return fmt.Errorf("%s %s", name, "密码错误")
	}
	// 解析LDAP配置
	if err := auth.ParseGroup(g); err != nil {
		return fmt.Errorf("%s %s", name, err.Error())
	}
	// 建立LDAP连接
	l, err := auth.Connect()
	if err != nil {
		return fmt.Errorf("%s %s", name, err.Error())
	}
	defer l.Close()
	// 搜索特定用户
	sr, err := auth.SearchUsers(l, name, []string{})
	if err != nil {
		return fmt.Errorf("%s %s", name, err.Error())
	}
	// 验证搜索结果
	if len(sr.Entries) != 1 {
		if len(sr.Entries) == 0 {
			return fmt.Errorf("LDAP 找不到 %s 用户, 请检查用户或LDAP配置参数", name)
		}
		return fmt.Errorf("LDAP发现 %s 用户，存在多个账号", name)
	}
	// 检查账号状态
	err = parseEntries(sr)
	if err != nil {
		return fmt.Errorf("LDAP %s 用户 %s", name, err.Error())
	}
	// 验证用户密码
	userDN := sr.Entries[0].DN
	err = l.Bind(userDN, pwd)
	if err != nil {
		return fmt.Errorf("%s LDAP 登入失败，请检查登入的账号或密码 %s", name, err.Error())
	}
	return nil
}

func parseEntries(sr *ldap.SearchResult) error {
	// Active Directory用户状态属性
	const (
		ACCOUNTDISABLE = 2  // 账户已禁用
		LOCKOUT        = 16 // 账户被锁定
	// 	PASSWD_NOTREQD       = 32     // 不需要密码
	// 	PASSWD_CANT_CHANGE   = 64     // 不能更改密码
	// 	NORMAL_ACCOUNT       = 512    // 普通用户账户
	// 	DONT_EXPIRE_PASSWORD = 65536  // 密码永不过期
	// 	PASSWORD_EXPIRED     = 8388608	// 密码已过期
	)
	for _, attr := range sr.Entries[0].Attributes {
		switch attr.Name {
		case "userAccountControl": // Active Directory用户状态属性
			if len(attr.Values) > 0 {
				val, err := strconv.ParseInt(attr.Values[0], 10, 64)
				if err != nil {
					return fmt.Errorf("无法解析userAccountControl值: %v", err)
				}
				// 使用Active Directory标志位字段判断用户是否正常
				if (val & LOCKOUT) != 0 {
					return fmt.Errorf("账号已被锁定")
				}
				if (val & ACCOUNTDISABLE) != 0 {
					return fmt.Errorf("账号已禁用")
				}
			}
		case "accountExpires": // Active Directory账号过期时间
			if len(attr.Values) > 0 {
				val, err := strconv.ParseInt(attr.Values[0], 10, 64)
				if err != nil {
					base.Debug("无法解析accountExpires值:", err)
					continue
				}
				// 0 = 永远不过期
				// 9223372036854775807 = 永远不会过期
				if val > 0 && val < 9223372036854775807 {
					expireTime := time.Unix((val-116444736000000000)/10000000, 0)
					if expireTime.Before(time.Now()) {
						return fmt.Errorf("账号已过期(过期时间: %s)", expireTime.Format("2006-01-02 15:04:05"))
					}
				}
			}
		case "shadowExpire":
			// -1 启用, 1 停用, >1 从1970-01-01至到期日的天数
			val, _ := strconv.ParseInt(attr.Values[0], 10, 64)
			if val == -1 {
				return nil
			}
			if val == 1 {
				return fmt.Errorf("账号已停用")
			}
			if val > 1 {
				expireTime := time.Unix(val*86400, 0)
				t := time.Date(expireTime.Year(), expireTime.Month(), expireTime.Day(), 23, 59, 59, 0, time.Local)
				if t.Before(time.Now()) {
					return fmt.Errorf("账号已过期(过期日期: %s)", t.Format("2006-01-02"))
				}
				return nil
			}
			return fmt.Errorf("账号shadowExpire值异常: %d", val)
		}
	}
	return nil
}

func ValidateDomainPort(addr string) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[A-Za-z]{2,18}\:([0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-5]{2}[0-3][0-5])$`)
	return re.MatchString(addr)
}

func ValidateDN(dn string) bool {
	re := regexp.MustCompile(`^(?:(?:CN|cn|OU|ou|DC|dc)\=[^,'"]+,)*(?:CN|cn|OU|ou|DC|dc)\=[^,'"]+$`)
	return re.MatchString(dn)
}

// 同步所有合法ldap用户
func SyncLdapUsers() {
	if !base.Cfg.SyncLdapUsers {
		return
	}
	groups, err := GetAllGroups()
	if err != nil {
		base.Error("获取所有组失败:", err)
		return
	}
	for _, g := range groups {
		if g.Auth["type"] == "ldap" {
			authLdap := AuthLdap{}
			if err := authLdap.ParseGroup(&g); err != nil {
				base.Error("解析LDAP配置失败:", g.Name, err)
				continue
			}
			go func(g Group, authldap AuthLdap) {
				if err := authldap.SaveUsers(&g); err != nil {
					base.Error("LDAP 自动同步失败", g.Name, err)
				} else {
					base.Info("LDAP用户同步成功", g.Name)
				}
			}(g, authLdap)
		}
	}
}
