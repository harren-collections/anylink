package dbdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

type AuthWXwork struct {
	CorpId             string `json:"corp_id"`
	AgentId            string `json:"agent_id"`
	Secret             string `json:"secret"`
	UseDefaultBrowser  bool   `json:"use_default_browser"` // 是否使用默认浏览器（true=默认浏览器, false=内置浏览器）
	AllowedDepartments string `json:"allowed_departments"` // 允许登录的部门ID列表，如果为空则不限制
}

func init() {
	authRegistry["wxwork"] = reflect.TypeOf(AuthWXwork{})
}

// 验证企微配置参数
func (auth AuthWXwork) checkData(authData map[string]interface{}) error {
	authType := authData["type"].(string)
	bodyBytes, err := json.Marshal(authData[authType])
	if err != nil {
		return errors.New("企微配置填写有误")
	}
	json.Unmarshal(bodyBytes, &auth)

	if auth.CorpId == "" {
		return errors.New("企微的企业ID不能为空")
	}
	if auth.AgentId == "" {
		return errors.New("企微的应用ID不能为空")
	}
	if auth.Secret == "" {
		return errors.New("企微的应用Secret不能为空")
	}
	if auth.AllowedDepartments != "" {
		parts := strings.SplitSeq(auth.AllowedDepartments, ",")
		for part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				if _, err := strconv.Atoi(part); err != nil {
					return errors.New("部门ID必须为数字，用逗号分隔")
				}
			}
		}
	}
	return nil
}

// 企微用户验证逻辑
func (auth AuthWXwork) checkUser(name, pwd string, g *Group, ext map[string]interface{}) error {
	// 这里的 name 实际上是从企微回调中获取的 code
	// pwd 参数在企微认证中不使用
	// Todo: 占位函数，后续可优化完善统一用户验证逻辑
	// 该逻辑在当前SAML 认证中未使用！！！！
	authType := g.Auth["type"].(string)
	if _, ok := g.Auth[authType]; !ok {
		return fmt.Errorf("%s %s", name, "企微配置中不存在该类型")
	}

	body, err := json.Marshal(g.Auth[authType])
	if err != nil {
		return fmt.Errorf("%s %s", name, err.Error())
	}

	err = json.Unmarshal(body, &auth)
	if err != nil {
		return fmt.Errorf("%s %s", name, err.Error())
	}

	// 通过企微 API 获取用户信息
	userID, err := auth.GetWeworkUser(auth.CorpId, auth.Secret, name) // 这里的 name 实际上是从企微回调中获取的 code
	if err != nil {
		return fmt.Errorf("企微用户信息获取失败: %s", err.Error())
	}

	// 验证用户是否有效
	if userID == "" {
		return fmt.Errorf("企微用户ID为空")
	}

	return nil
}

type WXworkError struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// 企微获取AccessToken API 响应结构
type WXworkTokenResponse struct {
	WXworkError
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// 企微用户ID信息
type WXworkUserResponse struct {
	WXworkError
	UserID     string `json:"userid"`
	Name       string `json:"name"`
	Department []int  `json:"department"` // 成员所属部门id列表
}

// 获取企微访问令牌
func (auth AuthWXwork) getAccessToken(CorpID, Secret string) (string, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s", CorpID, Secret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	tokenResp := &WXworkTokenResponse{}
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", err
	}

	if tokenResp.ErrCode != 0 {
		return "", fmt.Errorf("获取访问令牌失败: %s", tokenResp.ErrMsg)
	}

	return tokenResp.AccessToken, nil
}

// 通过 code 获取企微用户信息
func (auth AuthWXwork) GetWeworkUser(CorpID, Secret, code string) (string, error) {
	// 获取访问令牌
	accessToken, err := auth.getAccessToken(CorpID, Secret)
	if err != nil {
		return "", err
	}

	// 通过 code 获取用户信息
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=%s&code=%s", accessToken, code)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	userInfo := &WXworkUserResponse{}
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return "", err
	}

	if userInfo.ErrCode != 0 {
		return "", fmt.Errorf("获取用户信息失败: %s", userInfo.ErrMsg)
	}

	// 检查用户是否属于允许的部门
	allowedDepts := auth.parseDepartments()
	if len(allowedDepts) > 0 {
		// 检查用户部门是否在允许范围内
		ok, err := auth.CheckUserDepartment(accessToken, userInfo.UserID, allowedDepts)
		if err != nil {
			return "", fmt.Errorf("验证用户部门失败: %w", err)
		}
		if !ok {
			return "", fmt.Errorf("用户部门不在允许范围内，允许的部门: %v", allowedDepts)
		}
	}
	return userInfo.UserID, nil
}

// 解析部门字符串为整数数组
func (auth AuthWXwork) parseDepartments() []int {
	if auth.AllowedDepartments == "" {
		return nil
	}
	parts := strings.Split(auth.AllowedDepartments, ",")
	var depts []int
	for _, part := range parts {
		if id, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && id > 0 {
			depts = append(depts, id)
		}
	}
	return depts
}

// 检查用户部门是否在允许范围内
func (auth AuthWXwork) CheckUserDepartment(accessToken, userID string, allowedDepts []int) (bool, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	// 获取用户详细信息，包括部门
	detailUrl := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=%s&userid=%s", accessToken, userID)

	detailResp, err := client.Get(detailUrl)
	if err != nil {
		return false, err
	}
	defer detailResp.Body.Close()

	detailBody, err := io.ReadAll(detailResp.Body)
	if err != nil {
		return false, err
	}

	detailedUserInfo := &WXworkUserResponse{}
	err = json.Unmarshal(detailBody, &detailedUserInfo)
	if err != nil {
		return false, err
	}

	if detailedUserInfo.ErrCode != 0 {
		return false, fmt.Errorf("获取用户详细信息失败: %s", detailedUserInfo.ErrMsg)
	}

	// 检查用户所属部门是否在允许列表中
	for _, userDept := range detailedUserInfo.Department {
		if slices.Contains(allowedDepts, userDept) {
			return true, nil
		}
	}

	return false, nil
}

// GetAuthWework 从组配置中获取企微认证配置
func GetAuthWework(groupName string) (*AuthWXwork, error) {
	// 获取组配置信息
	groupData := &Group{}
	if err := One("Name", groupName, groupData); err != nil {
		return nil, fmt.Errorf("用户组错误: %v", err)
	}

	// 检查认证类型
	authType, ok := groupData.Auth["type"].(string)
	if !ok || authType != "wxwork" {
		return nil, fmt.Errorf("该组未配置企微认证")
	}

	// 获取企微配置
	config, exists := groupData.Auth["wxwork"]
	if !exists {
		return nil, fmt.Errorf("企微配置不存在")
	}

	wxworkConfig, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("企微配置格式错误")
	}

	// 解析配置到结构体
	authwxwork := &AuthWXwork{}
	body, err := json.Marshal(wxworkConfig)
	if err != nil {
		return nil, fmt.Errorf("企微配置序列化失败: %v", err)
	}

	if err := json.Unmarshal(body, authwxwork); err != nil {
		return nil, err
	}

	// 验证配置完整性
	if authwxwork.CorpId == "" || authwxwork.AgentId == "" || authwxwork.Secret == "" {
		return nil, fmt.Errorf("企微配置不完整: CorpId=%s, AgentId=%s, Secret=%s", authwxwork.CorpId, authwxwork.AgentId, authwxwork.Secret)
	}

	return authwxwork, nil
}
