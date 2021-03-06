package util

import (
	"encoding/json"
	"fmt"
)

// CommonError 微信返回的通用错误json
type CommonError struct {
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// DecodeWithCommonError 将返回值按照CommonError解析
func DecodeWithCommonError(response []byte, apiName string) (err error) {
	var commError CommonError
	err = json.Unmarshal(response, &commError)
	if err != nil {
		return
	}
	if commError.ErrCode != 0 {
		return fmt.Errorf("%s Error , errcode=%d , errmsg=%s", apiName, commError.ErrCode, commError.ErrMsg)
	}
	return nil
}

// Error 返回错误信息
func (c CommonError) Err() error {
	if c.ErrCode > 0 {
		return fmt.Errorf("[%v] %s", c.ErrCode, c.ErrMsg)
	}
	return nil
}

// IsInvalidCredential ...
func (c CommonError) IsInvalidCredential() bool {
	return c.ErrCode == 40001
}
