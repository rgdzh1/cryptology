package util

import (
	"crypto/hmac"
	"crypto/sha512"
)
//消息认证码只能保证数据传输的完整性,但是无法确认数据到底是由谁发送的,因为通信双方都持有对称加密的秘钥,无法确认数据由谁发送.
//生成消息验证码
func GenerateHMAC(mes, key []byte) []byte {
	myHamc := hmac.New(sha512.New, key)
	myHamc.Write(mes)
	resulet := myHamc.Sum(nil)
	return resulet //消息认证码
}

//验证消息验证码
/**
	mes : 原消息
	result:消息验证码
	key:秘钥
 */
func VerifyHMAC(mes, result, key []byte) bool {
	myHmac := hmac.New(sha512.New, key)
	myHmac.Write(mes)
	result2 := myHmac.Sum(nil)
	return hmac.Equal(result, result2)
}
