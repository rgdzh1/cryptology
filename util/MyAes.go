package util

import (
	"bytes"
	"crypto/des"
	"crypto/cipher"
	"crypto/aes"
)

func paddingLastGroup(plainText []byte, blockSize int) []byte {
	padNum := blockSize - len(plainText)%blockSize
	char := []byte{byte(padNum)}
	newPlain := bytes.Repeat(char, padNum)
	newText := append(plainText, newPlain...)
	return newText
}
func unPaddingLastGroup(plainText []byte) []byte {
	length := len(plainText)
	lastChar := plainText[length-1]
	number := int(lastChar)
	return plainText[:length-number]
}

//des加密 分组模式 CBC
func DesEncrypt(plainText, key []byte) []byte {
	block, e := des.NewCipher(key)
	if e != nil {
		panic(e)
	}
	//明文填充
	newText := paddingLastGroup(plainText, block.BlockSize())
	//创建一个使用cbc分组接口
	iv := []byte("12345678") //长度为8字节的向量值,可以生成随机数
	blockMode := cipher.NewCBCEncrypter(block, iv)
	//加密
	cipherText := make([]byte, len(newText))
	blockMode.CryptBlocks(cipherText, newText)
	return cipherText
}

//des解密 分组模式 CBC
func DesDecrypt(cipherText, key []byte) []byte {
	block, e := des.NewCipher(key)
	if e != nil {
		panic(e)
	}
	//创建向量
	iv := []byte("12345678")
	blockMode := cipher.NewCBCDecrypter(block, iv)
	//解密
	plainText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainText, cipherText)
	newPlainText := unPaddingLastGroup(plainText)
	return newPlainText
}

//aes 加密 分组模式 CRT
func AesEncrypt(plainText, key []byte) []byte {
	block, e := aes.NewCipher(key)
	if e != nil {
		panic(e)
	}
	// 创建一个使用ctr分组接口
	iv := []byte("1234567890qweasd") //16字节向量
	stream := cipher.NewCTR(block, iv)
	//加密
	cipherText := make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)
	return cipherText
}

//aes 解密 分组模式 CRT
func AesDecrypt(ciperText, key []byte) []byte {
	block, e := aes.NewCipher(key)
	if e != nil {
		panic(e)
	}
	iv := []byte("1234567890qweasd") //16字节向量
	stream := cipher.NewCTR(block, iv)
	plainText := make([]byte, len(ciperText))
	stream.XORKeyStream(plainText, ciperText)
	return plainText
}
