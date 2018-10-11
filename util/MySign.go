package util

import (
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/sha512"
	"crypto/rsa"
	"crypto/rand"
	"crypto"
)

//数字签名,可以解决通信双方数据由谁发送的问题.因为签名是非对称加密,公钥或者私钥只能是某一方持有.
//Rsa签名 私钥
func SignRsa(mess []byte, keyPath string) []byte {
	file, e := os.Open(keyPath)
	if e != nil {
		panic(e)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	bytes := make([]byte, info.Size())
	file.Read(bytes)
	block, _ := pem.Decode(bytes)
	//按照X509标准,将数据解析成私钥结构体
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	myHash := sha512.New()
	myHash.Write(mess)
	hashResult := myHash.Sum(nil)
	signText, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashResult)
	if err != nil {
		panic(err)
	}
	return signText
}

//Rsa签名认证 公钥
func VerifyRsa(mess, signText []byte, keyPath string) bool {
	file, err := os.Open(keyPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	bytes := make([]byte, info.Size())
	file.Read(bytes)
	block, _ := pem.Decode(bytes)
	//x509标准将数据格式化为公钥
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	key := publicKey.(*rsa.PublicKey)
	myHash := sha512.New()
	myHash.Write(mess)
	hashText := myHash.Sum(nil)
	signErr := rsa.VerifyPKCS1v15(key, crypto.SHA512, hashText, signText)
	if signErr != nil {
		return false
	} else {
		return true
	}
}
