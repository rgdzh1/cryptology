package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"crypto/sha512"
	"math/big"
)

//椭圆曲线签名

//秘钥生成
func GenerateEcckey() {
	//===========私钥生成
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//使用x509标准将是要格式化存储到磁盘本地
	ecPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	block := pem.Block{Bytes: ecPrivateKey, Type: "椭圆曲线秘钥"}
	file, err := os.Create("eccPrivate.pem")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	pem.Encode(file, &block)
	//==========公钥生成
	publicKey := privateKey.PublicKey
	//使用x509标准格式化公钥数据
	eccPublicKey, err := x509.MarshalPKIXPublicKey(&publicKey) //参数类型是地址值,需要追源码看一看
	if err != nil {
		panic(err)
	}
	block = pem.Block{Bytes: eccPublicKey, Type: "椭圆曲线私钥"}
	file, err = os.Create("eccPublic.pem")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	pem.Encode(file, &block)
}

//椭圆曲线私钥签名
func ECCSign(mess []byte, keyPath string) (str1, str2 []byte) {
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
	//x509格式化为私钥
	ecPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	hashText := sha512.Sum512(mess)
	r, s, e := ecdsa.Sign(rand.Reader, ecPrivateKey, hashText[:])
	if e != nil {
		panic(e)
	}
	rText, err := r.MarshalText()
	if err != nil {
		panic(err)
	}
	sText, err := s.MarshalText()
	if err != nil {
		panic(err)
	}
	return rText, sText
}

//椭圆曲线公钥签名认证
func EccVerify(mess, rText, sText []byte, keyPath string) bool {
	file, err := os.Open(keyPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, err := file.Stat()
	bytes := make([]byte, info.Size())
	file.Read(bytes)
	block, _ := pem.Decode(bytes)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	key := publicKey.(*ecdsa.PublicKey)
	hashText := sha512.Sum512(mess)
	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	verifyBool := ecdsa.Verify(key, hashText[:], &r, &s)
	return verifyBool
}
