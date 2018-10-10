package util

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"errors"
	"crypto/rsa"
)

//生成rsa的秘钥对,并且保存到磁盘文件中
func GenerateRsaKey(KeySize int) {
	generateKey, e := rsa.GenerateKey(rand.Reader, KeySize)
	if e != nil {
		panic(e)
	}
	//通过509标准得到ras撕咬序列化为ASN.1 的DER编码
	derText := x509.MarshalPKCS1PrivateKey(generateKey)
	block := pem.Block{
		Type:  "oklik",
		Bytes: derText,
	}
	//pem文件写入,编码
	file, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	pem.Encode(file, &block)

	//=========通过公钥生成私钥=========
	publicKey := generateKey.PublicKey
	derstrema, err := x509.MarshalPKIXPublicKey(&publicKey) //这个地方需要注意,是公钥的地址值,而不是值,因为go语言中没有提示
	if err != nil {
		panic(err)
	}
	block = pem.Block{
		Type:  "oklik",
		Bytes: derstrema,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	pem.Encode(file, &block)
}

//rsa公钥加密
func RsaEncrypter(keyFile, plainText string) string {
	file, err := os.Open(keyFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	bytes := make([]byte, fileInfo.Size())
	file.Read(bytes)
	block, _ := pem.Decode(bytes)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	key, bl := publicKey.(*rsa.PublicKey)
	if !bl {
		panic(errors.New("公钥断言错误"))
	}
	cipherText, e := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(plainText))
	if e != nil {
		panic(e)
	}
	return string(cipherText)
}

//Rsa私钥解密
func RsaDecrypter(privateKeyFile, cipherText string) string {
	file, err := os.Open(privateKeyFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	bytes := make([]byte, info.Size())
	file.Read(bytes)
	block, _ := pem.Decode(bytes)
	privateKey, e := x509.ParsePKCS1PrivateKey(block.Bytes)
	if e != nil {
		panic(e)
	}
	plaintText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, []byte(cipherText))
	if err != nil {
		panic(err)
	}
	return string(plaintText)
}

//func main() {
//	//GenerateRsaKey(4096) //如果rsa秘钥长度太短,加密信息长度太大,就会报错:message too long for RSA public key size
//	cipherText := RsaEncrypter("public.pem", "【环球网报道 记者 马丽】据日本中部电视台10月9日报道，日本爱知县小牧市一家化工厂7日黎明发生一场火灾，大火直至8日上午才被扑灭，历时32个小时。共有34辆消防车和急救车赶到现场抢救，一名消防员在火灾中受伤失火化工厂为3层结构。据警方透露，该工厂主要制造汽车上的塑料零配件。火灾发生时工厂里没有人")
//	fmt.Println(cipherText)
//	plainText := RsaDecrypter("private.pem", cipherText)
//	fmt.Println(plainText)
//}
