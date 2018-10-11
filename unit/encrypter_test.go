package unit

import (
	"Cryptology/util"
	"testing"
	"fmt"
)

func TestGenerateRsaKey(t *testing.T) {
	util.GenerateRsaKey(1024)
}

func TestRsaEncrypter(t *testing.T) {
	cipherText := util.RsaEncrypter("public.pem", "RsaEncrypterRsaEncrypterRsaEncrypterRsaEncrypterRsaEncrypterRsaEncrypterRsaEncrypter")
	t.Logf(cipherText)
	plainText := util.RsaDecrypter("private.pem", cipherText)
	t.Logf(plainText)
}

func TestHash(t *testing.T) {
	hash := util.Hash()
	t.Logf(hash)
}

func TestBigHash(t *testing.T) {
	bigFileHash := util.HashBigFile("hash.hash")
	t.Logf("%s", bigFileHash)
}

func TestDESEncrypt(t *testing.T) {
	//des 加密的秘钥长度是8字节
	cipherText := util.DesEncrypt([]byte("Go DES加密"), []byte("0000000-"))
	fmt.Println(string(cipherText))
	plainText := util.DesDecrypt(cipherText, []byte("0000000-"))
	fmt.Println(string(plainText))
}

func TestAESEncrypt(t *testing.T) {
	//aes 加密的秘钥长度为16字节
	cipherText := util.AesEncrypt([]byte("Go AES加密"), []byte("0000000-0000000-"))
	fmt.Println(string(cipherText))
	plainText := util.AesDecrypt(cipherText, []byte("0000000-0000000-"))
	fmt.Println(string(plainText))
}

//消息认证码测试
func TestMAC(t *testing.T) {
	generateHMAC := util.GenerateHMAC([]byte("明文"), []byte("秘钥"))
	macBool := util.VerifyHMAC([]byte("明文"), generateHMAC, []byte("秘钥"))
	fmt.Println(macBool)
}

//数字签名测试
func TestSign(t *testing.T) {
	signRsa := util.SignRsa([]byte("明文"), "private.pem")
	fmt.Println(signRsa)
	verifyRsa := util.VerifyRsa([]byte("明文"), signRsa, "public.pem")
	fmt.Println(verifyRsa)
}

//测试生成椭圆曲线秘钥
func TestEccKey(t *testing.T) {
	util.GenerateEcckey()
}

//测试椭圆曲线数字签名
func TestEccSign(t *testing.T) {
	str1, str2 := util.ECCSign([]byte("明文"), "eccPrivate.pem")
	verify := util.EccVerify([]byte("明文"), str1, str2, "eccPublic.pem")
	fmt.Println(verify)
}
