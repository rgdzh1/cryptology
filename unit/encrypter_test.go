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
