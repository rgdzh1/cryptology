package util

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"io"
	"fmt"
)

func Hash() string {
	sum512 := sha512.Sum512([]byte("这些hash值是多少"))
	hash := hex.EncodeToString(sum512[:])
	return hash
}

func HashBigFile(fileName string) string {
	file, e := os.Open(fileName)
	if e != nil {
		panic(e)
	}
	defer file.Close()
	hash := sha512.New()
	bytes := make([]byte, 1024*10)
	for {
		n, err := file.Read(bytes)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			fmt.Println("文件读取完成")
			break
		}
		hash.Write(bytes[:n])
	}
	sumBytes := hash.Sum(nil)
	hashStr := hex.EncodeToString(sumBytes[:])
	return hashStr
}
