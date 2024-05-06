package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	// msf生成的go shellcode
	buf :=  []byte{};

	fmt.Println("原来的数据:", buf)

	// 异或加密
	xorData := Xor(buf)
	fmt.Println("异或加密后数据:", xorData)

	// base64加密
	base64Data := base64.StdEncoding.EncodeToString(xorData)
	fmt.Println("base64加密后数据:", base64Data)

	// 密钥
	key := AesKey()
	AesData := AesEncryptByECB(base64Data, key)
	fmt.Println("密钥:", key)
	fmt.Println("Aes加密后数据:", AesData)

	err := writeToFile("1.txt", AesData)
	if err != nil {
		fmt.Println("加密数据写入文件失败:", err)
		return
	}

	err1 := writeToFile("key.txt", key)
	if err1 != nil {
		fmt.Println("密钥写入文件失败:", err1)
		return
	}

	fmt.Println("key与加密数据已写入文件！请妥善保存！")

}

func Xor(buf []byte) []byte {
	xorBuf := make([]byte, len(buf))
	for i := 0; i < len(buf); i++ {
		xorBuf[i] = buf[i] ^ 0x33
	}
	return xorBuf
}

func AesKey() string {
	// 生成AES密钥
	key := make([]byte, 16) // 128位密钥
	if _, err := rand.Read(key); err != nil {
		panic(err.Error())
	}

	// 将密钥转换为十六进制格式进行打印
	keyHex := hex.EncodeToString(key)
	return keyHex
}

func AesEncryptByECB(data, key string) string {
	// 判断key长度
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
	}
	// 密钥和待加密数据转成[]byte
	originByte := []byte(data)
	keyByte := []byte(key)
	// 创建密码组，长度只能是16、24、32字节
	block, _ := aes.NewCipher(keyByte)
	// 获取密钥长度
	blockSize := block.BlockSize()
	// 补码
	originByte = PKCS7Padding(originByte, blockSize)
	// 创建保存加密变量
	encryptResult := make([]byte, len(originByte))
	// CEB是把整个明文分成若干段相同的小段，然后对每一小段进行加密
	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encryptResult[bs:be], originByte[bs:be])
	}
	return base64.StdEncoding.EncodeToString(encryptResult)
}

func PKCS7Padding(originByte []byte, blockSize int) []byte {
	// 计算补码长度
	padding := blockSize - len(originByte)%blockSize
	// 生成补码
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	// 追加补码
	return append(originByte, padText...)
}

func writeToFile(filename, text string) error {
	// 创建或打开文件，以只写方式打开，如果文件存在则清空内容
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("close file error:", err)
		}
	}(file)

	// 写入文本到文件
	_, err = file.WriteString(text)
	if err != nil {
		return err
	}

	return nil
}
