package main

import (
	"fmt"
	"os"
	"time"
)

func writeFile() {
	f, err := os.OpenFile("test.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.WriteString(time.Now().String())
}

func main() {
	fmt.Println("当前PID是：", os.Getpid())
	for {
		writeFile()
		fmt.Println("成功写入 休眠5S", time.Now())
		time.Sleep(time.Second * 5)
	}
}
