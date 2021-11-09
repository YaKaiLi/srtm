package main

import (
	"fmt"
	"syscall"
)

func main() {
	reta, _, _ := syscall.Syscall(336, 0, 0, 0)
	fmt.Println("syscall return: ", reta)
}

//go run go_syscall_testgo.go
