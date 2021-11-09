package main

import (
	"unsafe"

	"github.com/sirupsen/logrus"
)

func main() {
	// var configJSONString string = "I'm the configJSON"
	// var configJSON []byte = []byte(configJSONString)
	var configJSON []byte
	configJSON = []byte{'I', '\'', 'm', ' ', 't', 'h', 'e', ' ', 'c', 'o', 'n', 'f', 'i', 'g', 'J', 'S', 'O', 'N'}
	lenConfigJSON := len(configJSON)
	unsafePointerConfigJSON := unsafe.Pointer(&configJSON)
	uintptrConfigJSON := (uintptr)(unsafePointerConfigJSON)
	logrus.Infof("configJSON直出：", configJSON)
	logrus.Infof("configJSON String：%s", configJSON)
	logrus.Infof("configJSON长度", lenConfigJSON)
	logrus.Infof("======================================")
	logrus.Infof("configJSON指向的地址： %p", configJSON)
	logrus.Infof("configJSON地址： %p", &configJSON)
	logrus.Infof("configJSON unsafe.Pointer 指向的地址： %p", unsafePointerConfigJSON)
	logrus.Infof("configJSON unsafe.Pointer 地址： %p", &unsafePointerConfigJSON)
	logrus.Infof("configJSON uintptr 指向的地址： %p", uintptrConfigJSON)
	logrus.Infof("configJSON uintptr 地址： %p", &uintptrConfigJSON)

	//执行系统调用
	// reta, _, _ := syscall.Syscall(335, uintptrConfigJSON, (uintptr)(unsafe.Pointer(&lenConfigJSON)), 0)
	// logrus.Infof("Process id: ", reta)
}
