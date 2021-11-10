package main

import (
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
)

func main() {
	// var configJSONString string = "I'm the configJSON"
	// var configJSON []byte = []byte(configJSONString)
	var configJSON []byte
	configJSON = []byte{'I', '\'', 'm', ' ', 't', 'h', 'e', ' ', 'c', 'o', 'n', 'f', 'i', 'g', 'J', 'S', 'O', 'N'}
	unsafePointerConfigJSON := unsafe.Pointer(&configJSON)
	uintptrConfigJSON := (uintptr)(unsafePointerConfigJSON)

	ConfigJSONlen := len(configJSON)
	unsafePointerConfigJSONlen := unsafe.Pointer(&ConfigJSONlen)
	uintptrConfigJSONlen := (uintptr)(unsafePointerConfigJSONlen)
	logrus.Infof("configJSON直出：", configJSON)
	logrus.Infof("configJSON String：%s", configJSON)
	logrus.Infof("configJSONlen 直出", ConfigJSONlen)
	logrus.Infof("======================================")
	logrus.Infof("configJSON指向的地址： %p", configJSON)
	logrus.Infof("configJSON地址： %p", &configJSON)
	logrus.Infof("configJSON unsafe.Pointer 指向的地址： %p", unsafePointerConfigJSON)
	logrus.Infof("configJSON unsafe.Pointer 地址： %p", &unsafePointerConfigJSON)
	logrus.Infof("configJSON uintptr 指向的地址： %p", uintptrConfigJSON)
	logrus.Infof("configJSON uintptr 大小： %d", unsafe.Sizeof(uintptrConfigJSON)) //uintptr占用8字节
	logrus.Infof("configJSON uintptr 地址： %p", &uintptrConfigJSON)
	logrus.Infof("======================================")
	logrus.Infof("configJSONlen 地址： %p", &ConfigJSONlen)
	logrus.Infof("configJSONlen unsafe.Pointer 指向的地址： %p", unsafePointerConfigJSONlen)
	logrus.Infof("configJSONlen unsafe.Pointer 地址： %p", &unsafePointerConfigJSONlen)
	logrus.Infof("configJSONlen uintptr 指向的地址： %p", uintptrConfigJSONlen)
	logrus.Infof("configJSONlen uintptr 大小： %d", unsafe.Sizeof(uintptrConfigJSONlen)) //uintptr占用8字节
	logrus.Infof("configJSONlen uintptr 地址： %p", &uintptrConfigJSONlen)

	//执行系统调用
	reta, _, _ := syscall.Syscall(335, uintptrConfigJSON, uintptrConfigJSONlen, 0)
	logrus.Infof("Process id: ", reta)
}
