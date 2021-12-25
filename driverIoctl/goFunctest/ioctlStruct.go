package main

import (
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

type diffIDListAndLengthStruct struct {
	ConfigJSON    string
	lenConfigJSON int
}

func main() {
	var diffIDListAndLength diffIDListAndLengthStruct
	var configJSONByte []byte
	var configJsonSourceStr string
	var DiffidListString string
	configJsonSourceStr = "{\"architecture\": \"amd64\", 	\"rootfs\": { 		\"type\": \"layers\", 		\"diff_ids\": [\"sha256:e81bff2725dbc0bf2003db10272fef362e882eb96353055778a66cda430cf81b\", \"sha256:43f4e41372e42dd32309f6a7bdce03cf2d65b3ca34b1036be946d53c35b503ab\", \"sha256:788e89a4d186f3614bfa74254524bc2e2c6de103698aeb1cb044f8e8339a90bd\", \"sha256:f8e880dfc4ef19e78853c3f132166a4760a220c5ad15b9ee03b22da9c490ae3b\", \"sha256:f7e00b807643e512b85ef8c9f5244667c337c314fa29572206c1b0f3ae7bf122\", \"sha256:9959a332cf6e41253a9cd0c715fa74b01db1621b4d16f98f4155a2ed5365da4a\"] 	} }"
	// configJSON = []byte{'I', '\'', 'm', ' ', 't', 'h', 'e', ' ', 'c', 'o', 'n', 'f', 'i', 'g', 'J', 'S', 'O', 'N'}
	configJSONByte = []byte(configJsonSourceStr)
	stringConfigJSON := *(*string)(unsafe.Pointer(&configJSONByte))

	rootfsDiff_ids := gjson.Get(stringConfigJSON, "rootfs.diff_ids")

	for i := 0; i < len(rootfsDiff_ids.Array()); i++ {
		if i != len(rootfsDiff_ids.Array())-1 {
			DiffidListString = DiffidListString + rootfsDiff_ids.Array()[i].String() + ","
		} else {
			DiffidListString = DiffidListString + rootfsDiff_ids.Array()[i].String()
		}
	}

	// diffIdDeep := len(rootfsDiff_ids.Array())

	diffIDListAndLength.ConfigJSON = DiffidListString
	diffIDListAndLength.lenConfigJSON = len(DiffidListString)

	// uintptrDiffidListString := (uintptr)(unsafe.Pointer(&DiffidListString))
	// DiffidListStringLen := len(DiffidListString)
	// uintptrDiffidListStringLen := (uintptr)(unsafe.Pointer(&DiffidListStringLen))

	fd, _ := syscall.Open("/dev/srtm", syscall.O_WRONLY, 0)

	logrus.Infof("======================================")
	logrus.Infof("diffIDListAndLength.ConfigJSON ： %s", diffIDListAndLength.ConfigJSON)
	logrus.Infof("diffIDListAndLength.lenConfigJSON ： %d", diffIDListAndLength.lenConfigJSON)
	logrus.Infof("diffIDListAndLength.lenConfigJSON ：", uintptr(unsafe.Pointer(&diffIDListAndLength)))
	logrus.Infof("======================================")
	//执行系统调用
	reta, _, _ := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(0xFFFB), uintptr(unsafe.Pointer(&diffIDListAndLength)))
	logrus.Infof("Process id: ", reta)
	syscall.Close(fd)
}
