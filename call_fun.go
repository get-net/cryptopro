package cryptopro

import "C"
import (
	"fmt"
	"unsafe"
)

//export getBytes
func getBytes(pvArg unsafe.Pointer, pbData *C.char, cbData C.uint, final C.int) C.int {

	//	file := C.GoString((*C.char)(pvArg))
	test := C.GoBytes(unsafe.Pointer(pbData), C.int(cbData))
	handle.Write(test)
	if final != 1 {
		fmt.Println("New run ===")
		//		fmt.Printf("got file %s\n", file)
		//		fmt.Printf("got len %d\n", cbData)
		//		fmt.Printf("got bytes %+v\n", test)
	} else {
		fmt.Println("End file ===")
		handle.Close()
	}
	fmt.Printf("got final %d\n", final)
	return 1
}
