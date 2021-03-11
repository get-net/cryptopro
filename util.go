package cryptopro

/*
#cgo CFLAGS: -DUNIX -DHAVE_LIMITS_H -DSIZEOF_VOID_P=8 -I/opt/cprocsp/include/ -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/pki
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcapi20 -lcapi10
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <CSP_WinCrypt.h>
*/
import "C"
import (
	"unsafe"
)

func Decode(ptr unsafe.Pointer) (string, error) {
	sz := C.wcslen((C.LPWSTR)(ptr))

	size := C.WideCharToMultiByte(C.CP_UTF8, 0, (C.LPWSTR)(ptr), C.int(sz), nil, 0, nil, nil)
	if size == 0 {
		return "", GetLastError()
	}
	info := make([]byte, int(size))

	status := C.WideCharToMultiByte(C.CP_UTF8, 0, (C.LPWSTR)(ptr), C.int(sz), (*C.char)(unsafe.Pointer(&info[0])), size, nil, nil)
	if status == 0 {
		return "", GetLastError()
	}

	return string(info), nil
}
