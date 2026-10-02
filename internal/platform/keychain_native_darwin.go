//go:build darwin && cgo

package platform

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static OSStatus claude_accounts_update(const char *service, const char *account,
                                       const void *data, uint32_t length, int *stage) {
    SecKeychainItemRef item = NULL;
    *stage = 1;
    OSStatus status = SecKeychainFindGenericPassword(NULL,
        (UInt32)strlen(service), service, (UInt32)strlen(account), account,
        NULL, NULL, &item);
    if (status != errSecSuccess) return status;
    *stage = 2;
    status = SecKeychainItemModifyContent(item, NULL, length, data);
    CFRelease(item);
    return status;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

func nativeKeychainWrite(service, account string, b []byte) error {
	if strings.ContainsRune(service, 0) || strings.ContainsRune(account, 0) || len(b) == 0 || uint64(len(b)) > uint64(^uint32(0)) {
		return errors.New("invalid native Keychain input")
	}
	cs, ca := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	data := C.CBytes(b)
	defer func() { C.memset(data, 0, C.size_t(len(b))); C.free(data) }()
	var stage C.int
	status := C.claude_accounts_update(cs, ca, data, C.uint32_t(len(b)), &stage)
	if status != 0 {
		return fmt.Errorf("native Keychain operation failed (stage %d, status %d)", int(stage), int32(status))
	}
	return nil
}
