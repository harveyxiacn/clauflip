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
    SecAccessRef original = NULL, current = NULL;
    CFArrayRef oldPartitions = NULL, newPartitions = NULL;
    *stage = 2;
    status = SecKeychainItemCopyAccess(item, &original);
    if (status != errSecSuccess) goto cleanup;
    oldPartitions = SecAccessCopyMatchingACLList(original, kSecACLAuthorizationPartitionID);
    if (!oldPartitions) { status = errSecAllocate; goto cleanup; }
    // Check that every entry can be copied before changing credential data.
    for (CFIndex n = 0; n < CFArrayGetCount(oldPartitions); n++) {
        CFArrayRef apps = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt;
        status = SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(oldPartitions, n),
                                   &apps, &description, &prompt);
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 3;
    status = SecKeychainItemModifyContent(item, NULL, length, data);
    if (status != errSecSuccess) goto cleanup;
    // A data update creates a fresh integrity ACL and caller partition ACL.
    // Retain the new integrity ACL, replacing only partition entries with the
    // exact original entries so official security/Claude access is preserved.
    *stage = 4;
    status = SecKeychainItemCopyAccess(item, &current);
    if (status != errSecSuccess) goto cleanup;
    newPartitions = SecAccessCopyMatchingACLList(current, kSecACLAuthorizationPartitionID);
    if (!newPartitions) { status = errSecAllocate; goto cleanup; }
    for (CFIndex n = 0; n < CFArrayGetCount(newPartitions); n++) {
        status = SecACLRemove((SecACLRef)CFArrayGetValueAtIndex(newPartitions, n));
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 5;
    for (CFIndex n = 0; n < CFArrayGetCount(oldPartitions); n++) {
        SecACLRef old = (SecACLRef)CFArrayGetValueAtIndex(oldPartitions, n), copy = NULL;
        CFArrayRef apps = NULL, auths = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt;
        status = SecACLCopyContents(old, &apps, &description, &prompt);
        if (status == errSecSuccess)
            status = SecACLCreateWithSimpleContents(current, apps, description, prompt, &copy);
        if (status == errSecSuccess) {
            auths = SecACLCopyAuthorizations(old);
            status = auths ? SecACLUpdateAuthorizations(copy, auths) : errSecAllocate;
        }
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
        if (auths) CFRelease(auths);
        if (copy) CFRelease(copy);
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 6;
    status = SecKeychainItemSetAccess(item, current);
cleanup:
    if (newPartitions) CFRelease(newPartitions);
    if (oldPartitions) CFRelease(oldPartitions);
    if (current) CFRelease(current);
    if (original) CFRelease(original);
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

// Used only by fake-item integration fixtures, restoring the process setting.
func nativeKeychainTestNoInteraction() (func(), error) {
	var previous C.Boolean
	if status := C.SecKeychainGetUserInteractionAllowed(&previous); status != 0 {
		return nil, fmt.Errorf("test Keychain interaction query failed (%d)", int32(status))
	}
	if status := C.SecKeychainSetUserInteractionAllowed(0); status != 0 {
		return nil, fmt.Errorf("test Keychain interaction setting failed (%d)", int32(status))
	}
	return func() { C.SecKeychainSetUserInteractionAllowed(previous) }, nil
}
