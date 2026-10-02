//go:build darwin && cgo

package platform

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int claude_accounts_fixture_trace = 0;
static void claude_accounts_set_fixture_trace(int enabled) {
    claude_accounts_fixture_trace = enabled;
}
static void claude_accounts_trace(const char *operation) {
    if (claude_accounts_fixture_trace) {
        fprintf(stderr, "fake Keychain fixture native call: %s\n", operation);
        fflush(stderr);
    }
}

static OSStatus claude_accounts_update(const char *service, const char *account,
                                       const void *data, uint32_t length, int *stage) {
    SecKeychainItemRef item = NULL;
    *stage = 1;
    claude_accounts_trace("find item");
    OSStatus status = SecKeychainFindGenericPassword(NULL,
        (UInt32)strlen(service), service, (UInt32)strlen(account), account,
        NULL, NULL, &item);
    if (status != errSecSuccess) return status;
    SecAccessRef original = NULL, current = NULL;
    CFArrayRef oldPartitions = NULL, newPartitions = NULL;
    *stage = 2;
    claude_accounts_trace("copy original access");
    status = SecKeychainItemCopyAccess(item, &original);
    if (status != errSecSuccess) goto cleanup;
    claude_accounts_trace("copy original partition list");
    oldPartitions = SecAccessCopyMatchingACLList(original, kSecACLAuthorizationPartitionID);
    if (!oldPartitions) { status = errSecAllocate; goto cleanup; }
    // Check that every entry can be copied before changing credential data.
    for (CFIndex n = 0; n < CFArrayGetCount(oldPartitions); n++) {
        CFArrayRef apps = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt;
        claude_accounts_trace("preflight original ACL contents");
        status = SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(oldPartitions, n),
                                   &apps, &description, &prompt);
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 3;
    claude_accounts_trace("modify content");
    status = SecKeychainItemModifyContent(item, NULL, length, data);
    if (status != errSecSuccess) goto cleanup;
    // A data update creates a fresh integrity ACL and caller partition ACL.
    // Retain the new integrity ACL, replacing only partition entries with the
    // exact original entries so official security/Claude access is preserved.
    *stage = 4;
    claude_accounts_trace("copy updated access");
    status = SecKeychainItemCopyAccess(item, &current);
    if (status != errSecSuccess) goto cleanup;
    claude_accounts_trace("copy updated partition list");
    newPartitions = SecAccessCopyMatchingACLList(current, kSecACLAuthorizationPartitionID);
    if (!newPartitions) { status = errSecAllocate; goto cleanup; }
    for (CFIndex n = 0; n < CFArrayGetCount(newPartitions); n++) {
        claude_accounts_trace("remove updated partition ACL");
        status = SecACLRemove((SecACLRef)CFArrayGetValueAtIndex(newPartitions, n));
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 5;
    for (CFIndex n = 0; n < CFArrayGetCount(oldPartitions); n++) {
        SecACLRef old = (SecACLRef)CFArrayGetValueAtIndex(oldPartitions, n), copy = NULL;
        CFArrayRef apps = NULL, auths = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt;
        claude_accounts_trace("clone original partition ACL");
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
    claude_accounts_trace("set restored partition access");
    status = SecKeychainItemSetAccess(item, current);
    claude_accounts_trace("set access returned");
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
	C.claude_accounts_set_fixture_trace(1)
	var previous C.Boolean
	if status := C.SecKeychainGetUserInteractionAllowed(&previous); status != 0 {
		return nil, fmt.Errorf("test Keychain interaction query failed (%d)", int32(status))
	}
	if status := C.SecKeychainSetUserInteractionAllowed(0); status != 0 {
		return nil, fmt.Errorf("test Keychain interaction setting failed (%d)", int32(status))
	}
	return func() { C.SecKeychainSetUserInteractionAllowed(previous); C.claude_accounts_set_fixture_trace(0) }, nil
}
