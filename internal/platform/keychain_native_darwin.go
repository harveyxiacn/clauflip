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
#include <unistd.h>
#include <dlfcn.h>

static int clauflip_fixture_trace = 0;
static void clauflip_set_fixture_trace(int enabled) {
    clauflip_fixture_trace = enabled;
}
static void clauflip_trace(const char *operation) {
    if (clauflip_fixture_trace) {
        fprintf(stderr, "fake Keychain fixture native call: %s\n", operation);
        fflush(stderr);
    }
}

static OSStatus clauflip_update(const char *service, const char *account, const char *path,
                                       const void *data, uint32_t length, int *stage) {
    SecKeychainItemRef item = NULL;
    *stage = 1;
    SecKeychainRef keychain = NULL;
    if (path[0]) {
        OSStatus opened = SecKeychainOpen(path, &keychain);
        if (opened != errSecSuccess) return opened;
    }
    clauflip_trace("find item");
    OSStatus status = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(service), service, (UInt32)strlen(account), account,
        NULL, NULL, &item);
    if (keychain) CFRelease(keychain);
    if (status != errSecSuccess) return status;
    SecAccessRef original = NULL, current = NULL;
    CFArrayRef oldPartitions = NULL, newPartitions = NULL;
    *stage = 2;
    clauflip_trace("copy original access");
    status = SecKeychainItemCopyAccess(item, &original);
    if (status != errSecSuccess) goto cleanup;
    clauflip_trace("copy original partition list");
    oldPartitions = SecAccessCopyMatchingACLList(original, kSecACLAuthorizationPartitionID);
    if (!oldPartitions) { status = errSecAllocate; goto cleanup; }
    // Check that every entry can be copied before changing credential data.
    for (CFIndex n = 0; n < CFArrayGetCount(oldPartitions); n++) {
        CFArrayRef apps = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt;
        clauflip_trace("preflight original ACL contents");
        status = SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(oldPartitions, n),
                                   &apps, &description, &prompt);
        if (apps) CFRelease(apps);
        if (description) CFRelease(description);
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 3;
    clauflip_trace("modify content");
    status = SecKeychainItemModifyContent(item, NULL, length, data);
    if (status != errSecSuccess) goto cleanup;
    // A data update creates a fresh integrity ACL and caller partition ACL.
    // Retain the new integrity ACL, replacing only partition entries with the
    // exact original entries so official security/Claude access is preserved.
    *stage = 4;
    clauflip_trace("copy updated access");
    status = SecKeychainItemCopyAccess(item, &current);
    if (status != errSecSuccess) goto cleanup;
    clauflip_trace("copy updated partition list");
    newPartitions = SecAccessCopyMatchingACLList(current, kSecACLAuthorizationPartitionID);
    if (!newPartitions) { status = errSecAllocate; goto cleanup; }
    for (CFIndex n = 0; n < CFArrayGetCount(newPartitions); n++) {
        clauflip_trace("remove updated partition ACL");
        status = SecACLRemove((SecACLRef)CFArrayGetValueAtIndex(newPartitions, n));
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 5;
    for (CFIndex n = 0; n < CFArrayGetCount(oldPartitions); n++) {
        SecACLRef old = (SecACLRef)CFArrayGetValueAtIndex(oldPartitions, n), copy = NULL;
        CFArrayRef apps = NULL, auths = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt;
        clauflip_trace("clone original partition ACL");
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
    clauflip_trace("set restored partition access");
    status = SecKeychainItemSetAccess(item, current);
    clauflip_trace("set access returned");
cleanup:
    if (newPartitions) CFRelease(newPartitions);
    if (oldPartitions) CFRelease(oldPartitions);
    if (current) CFRelease(current);
    if (original) CFRelease(original);
    CFRelease(item);
    return status;
}

// Fake-item fixtures replace only their owner with the current Unix user.
// A known fake Keychain password authorizes this one fixture setup operation.
static OSStatus clauflip_fixture_owner(const char *service, const char *account,
                                               const char *path, const char *password) {
    SecKeychainRef keychain = NULL; SecKeychainItemRef item = NULL;
    SecAccessRef original = NULL, access = NULL; CFArrayRef acls = NULL;
    OSStatus status = SecKeychainOpen(path, &keychain);
    if (status != errSecSuccess) goto done;
    status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
        (UInt32)strlen(account), account, NULL, NULL, &item);
    if (status != errSecSuccess) goto done;
    status = SecKeychainItemCopyAccess(item, &original);
    if (status != errSecSuccess) goto done;
    status = SecAccessCopyOwnerAndACL(original, NULL, NULL, NULL, &acls);
    if (status != errSecSuccess) goto done;
    access = SecAccessCreateWithOwnerAndACL(getuid(), getgid(), kSecUseOnlyUID, acls, NULL);
    if (!access) { status = errSecAllocate; goto done; }
    // This Apple SPI is confined to fake fixture setup. Resolve dynamically so
    // production binaries do not link against a private Keychain entry point.
    typedef OSStatus (*SetAccessWithPassword)(SecKeychainItemRef, SecAccessRef, UInt32, const void *);
    SetAccessWithPassword set = (SetAccessWithPassword)dlsym(RTLD_DEFAULT, "SecKeychainItemSetAccessWithPassword");
    status = set ? set(item, access, (UInt32)strlen(password), password) : errSecUnimplemented;
done:
    if (access) CFRelease(access);
    if (acls) CFRelease(acls);
    if (original) CFRelease(original);
    if (item) CFRelease(item);
    if (keychain) CFRelease(keychain);
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

func nativeKeychainWrite(service, account, path string, b []byte) error {
	if strings.ContainsRune(service, 0) || strings.ContainsRune(account, 0) || len(b) == 0 || uint64(len(b)) > uint64(^uint32(0)) {
		return errors.New("invalid native Keychain input")
	}
	cs, ca := C.CString(service), C.CString(account)
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	data := C.CBytes(b)
	defer func() { C.memset(data, 0, C.size_t(len(b))); C.free(data) }()
	var stage C.int
	status := C.clauflip_update(cs, ca, cp, data, C.uint32_t(len(b)), &stage)
	if status != 0 {
		return fmt.Errorf("native Keychain operation failed (stage %d, status %d)", int(stage), int32(status))
	}
	return nil
}

func nativeKeychainFixtureOwner(service, account, path, password string) error {
	cs, ca, cp, cw := C.CString(service), C.CString(account), C.CString(path), C.CString(password)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cw))
	if status := C.clauflip_fixture_owner(cs, ca, cp, cw); status != 0 {
		return fmt.Errorf("fake Keychain owner setup failed (%d)", int32(status))
	}
	return nil
}

// Used only by fake-item integration fixtures, restoring the process setting.
func nativeKeychainTestNoInteraction() (func(), error) {
	C.clauflip_set_fixture_trace(1)
	var previous C.Boolean
	if status := C.SecKeychainGetUserInteractionAllowed(&previous); status != 0 {
		return nil, fmt.Errorf("test Keychain interaction query failed (%d)", int32(status))
	}
	if status := C.SecKeychainSetUserInteractionAllowed(0); status != 0 {
		return nil, fmt.Errorf("test Keychain interaction setting failed (%d)", int32(status))
	}
	return func() { C.SecKeychainSetUserInteractionAllowed(previous); C.clauflip_set_fixture_trace(0) }, nil
}
