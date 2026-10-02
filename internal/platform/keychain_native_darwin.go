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

static OSStatus clauflip_copy_partitions(SecAccessRef access, CFArrayRef *result) {
    CFArrayRef all = NULL;
    OSStatus status = SecAccessCopyACLList(access, &all);
    if (clauflip_fixture_trace) fprintf(stderr, "fake ACL enumeration status=%d count=%ld\n", (int)status, all ? (long)CFArrayGetCount(all) : -1L);
    if (status != errSecSuccess) return status;
    if (!all) return errSecParam;
    CFMutableArrayRef matches = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (!matches) { CFRelease(all); return errSecAllocate; }
    for (CFIndex n = 0; n < CFArrayGetCount(all); n++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(all, n);
        CFArrayRef auths = SecACLCopyAuthorizations(acl);
        if (clauflip_fixture_trace) {
            fprintf(stderr, "fake ACL entry=%ld authorization-count=%ld\n", (long)n, auths ? (long)CFArrayGetCount(auths) : -1L);
            if (auths) CFShow(auths);
        }
        if (!auths) { CFRelease(matches); CFRelease(all); return errSecParam; }
        if (CFArrayContainsValue(auths, CFRangeMake(0, CFArrayGetCount(auths)), kSecACLAuthorizationPartitionID))
            CFArrayAppendValue(matches, acl);
        CFRelease(auths);
    }
    CFRelease(all);
    *result = matches;
    return errSecSuccess;
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
    status = clauflip_copy_partitions(original, &oldPartitions);
    if (status != errSecSuccess) goto cleanup;
    // Check that every entry can be copied before changing credential data.
    for (CFIndex n = 0; oldPartitions && n < CFArrayGetCount(oldPartitions); n++) {
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
    status = clauflip_copy_partitions(current, &newPartitions);
    if (status != errSecSuccess) goto cleanup;
    for (CFIndex n = 0; newPartitions && n < CFArrayGetCount(newPartitions); n++) {
        clauflip_trace("remove updated partition ACL");
        status = SecACLRemove((SecACLRef)CFArrayGetValueAtIndex(newPartitions, n));
        if (status != errSecSuccess) goto cleanup;
    }
    *stage = 5;
    for (CFIndex n = 0; oldPartitions && n < CFArrayGetCount(oldPartitions); n++) {
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
                                      const char *path, const char *password, int *stage) {
    SecKeychainRef keychain = NULL; SecKeychainItemRef item = NULL;
    SecAccessRef original = NULL, uidAccess = NULL, combined = NULL;
    CSSM_ACL_OWNER_PROTOTYPE *oldOwner = NULL, *uidOwner = NULL;
    CSSM_ACL_ENTRY_INFO *oldEntries = NULL, *uidEntries = NULL;
    uint32 oldCount = 0, uidCount = 0;
    CFArrayRef partitions = NULL;
    *stage = 1;
    OSStatus status = SecKeychainOpen(path, &keychain);
    if (status != errSecSuccess) goto done;
    *stage = 2;
    status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
        (UInt32)strlen(account), account, NULL, NULL, &item);
    if (status != errSecSuccess) goto done;
    *stage = 3;
    status = SecKeychainItemCopyAccess(item, &original);
    if (status != errSecSuccess) goto done;
    *stage = 4;
    status = clauflip_copy_partitions(original, &partitions);
    if (status != errSecSuccess) goto done;
    if (!partitions || CFArrayGetCount(partitions) == 0) { status = errSecParam; goto done; }
    CFRelease(partitions); partitions = NULL;
    *stage = 5;
    status = SecAccessGetOwnerAndACL(original, &oldOwner, &oldCount, &oldEntries);
    if (status != errSecSuccess) goto done;
    *stage = 6;
    uidAccess = SecAccessCreateWithOwnerAndACL(getuid(), getgid(), kSecUseOnlyUID, NULL, NULL);
    if (!uidAccess) { status = errSecAllocate; goto done; }
    *stage = 7;
    status = SecAccessGetOwnerAndACL(uidAccess, &uidOwner, &uidCount, &uidEntries);
    if (status != errSecSuccess) goto done;
    *stage = 8;
    // This API deep-copies the owner and every original ACL entry, including
    // partitions and integrity. Only the fake item's owner is substituted.
    status = SecAccessCreateFromOwnerAndACL(uidOwner, oldCount, oldEntries, &combined);
    if (status != errSecSuccess) goto done;
    *stage = 9;
    // Apple SPI confined to fake fixture setup; no production link dependency.
    typedef OSStatus (*SetAccessWithPassword)(SecKeychainItemRef, SecAccessRef, UInt32, const void *);
    SetAccessWithPassword set = (SetAccessWithPassword)dlsym(RTLD_DEFAULT, "SecKeychainItemSetAccessWithPassword");
    status = set ? set(item, combined, (UInt32)strlen(password), password) : errSecUnimplemented;
    if (status != errSecSuccess) goto done;
    *stage = 10;
    SecAccessRef verified = NULL;
    status = SecKeychainItemCopyAccess(item, &verified);
    if (status == errSecSuccess) {
        status = clauflip_copy_partitions(verified, &partitions);
        if (status == errSecSuccess && CFArrayGetCount(partitions) == 0) status = errSecParam;
        CFRelease(verified);
    }
done:
    if (partitions) CFRelease(partitions);
    if (combined) CFRelease(combined);
    if (uidAccess) CFRelease(uidAccess);
    if (original) CFRelease(original);
    if (item) CFRelease(item);
    if (keychain) CFRelease(keychain);
    // SecAccessGetOwnerAndACL allocates CSSM prototypes. The tool never calls
    // this helper outside two short-lived fake-item integration fixtures.
    free(oldOwner); free(oldEntries); free(uidOwner); free(uidEntries);
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
	var stage C.int
	if status := C.clauflip_fixture_owner(cs, ca, cp, cw, &stage); status != 0 {
		return fmt.Errorf("fake Keychain owner setup failed (stage %d, status %d)", int(stage), int32(status))
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
