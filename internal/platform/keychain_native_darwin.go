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

static OSStatus clauflip_find(const char *service, const char *account, const char *path, SecKeychainItemRef *item) {
    SecKeychainRef keychain = NULL;
    OSStatus status = errSecSuccess;
    if (path[0]) status = SecKeychainOpen(path, &keychain);
    if (status == errSecSuccess)
        status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
            (UInt32)strlen(account), account, NULL, NULL, item);
    if (keychain) CFRelease(keychain);
    return status;
}

static OSStatus clauflip_snapshot(const char *service, const char *account, const char *path, CFDataRef *result) {
    SecKeychainItemRef item = NULL; SecAccessRef access = NULL;
    CFArrayRef partitions = NULL;
    CFMutableArrayRef records = NULL;
    OSStatus status = clauflip_find(service, account, path, &item);
    if (status != errSecSuccess) goto done;
    status = SecKeychainItemCopyAccess(item, &access);
    if (status != errSecSuccess) goto done;
    status = clauflip_copy_partitions(access, &partitions);
    if (status != errSecSuccess) goto done;
    records = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (!records) { status = errSecAllocate; goto done; }
    for (CFIndex n = 0; n < CFArrayGetCount(partitions); n++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(partitions, n);
        CFArrayRef apps = NULL, auths = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = 0;
        status = SecACLCopyContents(acl, &apps, &description, &prompt);
        if (status == errSecSuccess && (!description || (apps && CFArrayGetCount(apps) != 0))) status = errSecParam;
        if (status == errSecSuccess) {
            auths = SecACLCopyAuthorizations(acl);
            if (!auths || CFArrayGetCount(auths) != 1 ||
                !CFEqual(CFArrayGetValueAtIndex(auths, 0), kSecACLAuthorizationPartitionID)) status = errSecParam;
        }
        if (status == errSecSuccess) {
            int64_t flags = prompt;
            CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &flags);
            const void *keys[] = {CFSTR("description"), CFSTR("prompt"), CFSTR("authorizations"), CFSTR("applicationsPresent")};
            const void *values[] = {description, number, auths, apps ? kCFBooleanTrue : kCFBooleanFalse};
            CFDictionaryRef record = number ? CFDictionaryCreate(kCFAllocatorDefault, keys, values, 4,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
            if (record) { CFArrayAppendValue(records, record); CFRelease(record); }
            else status = errSecAllocate;
            if (number) CFRelease(number);
        }
        if (apps) CFRelease(apps);
        if (auths) CFRelease(auths);
        if (description) CFRelease(description);
        if (status != errSecSuccess) goto done;
    }
    CFDataRef identity = NULL;
    status = SecKeychainItemCreatePersistentReference(item, &identity);
    if (status == errSecSuccess) {
        const void *keys[] = {CFSTR("item"), CFSTR("partitions")};
        const void *values[] = {identity, records};
        CFDictionaryRef metadata = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 2,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        *result = metadata ? CFPropertyListCreateData(kCFAllocatorDefault, metadata, kCFPropertyListXMLFormat_v1_0, 0, NULL) : NULL;
        if (!*result) status = errSecParam;
        if (metadata) CFRelease(metadata);
        CFRelease(identity);
    }
done:
    if (records) CFRelease(records);
    if (partitions) CFRelease(partitions);
    if (access) CFRelease(access);
    if (item) CFRelease(item);
    return status;
}

static OSStatus clauflip_restore(const char *service, const char *account, const char *path,
                                 const void *bytes, CFIndex length) {
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes, length);
    CFPropertyListRef metadata = data ? CFPropertyListCreateWithData(kCFAllocatorDefault, data, 0, NULL, NULL) : NULL;
    if (data) CFRelease(data);
    if (!metadata || CFGetTypeID(metadata) != CFDictionaryGetTypeID() || CFDictionaryGetCount(metadata) != 2) {
        if (metadata) CFRelease(metadata);
        return errSecParam;
    }
    CFArrayRef records = CFDictionaryGetValue(metadata, CFSTR("partitions"));
    CFDataRef identity = CFDictionaryGetValue(metadata, CFSTR("item"));
    if (!records || !identity || CFGetTypeID(records) != CFArrayGetTypeID() || CFGetTypeID(identity) != CFDataGetTypeID()) {
        CFRelease(metadata); return errSecParam;
    }
    SecKeychainItemRef item = NULL; SecAccessRef access = NULL; CFArrayRef partitions = NULL;
    OSStatus status = clauflip_find(service, account, path, &item);
    if (status != errSecSuccess) goto done;
    CFDataRef actualIdentity = NULL;
    status = SecKeychainItemCreatePersistentReference(item, &actualIdentity);
    if (status == errSecSuccess && !CFEqual(identity, actualIdentity)) status = errSecParam;
    if (actualIdentity) CFRelease(actualIdentity);
    if (status != errSecSuccess) goto done;
    status = SecKeychainItemCopyAccess(item, &access);
    if (status != errSecSuccess) goto done;
    status = clauflip_copy_partitions(access, &partitions);
    if (status != errSecSuccess) goto done;
    for (CFIndex n = 0; n < CFArrayGetCount(partitions); n++) {
        status = SecACLRemove((SecACLRef)CFArrayGetValueAtIndex(partitions, n));
        if (status != errSecSuccess) goto done;
    }
    for (CFIndex n = 0; n < CFArrayGetCount(records); n++) {
        CFDictionaryRef record = CFArrayGetValueAtIndex(records, n);
        if (CFGetTypeID(record) != CFDictionaryGetTypeID() || CFDictionaryGetCount(record) != 4) { status = errSecParam; goto done; }
        CFStringRef description = CFDictionaryGetValue(record, CFSTR("description"));
        CFNumberRef number = CFDictionaryGetValue(record, CFSTR("prompt"));
        CFArrayRef auths = CFDictionaryGetValue(record, CFSTR("authorizations"));
        CFBooleanRef present = CFDictionaryGetValue(record, CFSTR("applicationsPresent"));
        if (!description || !number || !auths || !present || CFGetTypeID(description) != CFStringGetTypeID() ||
            CFGetTypeID(number) != CFNumberGetTypeID() || CFGetTypeID(auths) != CFArrayGetTypeID() || CFGetTypeID(present) != CFBooleanGetTypeID()) { status = errSecParam; goto done; }
        int64_t flags = 0;
        if (!CFNumberGetValue(number, kCFNumberSInt64Type, &flags) || flags < 0 || flags > UINT32_MAX ||
            CFArrayGetCount(auths) != 1 ||
            !CFArrayContainsValue(auths, CFRangeMake(0, CFArrayGetCount(auths)), kSecACLAuthorizationPartitionID) ||
            CFArrayContainsValue(auths, CFRangeMake(0, CFArrayGetCount(auths)), kSecACLAuthorizationIntegrity)) { status = errSecParam; goto done; }
        for (CFIndex a = 0; a < CFArrayGetCount(auths); a++) {
            if (CFGetTypeID(CFArrayGetValueAtIndex(auths, a)) != CFStringGetTypeID()) { status = errSecParam; goto done; }
        }
        CFArrayRef apps = CFBooleanGetValue(present) ? CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks) : NULL;
        SecACLRef copy = NULL;
        status = SecACLCreateWithSimpleContents(access, apps, description, (SecKeychainPromptSelector)flags, &copy);
        if (status == errSecSuccess) status = SecACLUpdateAuthorizations(copy, auths);
        if (apps) CFRelease(apps);
        if (copy) CFRelease(copy);
        if (status != errSecSuccess) goto done;
    }
    status = SecKeychainItemSetAccess(item, access);
done:
    if (partitions) CFRelease(partitions);
    if (access) CFRelease(access);
    if (item) CFRelease(item);
    CFRelease(metadata);
    return status;
}

static OSStatus clauflip_read(const char *service, const char *account, const char *path, UInt32 *length, void **data) {
    SecKeychainRef keychain = NULL;
    OSStatus status = errSecSuccess;
    if (path[0]) status = SecKeychainOpen(path, &keychain);
    if (status == errSecSuccess)
        status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
            (UInt32)strlen(account), account, length, data, NULL);
    if (keychain) CFRelease(keychain);
    return status;
}

static OSStatus clauflip_fixture_partition(SecAccessRef access) {
    SecCodeRef code = NULL; CFDictionaryRef info = NULL;
    OSStatus signing = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    if (signing == errSecSuccess) signing = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    if (code) CFRelease(code);
    if (signing != errSecSuccess) { if (info) CFRelease(info); return signing; }
    CFDataRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (!hash || CFGetTypeID(hash) != CFDataGetTypeID() || CFDataGetLength(hash) > 64) { CFRelease(info); return errSecParam; }
    char caller[7 + 128 + 1] = "cdhash:";
    const char digits[] = "0123456789abcdef";
    const UInt8 *hashBytes = CFDataGetBytePtr(hash);
    CFIndex hashLength = CFDataGetLength(hash);
    if (!hashLength) { CFRelease(info); return errSecParam; }
    for (CFIndex n = 0; n < hashLength; n++) { caller[7+n*2] = digits[hashBytes[n] >> 4]; caller[7+n*2+1] = digits[hashBytes[n] & 15]; }
    caller[7+hashLength*2] = 0;
    CFStringRef callerPartition = CFStringCreateWithCString(kCFAllocatorDefault, caller, kCFStringEncodingASCII);
    CFRelease(info);
    if (!callerPartition) return errSecAllocate;
    const void *ids[] = {CFSTR("apple-tool:"), CFSTR("apple:"), callerPartition};
    CFArrayRef values = CFArrayCreate(kCFAllocatorDefault, ids, 3, &kCFTypeArrayCallBacks);
    CFRelease(callerPartition);
    const void *keys[] = {CFSTR("Partitions")}; const void *dictValues[] = {values};
    CFDictionaryRef dict = values ? CFDictionaryCreate(kCFAllocatorDefault, keys, dictValues, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
    CFDataRef xml = dict ? CFPropertyListCreateData(kCFAllocatorDefault, dict, kCFPropertyListXMLFormat_v1_0, 0, NULL) : NULL;
    OSStatus status = errSecAllocate;
    if (xml) {
        CFIndex length = CFDataGetLength(xml);
        char *hex = malloc((size_t)length * 2 + 1);
        if (hex) {
            const UInt8 *bytes = CFDataGetBytePtr(xml);
            const char digits[] = "0123456789abcdef";
            for (CFIndex n = 0; n < length; n++) { hex[n*2] = digits[bytes[n] >> 4]; hex[n*2+1] = digits[bytes[n] & 15]; }
            hex[length*2] = 0;
            CFStringRef description = CFStringCreateWithCString(kCFAllocatorDefault, hex, kCFStringEncodingASCII);
            free(hex);
            SecACLRef acl = NULL;
            status = description ? SecACLCreateWithSimpleContents(access, NULL, description, 0, &acl) : errSecAllocate;
            if (status == errSecSuccess) {
                const void *tag = kSecACLAuthorizationPartitionID;
                CFArrayRef auths = CFArrayCreate(kCFAllocatorDefault, &tag, 1, &kCFTypeArrayCallBacks);
                status = auths ? SecACLUpdateAuthorizations(acl, auths) : errSecAllocate;
                if (auths) CFRelease(auths);
            }
            if (acl) CFRelease(acl);
            if (description) CFRelease(description);
        }
        CFRelease(xml);
    }
    if (dict) CFRelease(dict);
    if (values) CFRelease(values);
    return status;
}

static OSStatus clauflip_fixture_interrupted_write(const char *service, const char *account,
                                                   const char *path, const void *data, UInt32 length) {
    SecKeychainItemRef item = NULL;
    OSStatus status = clauflip_find(service, account, path, &item);
    if (status == errSecSuccess) {
        status = SecKeychainItemModifyContent(item, NULL, length, data);
        CFRelease(item);
    }
    return status;
}

static OSStatus clauflip_update(const char *service, const char *account, const char *path,
                                const void *data, uint32_t length, int *stage) {
    SecKeychainItemRef item = NULL;
    *stage = 1;
    clauflip_trace("find item");
    OSStatus status = clauflip_find(service, account, path, &item);
    if (status != errSecSuccess) return status;
    *stage = 2;
    clauflip_trace("modify content; durable caller journal restores ACL");
    status = SecKeychainItemModifyContent(item, NULL, length, data);
    CFRelease(item);
    return status;
}
// Isolated fake fixtures create their owner policy at creation time. No owner
// authorization bypass or private Security API is used by this helper.
static OSStatus clauflip_fixture_owner(const char *service, const char *account,
                                      const char *path, const char *executable, int *stage) {
    if (!path[0]) return errSecParam;
    SecKeychainRef keychain = NULL; SecKeychainItemRef item = NULL, replacement = NULL;
    SecAccessRef standard = NULL, uidAccess = NULL, combined = NULL;
    SecTrustedApplicationRef security = NULL, caller = NULL;
    CFArrayRef apps = NULL, partitions = NULL;
    CSSM_ACL_OWNER_PROTOTYPE *oldOwner = NULL, *uidOwner = NULL;
    CSSM_ACL_ENTRY_INFO *oldEntries = NULL, *uidEntries = NULL;
    uint32 oldCount = 0, uidCount = 0;
    UInt32 length = 0; void *payload = NULL;
    *stage = 1;
    OSStatus status = SecKeychainOpen(path, &keychain);
    if (status != errSecSuccess) goto done;
    status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
        (UInt32)strlen(account), account, &length, &payload, &item);
    if (status != errSecSuccess) goto done;
    *stage = 2;
    status = SecTrustedApplicationCreateFromPath("/usr/bin/security", &security);
    if (status != errSecSuccess) goto done;
    status = SecTrustedApplicationCreateFromPath(executable, &caller);
    if (status != errSecSuccess) goto done;
    const void *trusted[] = {security, caller};
    apps = CFArrayCreate(kCFAllocatorDefault, trusted, 2, &kCFTypeArrayCallBacks);
    if (!apps) { status = errSecAllocate; goto done; }
    *stage = 3;
    status = SecAccessCreate(CFSTR("ClauFlip isolated fake fixture"), apps, &standard);
    if (status != errSecSuccess) goto done;
    status = SecAccessGetOwnerAndACL(standard, &oldOwner, &oldCount, &oldEntries);
    if (status != errSecSuccess) goto done;
    *stage = 4;
    uidAccess = SecAccessCreateWithOwnerAndACL(getuid(), getgid(), kSecUseOnlyUID, NULL, NULL);
    if (!uidAccess) { status = errSecAllocate; goto done; }
    status = SecAccessGetOwnerAndACL(uidAccess, &uidOwner, &uidCount, &uidEntries);
    if (status != errSecSuccess) goto done;
    *stage = 5;
    status = SecAccessCreateFromOwnerAndACL(uidOwner, oldCount, oldEntries, &combined);
    if (status != errSecSuccess) goto done;
    status = clauflip_fixture_partition(combined);
    if (status != errSecSuccess) goto done;
    *stage = 6;
    status = SecKeychainItemDelete(item);
    if (status != errSecSuccess) goto done;
    SecKeychainAttribute attributes[] = {
        {kSecServiceItemAttr, (UInt32)strlen(service), (void *)service},
        {kSecAccountItemAttr, (UInt32)strlen(account), (void *)account}
    };
    SecKeychainAttributeList list = {2, attributes};
    // Creation applies every supplied ACL and the UID owner, regardless of
    // raw imported entries' unchanged state (Access::setAccess(update=false)).
    status = SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &list,
        length, payload, keychain, combined, &replacement);
    if (status != errSecSuccess) goto done;
    *stage = 7;
    SecAccessRef verified = NULL;
    status = SecKeychainItemCopyAccess(replacement, &verified);
    if (status == errSecSuccess) {
        status = clauflip_copy_partitions(verified, &partitions);
        if (status == errSecSuccess && CFArrayGetCount(partitions) == 0) status = errSecParam;
        CFRelease(verified);
    }
done:
    if (payload) { memset(payload, 0, length); SecKeychainItemFreeContent(NULL, payload); }
    if (partitions) CFRelease(partitions);
    if (apps) CFRelease(apps);
    if (security) CFRelease(security);
    if (caller) CFRelease(caller);
    if (combined) CFRelease(combined);
    if (uidAccess) CFRelease(uidAccess);
    if (standard) CFRelease(standard);
    if (replacement) CFRelease(replacement);
    if (item) CFRelease(item);
    if (keychain) CFRelease(keychain);
    free(oldOwner); free(oldEntries); free(uidOwner); free(uidEntries);
    return status;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
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

func nativeKeychainArguments(service, account, path string) (*C.char, *C.char, *C.char, func()) {
	cs, ca, cp := C.CString(service), C.CString(account), C.CString(path)
	return cs, ca, cp, func() { C.free(unsafe.Pointer(cs)); C.free(unsafe.Pointer(ca)); C.free(unsafe.Pointer(cp)) }
}

func nativeKeychainError(status C.OSStatus) error {
	if status == C.errSecItemNotFound {
		return os.ErrNotExist
	}
	return fmt.Errorf("native Keychain metadata operation failed (status %d)", int32(status))
}

func nativeKeychainSnapshot(service, account, path string) ([]byte, error) {
	cs, ca, cp, cleanup := nativeKeychainArguments(service, account, path)
	defer cleanup()
	var data C.CFDataRef
	if status := C.clauflip_snapshot(cs, ca, cp, &data); status != 0 {
		return nil, nativeKeychainError(status)
	}
	defer C.CFRelease(C.CFTypeRef(data))
	length := C.CFDataGetLength(data)
	if length <= 0 || length > 1<<20 {
		return nil, errors.New("invalid native Keychain metadata size")
	}
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(length)), nil
}

func nativeKeychainRestore(service, account, path string, metadata []byte) error {
	if len(metadata) == 0 || len(metadata) > 1<<20 {
		return errors.New("invalid native Keychain metadata size")
	}
	cs, ca, cp, cleanup := nativeKeychainArguments(service, account, path)
	defer cleanup()
	data := C.CBytes(metadata)
	defer C.free(data)
	if status := C.clauflip_restore(cs, ca, cp, data, C.CFIndex(len(metadata))); status != 0 {
		return nativeKeychainError(status)
	}
	return nil
}

func nativeKeychainRead(service, account, path string) ([]byte, error) {
	cs, ca, cp, cleanup := nativeKeychainArguments(service, account, path)
	defer cleanup()
	var length C.UInt32
	var data unsafe.Pointer
	if status := C.clauflip_read(cs, ca, cp, &length, &data); status != 0 {
		return nil, nativeKeychainError(status)
	}
	defer func() {
		if data != nil {
			C.memset(data, 0, C.size_t(length))
			C.SecKeychainItemFreeContent(nil, data)
		}
	}()
	if length > 4<<20 {
		return nil, errors.New("native Keychain credential exceeds safe size")
	}
	return C.GoBytes(data, C.int(length)), nil
}

func nativeKeychainFixtureInterruptedWrite(service, account, path string, b []byte) error {
	cs, ca, cp, cleanup := nativeKeychainArguments(service, account, path)
	defer cleanup()
	data := C.CBytes(b)
	defer func() { C.memset(data, 0, C.size_t(len(b))); C.free(data) }()
	if status := C.clauflip_fixture_interrupted_write(cs, ca, cp, data, C.UInt32(len(b))); status != 0 {
		return nativeKeychainError(status)
	}
	return nil
}

func nativeKeychainFixtureOwner(service, account, path, password string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	ce := C.CString(executable)
	defer C.free(unsafe.Pointer(ce))
	cs, ca, cp, cw := C.CString(service), C.CString(account), C.CString(path), C.CString(password)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cw))
	var stage C.int
	if status := C.clauflip_fixture_owner(cs, ca, cp, ce, &stage); status != 0 {
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
