//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef envbank_string(const char *s) {
  return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

static OSStatus envbank_delete(const char *service, const char *account) {
  CFStringRef svc = envbank_string(service), acct = envbank_string(account);
  const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
  const void *vals[] = { kSecClassGenericPassword, svc, acct };
  CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 3, NULL, NULL);
  OSStatus status = SecItemDelete(query);
  CFRelease(query); CFRelease(svc); CFRelease(acct);
  return status;
}

static OSStatus envbank_put(const char *service, const char *account,
                            const unsigned char *secret, size_t length) {
  envbank_delete(service, account);
  CFErrorRef error = NULL;
  SecAccessControlRef access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAccessControlUserPresence, &error);
  if (!access) { if (error) CFRelease(error); return errSecParam; }
  CFStringRef svc = envbank_string(service), acct = envbank_string(account);
  CFDataRef data = CFDataCreate(NULL, secret, length);
  const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount,
                         kSecValueData, kSecAttrAccessControl };
  const void *vals[] = { kSecClassGenericPassword, svc, acct, data, access };
  CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 5, NULL, NULL);
  OSStatus status = SecItemAdd(attrs, NULL);
  CFRelease(attrs); CFRelease(data); CFRelease(svc); CFRelease(acct); CFRelease(access);
  if (status == errSecMissingEntitlement) {
    // Unsigned command-line tools have no default data-protection Keychain
    // access group. Fall back to the macOS file Keychain with an empty trusted
    // application list, which requires user confirmation on every secret read.
    // The modern user-presence item above remains preferred for signed builds.
    CFMutableArrayRef trusted = CFArrayCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFStringRef descriptor = envbank_string("EnvBank credential");
    SecAccessRef legacyAccess = NULL;
    OSStatus accessStatus = SecAccessCreate(descriptor, trusted, &legacyAccess);
    CFRelease(descriptor); CFRelease(trusted);
    if (accessStatus != errSecSuccess || !legacyAccess) return accessStatus;
    svc = envbank_string(service); acct = envbank_string(account);
    data = CFDataCreate(NULL, secret, length);
    const void *legacyKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount,
                                 kSecValueData, kSecAttrAccess };
    const void *legacyVals[] = { kSecClassGenericPassword, svc, acct, data,
                                 legacyAccess };
    CFDictionaryRef legacyAttrs = CFDictionaryCreate(
        NULL, legacyKeys, legacyVals, 5, NULL, NULL);
    status = SecItemAdd(legacyAttrs, NULL);
    CFRelease(legacyAttrs); CFRelease(data); CFRelease(svc); CFRelease(acct);
    CFRelease(legacyAccess);
  }
  return status;
}

static OSStatus envbank_get(const char *service, const char *account,
                            unsigned char **output, size_t *length) {
  CFStringRef svc = envbank_string(service), acct = envbank_string(account);
  const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount,
                         kSecReturnData, kSecMatchLimit };
  const void *vals[] = { kSecClassGenericPassword, svc, acct,
                         kCFBooleanTrue, kSecMatchLimitOne };
  CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 5, NULL, NULL);
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching(query, &result);
  if (status == errSecSuccess && result) {
    CFDataRef data = (CFDataRef)result;
    *length = CFDataGetLength(data);
    *output = malloc(*length);
    if (!*output && *length) status = errSecAllocate;
    else if (*length) memcpy(*output, CFDataGetBytePtr(data), *length);
    CFRelease(result);
  }
  CFRelease(query); CFRelease(svc); CFRelease(acct);
  return status;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func (SystemStore) Put(service, account string, secret []byte) error {
	cs, ca := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var ptr *C.uchar
	if len(secret) > 0 {
		ptr = (*C.uchar)(unsafe.Pointer(&secret[0]))
	}
	status := C.envbank_put(cs, ca, ptr, C.size_t(len(secret)))
	if status != C.errSecSuccess {
		return fmt.Errorf("Keychain store failed (status %d)", int(status))
	}
	return nil
}

func (SystemStore) Get(service, account, prompt string) ([]byte, error) {
	cs, ca := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	_ = prompt
	var output *C.uchar
	var length C.size_t
	status := C.envbank_get(cs, ca, &output, &length)
	if status == C.errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("Keychain access failed (status %d)", int(status))
	}
	if output == nil && length != 0 {
		return nil, errors.New("Keychain returned invalid data")
	}
	defer C.free(unsafe.Pointer(output))
	return C.GoBytes(unsafe.Pointer(output), C.int(length)), nil
}

func (SystemStore) Delete(service, account string) error {
	cs, ca := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	status := C.envbank_delete(cs, ca)
	if status == C.errSecItemNotFound {
		return nil
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("Keychain delete failed (status %d)", int(status))
	}
	return nil
}
