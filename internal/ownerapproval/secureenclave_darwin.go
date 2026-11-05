//go:build darwin && cgo

package ownerapproval

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication -framework CoreFoundation
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>

// Fixed private statuses for conditions Security.framework does not report.
#define ENVBANK_OWNER_NOT_HARDWARE  (-909001)
#define ENVBANK_OWNER_KEY_MISMATCH  (-909002)
#define ENVBANK_OWNER_AMBIGUOUS     (-909003)
#define ENVBANK_OWNER_UNSUPPORTED   (-909004)
#define ENVBANK_OWNER_BUFFER        (-909005)

static NSData *envbank_owner_tag(void) {
  static const char tag[] = "com.envbank.owner-approval.p256.v1";
  return [NSData dataWithBytes:tag length:strlen(tag)];
}

// Count every private key carrying the EnvBank tag, on ANY token, without
// allowing authentication UI. A software or duplicate key under the tag is a
// substitution signal and makes signing/enrollment refuse.
static OSStatus envbank_owner_count(int *count) {
  @autoreleasepool {
    *count = 0;
    LAContext *quiet = [[LAContext alloc] init];
    quiet.interactionNotAllowed = YES;
    NSDictionary *query = @{
      (__bridge id)kSecClass: (__bridge id)kSecClassKey,
      (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
      (__bridge id)kSecAttrApplicationTag: envbank_owner_tag(),
      (__bridge id)kSecUseDataProtectionKeychain: @YES,
      (__bridge id)kSecReturnAttributes: @YES,
      (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
      (__bridge id)kSecUseAuthenticationContext: quiet,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    [quiet invalidate];
    if (status == errSecItemNotFound) return errSecSuccess;
    if (status != errSecSuccess) return status;
    NSArray *items = (__bridge_transfer NSArray *)result;
    *count = (int)[items count];
    return errSecSuccess;
  }
}

static OSStatus envbank_owner_public(SecKeyRef privateKey, unsigned char *out, size_t *length) {
  SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
  if (!publicKey) return ENVBANK_OWNER_UNSUPPORTED;
  CFErrorRef error = NULL;
  CFDataRef data = SecKeyCopyExternalRepresentation(publicKey, &error);
  CFRelease(publicKey);
  if (!data) { if (error) CFRelease(error); return ENVBANK_OWNER_UNSUPPORTED; }
  CFIndex size = CFDataGetLength(data);
  if (size != 65) { CFRelease(data); return ENVBANK_OWNER_UNSUPPORTED; }
  memcpy(out, CFDataGetBytePtr(data), 65);
  *length = 65;
  CFRelease(data);
  return errSecSuccess;
}

// Re-check the retrieved key really is a 256-bit EC key on the Secure
// Enclave token. Access-control flags are fixed at enrollment; macOS has no
// public API to read them back from a SecAccessControlRef.
static OSStatus envbank_owner_check_hardware(SecKeyRef key) {
  NSDictionary *attributes = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
  if (!attributes) return ENVBANK_OWNER_NOT_HARDWARE;
  id token = attributes[(__bridge id)kSecAttrTokenID];
  id type = attributes[(__bridge id)kSecAttrKeyType];
  id size = attributes[(__bridge id)kSecAttrKeySizeInBits];
  if (![token isEqual:(__bridge id)kSecAttrTokenIDSecureEnclave]) return ENVBANK_OWNER_NOT_HARDWARE;
  if (![type isEqual:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom]) return ENVBANK_OWNER_NOT_HARDWARE;
  if (![size isKindOfClass:[NSNumber class]] || [size integerValue] != 256) return ENVBANK_OWNER_NOT_HARDWARE;
  return errSecSuccess;
}

static OSStatus envbank_owner_enroll(unsigned char *out, size_t *length) {
  @autoreleasepool {
    int count = 0;
    OSStatus status = envbank_owner_count(&count);
    if (status != errSecSuccess) return status;
    if (count != 0) return errSecDuplicateItem;
    CFErrorRef error = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence, &error);
    if (!access) { if (error) CFRelease(error); return errSecParam; }
    NSDictionary *attributes = @{
      (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
      (__bridge id)kSecAttrKeySizeInBits: @256,
      (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
      (__bridge id)kSecUseDataProtectionKeychain: @YES,
      (__bridge id)kSecPrivateKeyAttrs: @{
        (__bridge id)kSecAttrIsPermanent: @YES,
        (__bridge id)kSecAttrApplicationTag: envbank_owner_tag(),
        (__bridge id)kSecAttrLabel: @"EnvBank owner approval",
        (__bridge id)kSecAttrAccessControl: (__bridge id)access,
      },
    };
    SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);
    CFRelease(access);
    if (!key) {
      status = error ? (OSStatus)CFErrorGetCode(error) : errSecParam;
      if (error) CFRelease(error);
      return status;
    }
    status = envbank_owner_check_hardware(key);
    if (status == errSecSuccess) status = envbank_owner_public(key, out, length);
    CFRelease(key);
    return status;
  }
}

// Sign with a NEW LAContext whose reuse duration is zero, then invalidate it.
// No authenticated context is cached or shared between approvals.
static OSStatus envbank_owner_sign(const unsigned char *pinned, const unsigned char *message, size_t messageLength,
                                   const char *reason, unsigned char *signature, size_t *signatureLength) {
  @autoreleasepool {
    int count = 0;
    OSStatus status = envbank_owner_count(&count);
    if (status != errSecSuccess) return status;
    if (count == 0) return errSecItemNotFound;
    if (count != 1) return ENVBANK_OWNER_AMBIGUOUS;
    LAContext *context = [[LAContext alloc] init];
    context.touchIDAuthenticationAllowableReuseDuration = 0;
    context.localizedReason = [NSString stringWithUTF8String:reason];
    NSDictionary *query = @{
      (__bridge id)kSecClass: (__bridge id)kSecClassKey,
      (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
      (__bridge id)kSecAttrApplicationTag: envbank_owner_tag(),
      (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
      (__bridge id)kSecUseDataProtectionKeychain: @YES,
      (__bridge id)kSecReturnRef: @YES,
      (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
      (__bridge id)kSecUseAuthenticationContext: context,
    };
    CFTypeRef result = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) { [context invalidate]; return status == errSecSuccess ? errSecItemNotFound : status; }
    SecKeyRef key = (SecKeyRef)result;
    unsigned char publicBytes[65];
    size_t publicLength = 0;
    status = envbank_owner_check_hardware(key);
    if (status == errSecSuccess) status = envbank_owner_public(key, publicBytes, &publicLength);
    if (status == errSecSuccess && (publicLength != 65 || memcmp(publicBytes, pinned, 65) != 0)) status = ENVBANK_OWNER_KEY_MISMATCH;
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
    if (status == errSecSuccess && !SecKeyIsAlgorithmSupported(key, kSecKeyOperationTypeSign, algorithm)) status = ENVBANK_OWNER_UNSUPPORTED;
    if (status == errSecSuccess) {
      CFErrorRef error = NULL;
      CFDataRef data = CFDataCreate(kCFAllocatorDefault, message, (CFIndex)messageLength);
      CFDataRef signed_ = data ? SecKeyCreateSignature(key, algorithm, data, &error) : NULL;
      if (data) CFRelease(data);
      if (!signed_) {
        status = error ? (OSStatus)CFErrorGetCode(error) : errSecParam;
        if (error) CFRelease(error);
      } else {
        CFIndex size = CFDataGetLength(signed_);
        if (size <= 0 || size > 128) status = ENVBANK_OWNER_BUFFER;
        else { memcpy(signature, CFDataGetBytePtr(signed_), (size_t)size); *signatureLength = (size_t)size; }
        CFRelease(signed_);
      }
    }
    CFRelease(key);
    [context invalidate];
    return status;
  }
}
*/
import "C"

import (
	"context"
	"errors"
	"strings"
	"unsafe"
)

// The pinned key is the only key this signer may use; it never selects or
// accepts a key passed by a request.
type secureEnclaveSigner struct{ pinned []byte }

// OpenSecureEnclave returns a signer bound to the owner pin. It performs no
// Keychain query until Sign, and Sign always requires fresh user presence.
func OpenSecureEnclave(pinned []byte) (Signer, error) {
	if !ValidPublicKey(pinned) {
		return nil, ErrNotEnrolled
	}
	return &secureEnclaveSigner{pinned: append([]byte(nil), pinned...)}, nil
}

func (s *secureEnclaveSigner) PublicKey() []byte { return append([]byte(nil), s.pinned...) }

func (s *secureEnclaveSigner) Sign(ctx context.Context, message []byte, reason string) ([]byte, error) {
	if ctx.Err() != nil || len(message) == 0 {
		return nil, ErrCancelled
	}
	reason = safeReason(reason)
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	signature := make([]byte, 128)
	var length C.size_t
	status := C.envbank_owner_sign((*C.uchar)(unsafe.Pointer(&s.pinned[0])), (*C.uchar)(unsafe.Pointer(&message[0])), C.size_t(len(message)), cr, (*C.uchar)(unsafe.Pointer(&signature[0])), &length)
	if err := statusError(int(status)); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return signature[:int(length)], nil
}

// EnrollSecureEnclave creates the single owner key. It refuses when any key
// already carries the tag; rotation is a separate manual owner procedure.
func EnrollSecureEnclave() ([]byte, error) {
	public := make([]byte, PublicKeySize)
	var length C.size_t
	status := C.envbank_owner_enroll((*C.uchar)(unsafe.Pointer(&public[0])), &length)
	if status == C.errSecDuplicateItem {
		return nil, errors.New("an EnvBank owner approval key already exists; refusing to replace it")
	}
	if err := statusError(int(status)); err != nil {
		return nil, err
	}
	if int(length) != PublicKeySize || !ValidPublicKey(public) {
		return nil, ErrInvalidProof
	}
	return public, nil
}

func statusError(status int) error {
	switch status {
	case 0:
		return nil
	case -25300: // errSecItemNotFound
		return ErrNotEnrolled
	case -128, -25293, -2, -1: // user cancel, auth failed, LA cancel/failed
		return ErrCancelled
	case -34018: // errSecMissingEntitlement
		return ErrEntitlement
	case -909001, -909002, -909003:
		return ErrKeyMismatch
	default:
		return ErrUnavailable
	}
}

// safeReason keeps the system dialog text short printable ASCII.
func safeReason(reason string) string {
	var builder strings.Builder
	for _, r := range reason {
		if builder.Len() >= 180 {
			break
		}
		if r >= 0x20 && r < 0x7f {
			builder.WriteRune(r)
		}
	}
	if builder.Len() == 0 {
		return "approve an EnvBank deployment plan"
	}
	return builder.String()
}
