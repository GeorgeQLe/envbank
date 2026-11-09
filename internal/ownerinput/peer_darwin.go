//go:build darwin && cgo

package ownerinput

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <Security/Security.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <string.h>
#include <stdlib.h>

#ifndef LOCAL_PEERTOKEN
#define LOCAL_PEERTOKEN 0x006
#endif

// Result codes (fixed; no paths or names of other processes).
enum { PEER_OK = 0, PEER_NO_TOKEN = 1, PEER_NO_CODE = 2, PEER_INVALID = 3, PEER_NO_INFO = 4, PEER_UID = 5 };

static void cfstr(CFStringRef s, char *out, size_t n) {
	out[0] = 0;
	if (s && CFGetTypeID(s) == CFStringGetTypeID()) CFStringGetCString(s, out, (CFIndex)n, kCFStringEncodingUTF8);
}

// envbank_peer_identity validates the connected peer's dynamic code signature
// against `requirement` and reports team, identifier, cdhash and flags.
static int envbank_peer_identity(int fd, const char *requirement, uid_t want_uid,
		char *team, char *ident, char *cdhash, uint32_t *flags) {
	audit_token_t token;
	socklen_t len = sizeof(token);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0 || len != sizeof(token)) return PEER_NO_TOKEN;
	if (audit_token_to_euid(token) != want_uid) return PEER_UID;
	CFDataRef tokenData = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *vals[] = { tokenData };
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs); CFRelease(tokenData);
	if (st != errSecSuccess || !code) return PEER_NO_CODE;
	CFStringRef reqStr = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
	SecRequirementRef req = NULL;
	st = SecRequirementCreateWithString(reqStr, kSecCSDefaultFlags, &req);
	CFRelease(reqStr);
	if (st != errSecSuccess) { CFRelease(code); return PEER_INVALID; }
	st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	CFRelease(req);
	if (st != errSecSuccess) { CFRelease(code); return PEER_INVALID; }
	SecStaticCodeRef staticCode = NULL;
	CFDictionaryRef info = NULL;
	if (SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &staticCode) != errSecSuccess ||
	    SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation | kSecCSDynamicInformation, &info) != errSecSuccess || !info) {
		if (staticCode) CFRelease(staticCode);
		CFRelease(code);
		return PEER_NO_INFO;
	}
	cfstr(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), team, 64);
	cfstr(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), ident, 256);
	CFDataRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
	cdhash[0] = 0;
	if (unique && CFGetTypeID(unique) == CFDataGetTypeID()) {
		const UInt8 *b = CFDataGetBytePtr(unique);
		CFIndex n = CFDataGetLength(unique);
		static const char hex[] = "0123456789abcdef";
		for (CFIndex i = 0; i < n && i < 32; i++) { cdhash[2*i] = hex[b[i] >> 4]; cdhash[2*i+1] = hex[b[i] & 15]; cdhash[2*i+2] = 0; }
	}
	CFNumberRef f = CFDictionaryGetValue(info, kSecCodeInfoFlags);
	*flags = 0;
	if (f) CFNumberGetValue(f, kCFNumberSInt32Type, flags);
	CFRelease(info); CFRelease(staticCode); CFRelease(code);
	return PEER_OK;
}
*/
import "C"

import (
	"errors"
	"net"
	"os"
	"unsafe"
)

// kSecCodeSignatureRuntime (hardened runtime) from CSCommon.h.
const signatureRuntime = 0x10000

func peerIdentity(conn *net.UnixConn, requirement string) (Identity, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Identity{}, errors.New(CodePeerUnverified)
	}
	var team [64]C.char
	var ident [256]C.char
	var cdhash [80]C.char
	var flags C.uint32_t
	var rc C.int = -1
	creq := C.CString(requirement)
	defer C.free(unsafe.Pointer(creq))
	ctl := raw.Control(func(fd uintptr) {
		rc = C.envbank_peer_identity(C.int(fd), creq, C.uid_t(os.Getuid()), &team[0], &ident[0], &cdhash[0], &flags)
	})
	if ctl != nil || rc != 0 {
		return Identity{}, errors.New(CodePeerUnverified)
	}
	id := Identity{TeamID: C.GoString(&team[0]), Identifier: C.GoString(&ident[0]), CDHash: C.GoString(&cdhash[0]), HardenedRuntime: uint32(flags)&signatureRuntime != 0}
	if id.CDHash == "" || !id.HardenedRuntime {
		return Identity{}, errors.New(CodePeerUnverified)
	}
	return id, nil
}
