//go:build darwin && cgo

package approval

/*
#cgo CFLAGS: -x objective-c -fno-objc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>

enum { LA_DENIED = 0, LA_APPROVED = 1, LA_UNAVAILABLE = 2 };

static LAPolicy envbank_la_policy(int allow_password) {
	return allow_password ? LAPolicyDeviceOwnerAuthentication : LAPolicyDeviceOwnerAuthenticationWithBiometrics;
}

// envbank_la_available asks LocalAuthentication whether the policy can be
// evaluated (biometry present and enrolled; never prompts).
static int envbank_la_available(int allow_password) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		NSError *err = nil;
		BOOL ok = [ctx canEvaluatePolicy:envbank_la_policy(allow_password) error:&err];
		[ctx release];
		return ok ? 1 : 0;
	}
}

// envbank_la_open returns a retained LAContext configured for one approval,
// or NULL (with *rc = LA_UNAVAILABLE) if the policy cannot be evaluated. It
// never prompts.
static void *envbank_la_open(int allow_password, int *rc) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		if (!allow_password) ctx.localizedFallbackTitle = @""; // biometrics only: no "Enter Password" button
		ctx.touchIDAuthenticationAllowableReuseDuration = 0; // every approval is a fresh touch
		NSError *err = nil;
		if (![ctx canEvaluatePolicy:envbank_la_policy(allow_password) error:&err]) {
			[ctx release];
			*rc = LA_UNAVAILABLE;
			return NULL;
		}
		*rc = LA_APPROVED;
		return ctx;
	}
}

// envbank_la_state copies the biometric enrollment state hash of ctx (valid
// after canEvaluatePolicy or evaluatePolicy) into out. It returns the length,
// 0 when there is none, or -1 if it does not fit.
static int envbank_la_state(void *p, unsigned char *out, int cap) {
	@autoreleasepool {
		LAContext *ctx = (LAContext *)p;
		NSData *d = nil;
#if defined(__MAC_15_0)
		if (@available(macOS 15.0, *)) {
			d = ctx.domainState.biometry.stateHash;
		} else
#endif
		{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
			d = ctx.evaluatedPolicyDomainState;
#pragma clang diagnostic pop
		}
		if (d == nil) return 0;
		if ((int)d.length > cap) return -1;
		memcpy(out, d.bytes, d.length);
		return (int)d.length;
	}
}

// envbank_la_evaluate shows the system prompt with `reason` and waits at most
// timeout_ms. Any error other than "no biometry" is a denial.
static int envbank_la_evaluate(void *p, const char *reason, int allow_password, long long timeout_ms) {
	@autoreleasepool {
		LAContext *ctx = (LAContext *)p;
		NSString *why = [NSString stringWithUTF8String:reason];
		if (why == nil || why.length == 0) return LA_DENIED;
		__block int result = LA_DENIED;
		dispatch_semaphore_t done = dispatch_semaphore_create(0);
		[ctx evaluatePolicy:envbank_la_policy(allow_password) localizedReason:why reply:^(BOOL success, NSError *error) {
			if (success) {
				result = LA_APPROVED;
			} else if (error != nil && [error.domain isEqualToString:LAErrorDomain] &&
			           (error.code == LAErrorBiometryNotAvailable || error.code == LAErrorBiometryNotEnrolled ||
			            error.code == LAErrorBiometryLockout || error.code == LAErrorPasscodeNotSet)) {
				result = LA_UNAVAILABLE;
			} else {
				result = LA_DENIED;
			}
			dispatch_semaphore_signal(done);
		}];
		long waited = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, timeout_ms * NSEC_PER_MSEC));
		int out = result;
		if (waited != 0) {
			[ctx invalidate]; // dismisses the prompt; the reply then reports a cancel
			dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
			out = LA_DENIED;
		}
		dispatch_release(done);
		return out;
	}
}

// envbank_la_invalidate dismisses any prompt of ctx (callable from any
// thread); a pending evaluation then replies with a cancel.
static void envbank_la_invalidate(void *p) { [(LAContext *)p invalidate]; }

static void envbank_la_release(void *p) { [(LAContext *)p release]; }
*/
import "C"

import (
	"unsafe"
)

// laHandle is one LAContext.
type laHandle = unsafe.Pointer

// laBackend is the LocalAuthentication glue; tests replace it.
type laBackend interface {
	available(allowPasscode bool) bool
	open(allowPasscode bool) (laHandle, bool)
	state(h laHandle) ([]byte, bool)
	evaluate(h laHandle, reason string, allowPasscode bool, timeoutMS int64) int
	invalidate(h laHandle)
	release(h laHandle)
}

type cBackend struct{}

func boolInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

func (cBackend) available(allow bool) bool { return C.envbank_la_available(boolInt(allow)) == 1 }

func (cBackend) open(allow bool) (laHandle, bool) {
	var rc C.int
	h := C.envbank_la_open(boolInt(allow), &rc)
	return laHandle(h), h != nil
}

func (cBackend) state(h laHandle) ([]byte, bool) {
	var buf [512]byte
	n := C.envbank_la_state(h, (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n < 0 {
		return nil, false
	}
	return append([]byte(nil), buf[:n]...), true
}

func (cBackend) evaluate(h laHandle, reason string, allow bool, timeoutMS int64) int {
	creason := C.CString(reason)
	defer C.free(unsafe.Pointer(creason))
	// The call blocks this OS thread until the owner answers, the timeout
	// passes or the context is invalidated.
	return int(C.envbank_la_evaluate(h, creason, boolInt(allow), C.longlong(timeoutMS)))
}

func (cBackend) invalidate(h laHandle) { C.envbank_la_invalidate(h) }
func (cBackend) release(h laHandle)    { C.envbank_la_release(h) }

var la laBackend = cBackend{}
