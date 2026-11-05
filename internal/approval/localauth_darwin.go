//go:build darwin && cgo

package approval

/*
#cgo CFLAGS: -x objective-c -fno-objc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>

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

// envbank_la_evaluate shows the system prompt with `reason` and waits at most
// timeout_ms. Any error other than "no biometry" is a denial.
static int envbank_la_evaluate(const char *reason, int allow_password, long long timeout_ms) {
	@autoreleasepool {
		LAPolicy policy = envbank_la_policy(allow_password);
		LAContext *ctx = [[LAContext alloc] init];
		if (!allow_password) ctx.localizedFallbackTitle = @""; // biometrics only: no "Enter Password" button
		ctx.touchIDAuthenticationAllowableReuseDuration = 0; // every approval is a fresh touch
		NSError *err = nil;
		if (![ctx canEvaluatePolicy:policy error:&err]) {
			[ctx release];
			return LA_UNAVAILABLE;
		}
		NSString *why = [NSString stringWithUTF8String:reason];
		if (why == nil || why.length == 0) {
			[ctx release];
			return LA_DENIED;
		}
		__block int result = LA_DENIED;
		dispatch_semaphore_t done = dispatch_semaphore_create(0);
		[ctx evaluatePolicy:policy localizedReason:why reply:^(BOOL success, NSError *error) {
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
		[ctx release];
		return out;
	}
}
*/
import "C"

import (
	"context"
	"time"
	"unsafe"
)

// LocalAuth approves with LocalAuthentication. By default it uses
// LAPolicyDeviceOwnerAuthenticationWithBiometrics (no device-passcode
// fallback). AllowPasscode is set only by the owner's own
// --allow-password-fallback flag and selects LAPolicyDeviceOwnerAuthentication.
type LocalAuth struct {
	AllowPasscode bool
	Timeout       time.Duration
}

func boolInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// Available implements Approver (canEvaluatePolicy; never prompts).
func (l LocalAuth) Available() bool { return C.envbank_la_available(boolInt(l.AllowPasscode)) == 1 }

// Approve implements Approver.
func (l LocalAuth) Approve(ctx context.Context, reason string) Outcome {
	if ctx.Err() != nil {
		return Denied
	}
	timeout := l.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
		timeout = time.Until(dl)
	}
	// Too little time left for the owner to read and touch: do not flash a prompt.
	if timeout < MinPromptTime || reason == "" || len(reason) > MaxReasonBytes+8 {
		return Denied
	}
	creason := C.CString(reason)
	defer C.free(unsafe.Pointer(creason))
	// The call blocks this OS thread until the owner answers or the timeout.
	rc := C.envbank_la_evaluate(creason, boolInt(l.AllowPasscode), C.longlong(timeout.Milliseconds()))
	if ctx.Err() != nil {
		return Denied // the requester went away while the owner was deciding
	}
	switch rc {
	case 1:
		return Approved
	case 2:
		return Unavailable
	default:
		return Denied
	}
}
