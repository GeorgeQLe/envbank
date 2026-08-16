// Command envbank-e2e-nativehost is a test-only native messaging fixture.
// It reuses production framing and keeps one synthetic value only in memory.
package main

import (
	"io"
	"os"
	"time"

	"github.com/GeorgeQLe/envbank/internal/nativehost"
)

const marker = "ENVBANK_E2E_SECRET_DO_NOT_LEAK"

func main() {
	revision := int64(1)
	allowedOrigin := ""
	for {
		var request nativehost.Request
		if err := nativehost.ReadMessage(os.Stdin, &request); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			return
		}
		if request.Name == "DISCONNECT" && request.Action == "get_for_fill" {
			return
		}
		if request.Name == "TIMEOUT" && request.Action == "get_for_fill" {
			time.Sleep(20 * time.Second)
			return
		}
		response := nativehost.Response{Version: nativehost.ProtocolVersion, ID: request.ID, OK: true}
		switch request.Action {
		case "list_for_origin":
			if allowedOrigin == "" {
				allowedOrigin = request.Origin
			}
			response.Result = []nativehost.ListedRecord{
				{Name: "E2E_VALUE", Allowed: request.Origin == allowedOrigin, Revision: revision},
				{Name: "DISCONNECT", Allowed: request.Origin == allowedOrigin, Revision: 1},
				{Name: "TIMEOUT", Allowed: request.Origin == allowedOrigin, Revision: 1},
			}
		case "allow_origin":
			allowedOrigin = request.Origin
			response.Result = map[string]any{"name": request.Name, "origin": request.Origin}
		case "generate_password":
			if request.ExpectedRevision != revision {
				response.OK = false
				response.Error = "record changed or replacement was not confirmed"
				break
			}
			revision++
			response.Result = nativehost.ListedRecord{Name: request.Name, Allowed: true, Revision: revision, RotatedAt: "2026-08-14T00:00:00Z", RotateEveryDays: 90}
		case "get_for_fill":
			if request.Origin != allowedOrigin {
				response.OK = false
				response.Error = "variable is not allowed on this origin"
				break
			}
			response.Result = map[string]string{"value": marker}
		case "lock":
			response.Result = map[string]bool{"locked": true}
		default:
			response.OK = false
			response.Error = "unknown native action"
		}
		if nativehost.WriteMessage(os.Stdout, response) != nil {
			return
		}
	}
}
