package testlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/mcpserver"
)

func schema(properties map[string]any, required ...string) map[string]any {
	result := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) != 0 {
		result["required"] = required
	}
	return result
}

func (extensionBackend) Tools() []mcpserver.ToolDefinition {
	stringEnum := func(values ...string) map[string]any { return map[string]any{"type": "string", "enum": values} }
	return []mcpserver.ToolDefinition{
		{Name: "envbank_test_clock_advance", Description: "Advance the bounded virtual test clock", Schema: schema(map[string]any{"duration": map[string]any{"type": "string", "maxLength": 16}}, "duration")},
		{Name: "envbank_test_fault_set", Description: "Inject a bounded test workflow fault", Schema: schema(map[string]any{
			"provider":   stringEnum("stripe", "clerk", "vercel", "railway", "browser", "any"),
			"checkpoint": stringEnum("acquire", "store", "stage:vercel", "stage:railway", "activate:vercel", "activate:railway", "verify", "grace", "revoke"),
			"behavior":   stringEnum("retryable", "ambiguous-commit", "terminal", "timeout", "unhealthy", "interrupt-after-commit", "revision-conflict", "rollback-failure"),
			"count":      map[string]any{"type": "integer", "minimum": 1, "maximum": 20},
		}, "provider", "checkpoint", "behavior", "count")},
		{Name: "envbank_test_fault_clear", Description: "Clear selected or all test faults", Schema: schema(map[string]any{"provider": stringEnum("stripe", "clerk", "vercel", "railway", "browser", "any", "all"), "checkpoint": map[string]any{"type": "string", "maxLength": 32}})},
		{Name: "envbank_test_assert_secret_flow", Description: "Compare secret flow internally without returning values or digests", Schema: schema(map[string]any{
			"operation_id":       map[string]any{"type": "string", "pattern": "^op-[0-9]{6}$"},
			"vercel_project_id":  map[string]any{"type": "string", "enum": []string{"vercel-project"}},
			"railway_project_id": map[string]any{"type": "string", "enum": []string{"railway-project"}},
		}, "operation_id")},
		{Name: "envbank_test_scenario_status", Description: "Return secret-free test scenario checkpoints and clock state", Schema: schema(map[string]any{})},
	}
}

func (backend extensionBackend) Call(_ context.Context, name string, raw json.RawMessage) (any, error) {
	lab := backend.lab
	switch name {
	case "envbank_test_clock_advance":
		var request struct {
			Duration string `json:"duration"`
		}
		if err := strict(raw, &request); err != nil {
			return nil, err
		}
		duration, err := time.ParseDuration(request.Duration)
		if err != nil {
			return nil, errors.New("invalid tool arguments")
		}
		previous, next, err := lab.clock.Advance(duration)
		if err != nil {
			return nil, err
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		if err := lab.saveLocked(); err != nil {
			return nil, err
		}
		resumable := []string{}
		for id, op := range lab.state.Operations {
			if op.State != "complete" && op.State != "terminal-failure" && op.State != "rolled-back" {
				resumable = append(resumable, id)
			}
		}
		sort.Strings(resumable)
		return map[string]any{"previous_timestamp": previous.Format(time.RFC3339), "new_timestamp": next.Format(time.RFC3339), "resumable_operation_ids": resumable}, nil
	case "envbank_test_fault_set":
		var request struct {
			Provider   string `json:"provider"`
			Checkpoint string `json:"checkpoint"`
			Behavior   string `json:"behavior"`
			Count      int    `json:"count"`
		}
		if strict(raw, &request) != nil || !oneOf(request.Provider, "stripe", "clerk", "vercel", "railway", "browser", "any") || !oneOf(request.Behavior, "retryable", "ambiguous-commit", "terminal", "timeout", "unhealthy", "interrupt-after-commit", "revision-conflict", "rollback-failure") || request.Count < 1 || request.Count > 20 || request.Checkpoint == "" {
			return nil, errors.New("invalid tool arguments")
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		lab.state.Faults[request.Provider+":"+request.Checkpoint] = fault{Behavior: request.Behavior, Remaining: request.Count}
		if err := lab.saveLocked(); err != nil {
			return nil, err
		}
		return map[string]any{"set": true, "remaining": request.Count}, nil
	case "envbank_test_fault_clear":
		var request struct {
			Provider   string `json:"provider"`
			Checkpoint string `json:"checkpoint"`
		}
		if strict(raw, &request) != nil {
			return nil, errors.New("invalid tool arguments")
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		if request.Provider == "" || request.Provider == "all" {
			lab.state.Faults = map[string]fault{}
		} else if request.Checkpoint != "" {
			delete(lab.state.Faults, request.Provider+":"+request.Checkpoint)
		} else {
			for key := range lab.state.Faults {
				if strings.HasPrefix(key, request.Provider+":") {
					delete(lab.state.Faults, key)
				}
			}
		}
		if err := lab.saveLocked(); err != nil {
			return nil, err
		}
		return map[string]any{"cleared": true}, nil
	case "envbank_test_assert_secret_flow":
		var request struct {
			OperationID      string `json:"operation_id"`
			VercelProjectID  string `json:"vercel_project_id"`
			RailwayProjectID string `json:"railway_project_id"`
		}
		if strict(raw, &request) != nil {
			return nil, errors.New("invalid tool arguments")
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		op := lab.state.Operations[request.OperationID]
		if op == nil {
			return map[string]any{"operation_found": false, "all_match": false}, nil
		}
		record := lab.state.Records[op.Record]
		flow := lab.state.Flows[op.ID]
		sourceDigest := digest(lab.oracle, record.Value)
		// Emulators receive the value only during write-only staging. Their state is
		// represented by session-keyed comparisons, never by an exportable value.
		providerMatch := bytes.Equal(sourceDigest, digest(lab.oracle, flow.Provider))
		vercelMatch := bytes.Equal(sourceDigest, digest(lab.oracle, flow.Vercel)) && (request.VercelProjectID == "" || request.VercelProjectID == "vercel-project")
		railwayMatch := bytes.Equal(sourceDigest, digest(lab.oracle, flow.Railway)) && (request.RailwayProjectID == "" || request.RailwayProjectID == "railway-project")
		return map[string]any{"operation_found": true, "provider_to_record": record.Revision == op.Revision && providerMatch, "vercel_match": vercelMatch, "railway_match": railwayMatch, "all_match": record.Revision == op.Revision && providerMatch && vercelMatch && railwayMatch && flow.Active, "resource_ids": append([]string(nil), op.Resources...)}, nil
	case "envbank_test_scenario_status":
		var request struct{}
		if strict(raw, &request) != nil {
			return nil, errors.New("invalid tool arguments")
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		operations := make([]map[string]any, 0, len(lab.state.Operations))
		ids := make([]string, 0, len(lab.state.Operations))
		for id := range lab.state.Operations {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			op := lab.state.Operations[id]
			operations = append(operations, map[string]any{"operation_id": id, "provider": op.Provider, "stage": op.State, "completed_checkpoints": append([]string(nil), op.Checkpoints...), "quarantined": op.Quarantined})
		}
		failures := 0
		for _, item := range lab.state.Faults {
			failures += item.Remaining
		}
		return map[string]any{"scenario": defaultBundle, "clock_timestamp": lab.clock.Now().Format(time.RFC3339), "lease_owner": lab.state.LeaseOwner, "outstanding_expected_failures": failures, "operations": operations}, nil
	default:
		return nil, errors.New("unknown tool")
	}
}

func strict(raw json.RawMessage, destination any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid tool arguments")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid tool arguments")
	}
	return nil
}
func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
