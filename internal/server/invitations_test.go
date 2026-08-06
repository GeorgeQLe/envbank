package server

import (
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	_ "modernc.org/sqlite"
)

type invitationFixture struct {
	service    *Server
	vaultID    string
	vaultKey   []byte
	activeAPI  *client.API
	pendingAPI *client.API
	status     protocol.InvitationStatus
}

func newInvitationFixture(t *testing.T, service *Server) invitationFixture {
	t.Helper()
	activeKeys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, err := secure.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	activeAPI := NewTestAPI(service)
	created, err := activeAPI.CreateVault("invitations", protocol.PublicDevice{
		Name: "active", SigningPublic: activeKeys.SigningPublic,
		WrappingPublic: activeKeys.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	activeAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: created.DeviceID}
	activeAPI.Secrets = activeKeys.Secrets
	pendingKeys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	status, err := activeAPI.CreateInvitation(created.VaultID, protocol.InvitationRequest{
		Version: protocol.InvitationProtocolVersion, Name: "pending",
		SigningPublic: pendingKeys.SigningPublic, WrappingPublic: pendingKeys.WrappingPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	pendingAPI := NewTestAPI(service)
	pendingAPI.Config = &client.Config{VaultID: created.VaultID, DeviceID: status.Device.ID}
	pendingAPI.Secrets = pendingKeys.Secrets
	return invitationFixture{service: service, vaultID: created.VaultID, vaultKey: vaultKey,
		activeAPI: activeAPI, pendingAPI: pendingAPI, status: status}
}

func transitionFor(status protocol.InvitationStatus) protocol.InvitationTransition {
	return protocol.InvitationTransition{Version: status.Version, DeviceID: status.Device.ID,
		Fingerprint: status.Device.Fingerprint}
}

func approvalFor(t *testing.T, fixture invitationFixture) protocol.InvitationApproval {
	t.Helper()
	envelope, err := secure.WrapVaultKey(fixture.vaultKey,
		fixture.status.Device.WrappingPublic, fixture.vaultID, fixture.status.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.InvitationApproval{Version: fixture.status.Version,
		DeviceID: fixture.status.Device.ID, Fingerprint: fixture.status.Device.Fingerprint,
		Envelope: envelope}
}

func TestInvitationApprovalAndEnvelopeRedaction(t *testing.T) {
	service, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	fixture := newInvitationFixture(t, service)
	if fixture.status.State != protocol.InvitationPending ||
		fixture.status.AttemptsRemaining != invitationMaxAttempts {
		t.Fatalf("created status = %#v", fixture.status)
	}
	activeStatus, err := fixture.activeAPI.GetInvitation(fixture.status.Device.ID)
	if err != nil || activeStatus.Envelope != nil {
		t.Fatalf("active pending inspection = %#v, %v", activeStatus, err)
	}
	approved, err := fixture.activeAPI.ApproveInvitation(fixture.status.Device.ID,
		approvalFor(t, fixture))
	if err != nil || approved.State != protocol.InvitationApproved {
		t.Fatalf("approval = %#v, %v", approved, err)
	}
	activeStatus, err = fixture.activeAPI.GetInvitation(fixture.status.Device.ID)
	if err != nil || activeStatus.Envelope != nil {
		t.Fatalf("active approved inspection exposed envelope: %#v, %v", activeStatus, err)
	}
	intended, err := fixture.pendingAPI.GetInvitation(fixture.status.Device.ID)
	if err != nil || intended.Envelope == nil {
		t.Fatalf("intended device did not recover envelope: %#v, %v", intended, err)
	}
	if _, err := fixture.activeAPI.ApproveInvitation(fixture.status.Device.ID,
		approvalFor(t, fixture)); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("terminal approval replay = %v", err)
	}
	var devices int
	if err := service.db.QueryRow(`SELECT COUNT(*) FROM devices
		WHERE vault_id = ? AND id = ?`, fixture.vaultID,
		fixture.status.Device.ID).Scan(&devices); err != nil || devices != 1 {
		t.Fatalf("inserted devices = %d, %v", devices, err)
	}
}

func TestInvitationCancelRejectExpireAndAttemptExhaustion(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		service, _ := Open("")
		defer service.Close()
		fixture := newInvitationFixture(t, service)
		cancelled, err := fixture.pendingAPI.CancelInvitation(fixture.status.Device.ID,
			transitionFor(fixture.status))
		if err != nil || cancelled.State != protocol.InvitationCancelled {
			t.Fatalf("cancel = %#v, %v", cancelled, err)
		}
		if _, err := fixture.activeAPI.ApproveInvitation(fixture.status.Device.ID,
			approvalFor(t, fixture)); err == nil || !strings.Contains(err.Error(), "409") {
			t.Fatalf("approval after confirmed cancellation = %v", err)
		}
	})
	t.Run("reject", func(t *testing.T) {
		service, _ := Open("")
		defer service.Close()
		fixture := newInvitationFixture(t, service)
		rejected, err := fixture.activeAPI.RejectInvitation(fixture.status.Device.ID,
			transitionFor(fixture.status))
		if err != nil || rejected.State != protocol.InvitationRejected {
			t.Fatalf("reject = %#v, %v", rejected, err)
		}
	})
	t.Run("expire", func(t *testing.T) {
		service, _ := Open("")
		defer service.Close()
		base := time.Now().UTC().Truncate(time.Second)
		service.now = func() time.Time { return base }
		fixture := newInvitationFixture(t, service)
		later := base.Add(invitationLifetime)
		service.now = func() time.Time { return later }
		fixture.pendingAPI.Now = func() time.Time { return later }
		expired, err := fixture.pendingAPI.GetInvitation(fixture.status.Device.ID)
		if err != nil || expired.State != protocol.InvitationExpired {
			t.Fatalf("expired status = %#v, %v", expired, err)
		}
	})
	t.Run("attempts", func(t *testing.T) {
		service, _ := Open("")
		defer service.Close()
		fixture := newInvitationFixture(t, service)
		bad := transitionFor(fixture.status)
		bad.Fingerprint = "0000000000000000"
		for attempt := 1; attempt <= invitationMaxAttempts; attempt++ {
			_, err := fixture.activeAPI.RejectInvitation(fixture.status.Device.ID, bad)
			if err == nil {
				t.Fatalf("attempt %d succeeded", attempt)
			}
			status, statusErr := fixture.pendingAPI.GetInvitation(fixture.status.Device.ID)
			if statusErr != nil {
				t.Fatal(statusErr)
			}
			if status.AttemptsRemaining != invitationMaxAttempts-attempt {
				t.Fatalf("attempt %d remaining = %d", attempt, status.AttemptsRemaining)
			}
			if attempt == invitationMaxAttempts &&
				status.State != protocol.InvitationAttemptsExhausted {
				t.Fatalf("fifth failure state = %s", status.State)
			}
		}
	})
}

func TestInvitationLegacyApprovalCannotBypassLifecycle(t *testing.T) {
	service, _ := Open("")
	defer service.Close()
	fixture := newInvitationFixture(t, service)
	if err := fixture.activeAPI.ApproveEnrollment(fixture.status.Device.ID,
		approvalFor(t, fixture).Envelope); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("legacy approval bypass = %v", err)
	}
	legacyKeys, _ := secure.NewDeviceKeys()
	legacy, err := fixture.activeAPI.RequestEnrollment(fixture.vaultID,
		protocol.EnrollmentRequest{Name: "legacy", SigningPublic: legacyKeys.SigningPublic,
			WrappingPublic: legacyKeys.WrappingPublic})
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := secure.WrapVaultKey(fixture.vaultKey, legacyKeys.WrappingPublic,
		fixture.vaultID, legacy.Device.ID)
	if err := fixture.activeAPI.ApproveEnrollment(legacy.Device.ID, envelope); err != nil {
		t.Fatalf("legacy enrollment stopped working: %v", err)
	}
}

func TestInvitationRejectsRevokedAndUnrelatedActors(t *testing.T) {
	t.Run("revoked active device", func(t *testing.T) {
		service, _ := Open("")
		defer service.Close()
		fixture := newInvitationFixture(t, service)

		secondKeys, _ := secure.NewDeviceKeys()
		legacy, err := fixture.activeAPI.RequestEnrollment(fixture.vaultID,
			protocol.EnrollmentRequest{Name: "second active",
				SigningPublic:  secondKeys.SigningPublic,
				WrappingPublic: secondKeys.WrappingPublic})
		if err != nil {
			t.Fatal(err)
		}
		envelope, _ := secure.WrapVaultKey(fixture.vaultKey, secondKeys.WrappingPublic,
			fixture.vaultID, legacy.Device.ID)
		if err := fixture.activeAPI.ApproveEnrollment(legacy.Device.ID, envelope); err != nil {
			t.Fatal(err)
		}
		secondAPI := NewTestAPI(service)
		secondAPI.Config = &client.Config{VaultID: fixture.vaultID, DeviceID: legacy.Device.ID}
		secondAPI.Secrets = secondKeys.Secrets
		if _, err := secondAPI.RevokeDevice(fixture.activeAPI.Config.DeviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.activeAPI.RejectInvitation(fixture.status.Device.ID,
			transitionFor(fixture.status)); err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("revoked rejection = %v", err)
		}
		if _, err := fixture.activeAPI.ApproveInvitation(fixture.status.Device.ID,
			approvalFor(t, fixture)); err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("revoked approval = %v", err)
		}
		status, err := fixture.pendingAPI.GetInvitation(fixture.status.Device.ID)
		if err != nil || status.AttemptsRemaining != invitationMaxAttempts {
			t.Fatalf("revoked requests consumed attempts: %#v, %v", status, err)
		}
	})
	t.Run("unrelated pending device", func(t *testing.T) {
		service, _ := Open("")
		defer service.Close()
		fixture := newInvitationFixture(t, service)
		otherKeys, _ := secure.NewDeviceKeys()
		other, err := fixture.activeAPI.CreateInvitation(fixture.vaultID,
			protocol.InvitationRequest{Version: protocol.InvitationProtocolVersion,
				Name: "other", SigningPublic: otherKeys.SigningPublic,
				WrappingPublic: otherKeys.WrappingPublic})
		if err != nil {
			t.Fatal(err)
		}
		otherAPI := NewTestAPI(service)
		otherAPI.Config = &client.Config{VaultID: fixture.vaultID, DeviceID: other.Device.ID}
		otherAPI.Secrets = otherKeys.Secrets
		if _, err := otherAPI.GetInvitation(fixture.status.Device.ID); err == nil ||
			!strings.Contains(err.Error(), "401") {
			t.Fatalf("unrelated inspection = %v", err)
		}
		if _, err := otherAPI.CancelInvitation(fixture.status.Device.ID,
			transitionFor(fixture.status)); err == nil {
			t.Fatal("unrelated pending device cancelled invitation")
		}
		status, err := fixture.pendingAPI.GetInvitation(fixture.status.Device.ID)
		if err != nil || status.State != protocol.InvitationPending ||
			status.AttemptsRemaining != invitationMaxAttempts-1 {
			t.Fatalf("unrelated actor accounting = %#v, %v", status, err)
		}
	})
}

func TestInvitationEventFailureRollsBackApproval(t *testing.T) {
	service, _ := Open("")
	defer service.Close()
	fixture := newInvitationFixture(t, service)
	if _, err := service.db.Exec(`CREATE TRIGGER fail_invitation_event
		BEFORE INSERT ON access_events WHEN NEW.operation = 'invitation_approval'
		BEGIN SELECT RAISE(FAIL, 'forced event failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.activeAPI.ApproveInvitation(fixture.status.Device.ID,
		approvalFor(t, fixture)); err == nil {
		t.Fatal("approval succeeded despite event failure")
	}
	var state string
	var approved, devices, envelopeBytes, nonces int
	if err := service.db.QueryRow(`SELECT i.state, e.approved, COALESCE(length(e.envelope), 0)
		FROM invitations i JOIN enrollments e
		ON e.vault_id = i.vault_id AND e.device_id = i.device_id
		WHERE i.vault_id = ? AND i.device_id = ?`, fixture.vaultID,
		fixture.status.Device.ID).Scan(&state, &approved, &envelopeBytes); err != nil {
		t.Fatal(err)
	}
	_ = service.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE vault_id = ? AND id = ?`,
		fixture.vaultID, fixture.status.Device.ID).Scan(&devices)
	_ = service.db.QueryRow(`SELECT COUNT(*) FROM nonces WHERE vault_id = ?`,
		fixture.vaultID).Scan(&nonces)
	if state != protocol.InvitationPending || approved != 0 || envelopeBytes != 0 ||
		devices != 0 || nonces != 0 {
		t.Fatalf("rollback state=%s approved=%d envelope=%d devices=%d nonces=%d",
			state, approved, envelopeBytes, devices, nonces)
	}
}

func TestInvitationEventFailureRollsBackAttemptAndNonce(t *testing.T) {
	service, _ := Open("")
	defer service.Close()
	fixture := newInvitationFixture(t, service)
	if _, err := service.db.Exec(`CREATE TRIGGER fail_invitation_rejection_event
		BEFORE INSERT ON access_events WHEN NEW.operation = 'invitation_rejection'
		BEGIN SELECT RAISE(FAIL, 'forced event failure'); END`); err != nil {
		t.Fatal(err)
	}
	bad := transitionFor(fixture.status)
	bad.DeviceID = "wrong-device-binding"
	if _, err := fixture.activeAPI.RejectInvitation(fixture.status.Device.ID, bad); err == nil {
		t.Fatal("failed attempt succeeded despite event failure")
	}
	var attempts, nonces int
	if err := service.db.QueryRow(`SELECT failed_attempts FROM invitations
		WHERE vault_id = ? AND device_id = ?`, fixture.vaultID,
		fixture.status.Device.ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := service.db.QueryRow(`SELECT COUNT(*) FROM nonces
		WHERE vault_id = ?`, fixture.vaultID).Scan(&nonces); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || nonces != 0 {
		t.Fatalf("failed event left attempts=%d nonces=%d", attempts, nonces)
	}
}

func TestInvitationApprovalCancellationRaceAcrossServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	fixture := newInvitationFixture(t, first)
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	pendingOnSecond := NewTestAPI(second)
	pendingOnSecond.Config, pendingOnSecond.Secrets =
		fixture.pendingAPI.Config, fixture.pendingAPI.Secrets

	start := make(chan struct{})
	results := make(chan error, 2)
	approval := approvalFor(t, fixture)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := fixture.activeAPI.ApproveInvitation(fixture.status.Device.ID, approval)
		results <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := pendingOnSecond.CancelInvitation(fixture.status.Device.ID,
			transitionFor(fixture.status))
		results <- err
	}()
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("terminal winners = %d", successes)
	}
	var state string
	var devices int
	if err := first.db.QueryRow(`SELECT state FROM invitations
		WHERE vault_id = ? AND device_id = ?`, fixture.vaultID,
		fixture.status.Device.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := first.db.QueryRow(`SELECT COUNT(*) FROM devices
		WHERE vault_id = ? AND id = ?`, fixture.vaultID,
		fixture.status.Device.ID).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if state != protocol.InvitationApproved && state != protocol.InvitationCancelled {
		t.Fatalf("terminal state = %s", state)
	}
	if devices > 1 || (state == protocol.InvitationCancelled && devices != 0) {
		t.Fatalf("state=%s devices=%d", state, devices)
	}
}

func TestSchemaThreeToFourPreservesEventsWithoutInvitationBackfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.db")
	service, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newInvitationFixture(t, service)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE invitations;
		DROP INDEX IF EXISTS invitations_vault_state_expiry;
		PRAGMA user_version = 3;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var version, invitations, enrollments, events int
	_ = migrated.db.QueryRow("PRAGMA user_version").Scan(&version)
	_ = migrated.db.QueryRow("SELECT COUNT(*) FROM invitations").Scan(&invitations)
	_ = migrated.db.QueryRow("SELECT COUNT(*) FROM enrollments").Scan(&enrollments)
	_ = migrated.db.QueryRow("SELECT COUNT(*) FROM access_events").Scan(&events)
	if version != 4 || invitations != 0 || enrollments != 1 || events == 0 {
		t.Fatalf("version=%d invitations=%d enrollments=%d events=%d fixture=%s",
			version, invitations, enrollments, events, fixture.status.Device.ID)
	}
}
