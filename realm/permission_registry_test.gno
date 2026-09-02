package permission_registry

import (
	"strings"
	"testing"

	"gno.land/p/nt/testutils/v0"
	"gno.land/p/nt/uassert/v0"
)

var (
	admin    = testutils.TestAddress("admin")
	alice    = testutils.TestAddress("alice")
	bob      = testutils.TestAddress("bob")
	attacker = testutils.TestAddress("attacker")
	newAdmin = testutils.TestAddress("newadmin")
)

// resetState resets all package-level state between tests.
func resetState() {
	resources = make(map[string]address)
	resourceNames = []string{}
	permissions = make(map[string]map[string]map[address]bool)
	permList = make(map[string][]string)
	retired = make(map[string]*Reservation)
	resourceCreators = make(map[string]address)
}

func createVault() {
	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross, "vault")
}

// ---------- CreateResource ----------

func TestCreate_Basic(cur realm, t *testing.T) {
	resetState()
	createVault()

	uassert.Equal(t, string(admin), GetAdmin("vault"))
	uassert.Equal(t, "vault", ListResources())
}

func TestCreate_DuplicateRejected(cur realm, t *testing.T) {
	resetState()
	createVault()

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t,
		"resource already exists: vault",
		func() { CreateResource(cross, "vault") },
	)
}

func TestCreate_NameValidation(cur realm, t *testing.T) {
	resetState()
	testing.SetRealm(testing.NewUserRealm(admin))

	for _, bad := range []string{"", "Vault", "has space", "pipe|name", strings.Repeat("a", MaxNameLen+1)} {
		uassert.AbortsContains(t,
			"resource name must be",
			func() { CreateResource(cross, bad) },
		)
	}
}

func TestCreate_GlobalCap(cur realm, t *testing.T) {
	resetState()
	testing.SetRealm(testing.NewUserRealm(admin))

	for i := 0; i < MaxResources; i++ {
		CreateResource(cross, "res_"+strings.Repeat("x", i%3)+string(rune('a'+i%26))+itoa(i))
	}
	uassert.AbortsWithMessage(t,
		"global resource limit reached",
		func() { CreateResource(cross, "one_too_many") },
	)
}

// small local itoa to build unique names without strconv import clutter
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// ---------- DeleteResource + squat protection ----------

func TestDelete_NameStaysReservedForAdmin(cur realm, t *testing.T) {
	resetState()
	createVault()

	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross, "vault", "withdraw", alice)
	DeleteResource(cross, "vault")

	uassert.Equal(t, "not found", GetAdmin("vault"))
	uassert.False(t, Has("vault", "withdraw", alice), "permissions must die with the resource")

	// the squat the audit found: an attacker re-creates the freed name
	// and becomes admin of every consumer's authorization decisions
	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t,
		"resource name is reserved for its former admin: vault",
		func() { CreateResource(cross, "vault") },
	)

	// the former admin can re-create it
	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross, "vault")
	uassert.Equal(t, string(admin), GetAdmin("vault"))
}

func TestDelete_AdminOnly(cur realm, t *testing.T) {
	resetState()
	createVault()

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t,
		"permission denied: caller is not admin of vault",
		func() { DeleteResource(cross, "vault") },
	)
}

// ---------- Grant / Revoke ----------

func TestGrant_AdminOnly(cur realm, t *testing.T) {
	resetState()
	createVault()

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t,
		"permission denied: caller is not admin of vault",
		func() { Grant(cross, "vault", "withdraw", attacker) },
	)
	uassert.False(t, Has("vault", "withdraw", attacker), "denied grant must not stick")
}

func TestGrant_And_Has(cur realm, t *testing.T) {
	resetState()
	createVault()

	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross, "vault", "withdraw", alice)

	uassert.True(t, Has("vault", "withdraw", alice), "granted permission must hold")
	uassert.False(t, Has("vault", "withdraw", bob), "ungranted address must not hold")
	uassert.False(t, Has("vault", "deposit", alice), "ungranted permission must not hold")
	uassert.False(t, Has("ghost", "withdraw", alice), "unknown resource is false, never a panic")
}

func TestGrant_Validation(cur realm, t *testing.T) {
	resetState()
	createVault()
	testing.SetRealm(testing.NewUserRealm(admin))

	uassert.AbortsContains(t, "permission name must be",
		func() { Grant(cross, "vault", "Bad|Name", alice) })
	uassert.AbortsWithMessage(t, "invalid address: junk",
		func() { Grant(cross, "vault", "withdraw", address("junk")) })

	Grant(cross, "vault", "withdraw", alice)
	uassert.AbortsContains(t, "permission already granted",
		func() { Grant(cross, "vault", "withdraw", alice) })
}

func TestRevoke_RemovesAndPrunes(cur realm, t *testing.T) {
	resetState()
	createVault()
	testing.SetRealm(testing.NewUserRealm(admin))

	Grant(cross, "vault", "withdraw", alice)
	Grant(cross, "vault", "deposit", alice)
	Revoke(cross, "vault", "withdraw", alice)

	uassert.False(t, Has("vault", "withdraw", alice), "revoked permission must not hold")
	uassert.True(t, Has("vault", "deposit", alice), "other permissions must survive")
	// pruning: the emptied permission leaves the per-resource list
	uassert.Equal(t, 1, len(permList["vault"]))
	uassert.Equal(t, "deposit", permList["vault"][0])

	uassert.AbortsContains(t, "permission not granted",
		func() { Revoke(cross, "vault", "withdraw", alice) })
}

func TestRevoke_AdminOnly(cur realm, t *testing.T) {
	resetState()
	createVault()
	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross, "vault", "withdraw", alice)

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t,
		"permission denied: caller is not admin of vault",
		func() { Revoke(cross, "vault", "withdraw", alice) },
	)
	uassert.True(t, Has("vault", "withdraw", alice), "denied revoke must not stick")
}

// ---------- TransferAdmin ----------

func TestTransferAdmin(cur realm, t *testing.T) {
	resetState()
	createVault()

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t,
		"permission denied: caller is not admin of vault",
		func() { TransferAdmin(cross, "vault", attacker) },
	)

	testing.SetRealm(testing.NewUserRealm(admin))
	uassert.AbortsWithMessage(t,
		"invalid new admin address: junk",
		func() { TransferAdmin(cross, "vault", address("junk")) },
	)
	TransferAdmin(cross, "vault", newAdmin)
	uassert.Equal(t, string(newAdmin), GetAdmin("vault"))

	// old admin has lost control; new admin has it
	uassert.AbortsWithMessage(t,
		"permission denied: caller is not admin of vault",
		func() { Grant(cross, "vault", "withdraw", alice) },
	)
	testing.SetRealm(testing.NewUserRealm(newAdmin))
	Grant(cross, "vault", "withdraw", alice)
	uassert.True(t, Has("vault", "withdraw", alice), "new admin's grant must hold")
}

// ---------- queries + render ----------

func TestGetPermissions(cur realm, t *testing.T) {
	resetState()
	createVault()
	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross, "vault", "withdraw", alice)
	Grant(cross, "vault", "deposit", alice)
	Grant(cross, "vault", "deposit", bob)

	uassert.Equal(t, "withdraw, deposit", GetPermissions("vault", alice))
	uassert.Equal(t, "deposit", GetPermissions("vault", bob))
	uassert.Equal(t, "none", GetPermissions("vault", attacker))
	uassert.Equal(t, "none", GetPermissions("ghost", alice))
}

func TestRender(cur realm, t *testing.T) {
	resetState()
	uassert.Equal(t, "# Permission Registry\n\nNo resources registered.\n", Render(""))

	createVault()
	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross, "vault", "withdraw", alice)

	out := Render("")
	uassert.True(t, strings.Contains(out, "## vault"), "render must show the resource")
	uassert.True(t, strings.Contains(out, "withdraw"), "render must show the permission")
	uassert.True(t, strings.Contains(out, string(alice)), "render must show the holder")
}

// ---------- re-audit regressions (2026-09-02) ----------

func skipSeconds(sec int64) {
	testing.SkipHeights((sec + 4) / 5)
}

func TestReservation_ExpiresAndFreesTheName(cur realm, t *testing.T) {
	resetState()
	createVault()
	testing.SetRealm(testing.NewUserRealm(admin))
	DeleteResource(cross, "vault")

	// re-audit P1: within the window the name stays reserved...
	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t,
		"resource name is reserved for its former admin: vault",
		func() { CreateResource(cross, "vault") },
	)

	// ...after expiry it frees for anyone
	skipSeconds(ReservationPeriod + 10)
	CreateResource(cross, "vault")
	uassert.Equal(t, string(attacker), GetAdmin("vault"))
}

func TestReservation_OriginalCreatorCanReclaim(cur realm, t *testing.T) {
	resetState()
	createVault()

	// re-audit P2: hostile admin-transferee deletes the resource — the
	// ORIGINAL creator can still re-create during the window
	testing.SetRealm(testing.NewUserRealm(admin))
	TransferAdmin(cross, "vault", attacker)
	testing.SetRealm(testing.NewUserRealm(attacker))
	DeleteResource(cross, "vault")

	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross, "vault")
	uassert.Equal(t, string(admin), GetAdmin("vault"))
}
