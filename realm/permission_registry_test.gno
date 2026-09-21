package permission_registry

import (
	"chain"
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
	adminResources = make(map[address]int)
	pendingAdmins = make(map[string]address)
}

func createVault(cur realm) {
	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross(cur), "vault")
}

// handOff performs the full two-step admin handoff of a resource from
// its sitting admin to `to`.
func handOff(cur realm, from, to address, resourceName string) {
	testing.SetRealm(testing.NewUserRealm(from))
	TransferAdmin(cross(cur), resourceName, to)
	testing.SetRealm(testing.NewUserRealm(to))
	AcceptAdmin(cross(cur), resourceName)
}

// fill creates n resources spread across as many distinct addresses as
// MaxResourcesPerAdmin requires, leaving the last filler realm active.
func fill(cur realm, n int) {
	created := 0
	for a := 0; created < n; a++ {
		testing.SetRealm(testing.NewUserRealm(testutils.TestAddress("filler" + itoa(a))))
		for i := 0; i < MaxResourcesPerAdmin && created < n; i++ {
			CreateResource(cross(cur), "res_"+itoa(created))
			created++
		}
	}
}

// ---------- CreateResource ----------

func TestCreate_Basic(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	uassert.Equal(t, string(admin), GetAdmin("vault"))
	uassert.Equal(t, "vault", ListResources())
	uassert.Equal(t, "none", GetPendingAdmin("vault"))
	uassert.Equal(t, 1, adminResources[admin])
}

func TestCreate_DuplicateRejected(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"resource already exists: vault",
		func() { CreateResource(cross(cur), "vault") },
	)
}

func TestCreate_NameValidation(cur realm, t *testing.T) {
	resetState()
	testing.SetRealm(testing.NewUserRealm(admin))

	for _, bad := range []string{"", "Vault", "has space", "pipe|name", strings.Repeat("a", MaxNameLen+1)} {
		uassert.AbortsContains(t, cur,
			"resource name must be",
			func() { CreateResource(cross(cur), bad) },
		)
	}
}

func TestCreate_GlobalCap(cur realm, t *testing.T) {
	resetState()

	// MaxResources is the global state bound; MaxResourcesPerAdmin means
	// filling it now takes a fleet of addresses rather than one key
	fill(cur, MaxResources)
	uassert.Equal(t, MaxResources, len(resources))

	testing.SetRealm(testing.NewUserRealm(admin))
	uassert.AbortsWithMessage(t, cur,
		"global resource limit reached",
		func() { CreateResource(cross(cur), "one_too_many") },
	)
}

// R1 (audit 2026-09-21): the per-admin quota is what stops a single
// unprivileged key from occupying the whole shared registry and
// permanently denying it to every other tenant.
func TestCreate_PerAdminCap(cur realm, t *testing.T) {
	resetState()
	testing.SetRealm(testing.NewUserRealm(attacker))

	for i := 0; i < MaxResourcesPerAdmin; i++ {
		CreateResource(cross(cur), "squat_"+itoa(i))
	}
	uassert.AbortsWithMessage(t, cur,
		"per-admin resource limit reached",
		func() { CreateResource(cross(cur), "one_too_many") },
	)

	// an honest tenant is unaffected: the registry is not monopolizable
	testing.SetRealm(testing.NewUserRealm(alice))
	CreateResource(cross(cur), "alice_res")
	uassert.Equal(t, string(alice), GetAdmin("alice_res"))

	// deleting returns the slot to its admin's quota
	testing.SetRealm(testing.NewUserRealm(attacker))
	DeleteResource(cross(cur), "squat_0")
	uassert.Equal(t, MaxResourcesPerAdmin-1, adminResources[attacker])
	CreateResource(cross(cur), "squat_fresh")
	uassert.Equal(t, MaxResourcesPerAdmin, adminResources[attacker])
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
	createVault(cur)

	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross(cur), "vault", "withdraw", alice)
	DeleteResource(cross(cur), "vault")

	uassert.Equal(t, "not found", GetAdmin("vault"))
	uassert.False(t, Has("vault", "withdraw", alice), "permissions must die with the resource")
	uassert.Equal(t, 0, adminResources[admin])

	// the squat the audit found: an attacker re-creates the freed name
	// and becomes admin of every consumer's authorization decisions
	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"resource name is reserved for its former admin: vault",
		func() { CreateResource(cross(cur), "vault") },
	)

	// the former admin can re-create it
	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross(cur), "vault")
	uassert.Equal(t, string(admin), GetAdmin("vault"))
}

func TestDelete_AdminOnly(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"permission denied: caller is not admin of vault",
		func() { DeleteResource(cross(cur), "vault") },
	)
}

// ---------- Grant / Revoke ----------

func TestGrant_AdminOnly(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"permission denied: caller is not admin of vault",
		func() { Grant(cross(cur), "vault", "withdraw", attacker) },
	)
	uassert.False(t, Has("vault", "withdraw", attacker), "denied grant must not stick")
}

func TestGrant_And_Has(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross(cur), "vault", "withdraw", alice)

	uassert.True(t, Has("vault", "withdraw", alice), "granted permission must hold")
	uassert.False(t, Has("vault", "withdraw", bob), "ungranted address must not hold")
	uassert.False(t, Has("vault", "deposit", alice), "ungranted permission must not hold")
	uassert.False(t, Has("ghost", "withdraw", alice), "unknown resource is false, never a panic")
}

func TestGrant_Validation(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))

	uassert.AbortsContains(t, cur, "permission name must be",
		func() { Grant(cross(cur), "vault", "Bad|Name", alice) })
	uassert.AbortsWithMessage(t, cur, "invalid address: junk",
		func() { Grant(cross(cur), "vault", "withdraw", address("junk")) })

	Grant(cross(cur), "vault", "withdraw", alice)
	uassert.AbortsContains(t, cur, "permission already granted",
		func() { Grant(cross(cur), "vault", "withdraw", alice) })
}

// Y6 (audit 2026-09-21): MaxPermissionsPerResource was a declared bound
// with no test behind it.
func TestGrant_PermissionCap(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))

	for i := 0; i < MaxPermissionsPerResource; i++ {
		Grant(cross(cur), "vault", "perm_"+itoa(i), alice)
	}
	uassert.AbortsWithMessage(t, cur,
		"permission limit reached for resource vault",
		func() { Grant(cross(cur), "vault", "one_too_many", alice) },
	)

	// revoking the last holder prunes the permission and frees the slot
	Revoke(cross(cur), "vault", "perm_0", alice)
	uassert.Equal(t, MaxPermissionsPerResource-1, len(permList["vault"]))
	Grant(cross(cur), "vault", "one_too_many", alice)
	uassert.True(t, Has("vault", "one_too_many", alice), "pruning must free a permission slot")
}

// Y6: MaxHoldersPerPermission was likewise untested.
func TestGrant_HolderCap(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))

	for i := 0; i < MaxHoldersPerPermission; i++ {
		Grant(cross(cur), "vault", "withdraw", testutils.TestAddress("h"+itoa(i)))
	}
	uassert.AbortsWithMessage(t, cur,
		"holder limit reached for permission withdraw",
		func() { Grant(cross(cur), "vault", "withdraw", attacker) },
	)
	uassert.False(t, Has("vault", "withdraw", attacker), "rejected grant must not stick")
}

func TestRevoke_RemovesAndPrunes(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))

	Grant(cross(cur), "vault", "withdraw", alice)
	Grant(cross(cur), "vault", "deposit", alice)
	Revoke(cross(cur), "vault", "withdraw", alice)

	uassert.False(t, Has("vault", "withdraw", alice), "revoked permission must not hold")
	uassert.True(t, Has("vault", "deposit", alice), "other permissions must survive")
	// pruning: the emptied permission leaves the per-resource list
	uassert.Equal(t, 1, len(permList["vault"]))
	uassert.Equal(t, "deposit", permList["vault"][0])

	uassert.AbortsContains(t, cur, "permission not granted",
		func() { Revoke(cross(cur), "vault", "withdraw", alice) })
}

func TestRevoke_AdminOnly(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross(cur), "vault", "withdraw", alice)

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"permission denied: caller is not admin of vault",
		func() { Revoke(cross(cur), "vault", "withdraw", alice) },
	)
	uassert.True(t, Has("vault", "withdraw", alice), "denied revoke must not stick")
}

// ---------- TransferAdmin (two-step, Y4) ----------

func TestTransferAdmin_TwoStep(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"permission denied: caller is not admin of vault",
		func() { TransferAdmin(cross(cur), "vault", attacker) },
	)

	testing.SetRealm(testing.NewUserRealm(admin))
	uassert.AbortsWithMessage(t, cur,
		"invalid new admin address: junk",
		func() { TransferAdmin(cross(cur), "vault", address("junk")) },
	)
	uassert.AbortsContains(t, cur, "already the admin",
		func() { TransferAdmin(cross(cur), "vault", admin) })

	TransferAdmin(cross(cur), "vault", newAdmin)

	// Y4: nomination alone changes nothing — the sitting admin keeps
	// full control until the nominee consents
	uassert.Equal(t, string(admin), GetAdmin("vault"))
	uassert.Equal(t, string(newAdmin), GetPendingAdmin("vault"))
	Grant(cross(cur), "vault", "withdraw", alice)
	uassert.True(t, Has("vault", "withdraw", alice), "nomination must not disarm the sitting admin")

	// only the nominee may accept
	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"caller is not the pending admin of vault",
		func() { AcceptAdmin(cross(cur), "vault") },
	)

	testing.SetRealm(testing.NewUserRealm(newAdmin))
	AcceptAdmin(cross(cur), "vault")
	uassert.Equal(t, string(newAdmin), GetAdmin("vault"))
	uassert.Equal(t, "none", GetPendingAdmin("vault"))
	uassert.Equal(t, 0, adminResources[admin])
	uassert.Equal(t, 1, adminResources[newAdmin])

	// old admin has lost control; new admin has it
	testing.SetRealm(testing.NewUserRealm(admin))
	uassert.AbortsWithMessage(t, cur,
		"permission denied: caller is not admin of vault",
		func() { Grant(cross(cur), "vault", "deposit", alice) },
	)
	testing.SetRealm(testing.NewUserRealm(newAdmin))
	Grant(cross(cur), "vault", "deposit", alice)
	uassert.True(t, Has("vault", "deposit", alice), "new admin's grant must hold")
}

func TestTransferAdmin_Cancel(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))

	uassert.AbortsWithMessage(t, cur, "no pending admin transfer for vault",
		func() { CancelAdminTransfer(cross(cur), "vault") })

	TransferAdmin(cross(cur), "vault", newAdmin)
	CancelAdminTransfer(cross(cur), "vault")
	uassert.Equal(t, "none", GetPendingAdmin("vault"))

	// the withdrawn nominee can no longer take the resource
	testing.SetRealm(testing.NewUserRealm(newAdmin))
	uassert.AbortsWithMessage(t, cur, "no pending admin transfer for vault",
		func() { AcceptAdmin(cross(cur), "vault") })
	uassert.Equal(t, string(admin), GetAdmin("vault"))
}

func TestTransferAdmin_QuotaCheckedAtConsent(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	// the nominee fills its own quota first
	testing.SetRealm(testing.NewUserRealm(newAdmin))
	for i := 0; i < MaxResourcesPerAdmin; i++ {
		CreateResource(cross(cur), "own_"+itoa(i))
	}

	testing.SetRealm(testing.NewUserRealm(admin))
	TransferAdmin(cross(cur), "vault", newAdmin)

	testing.SetRealm(testing.NewUserRealm(newAdmin))
	uassert.AbortsWithMessage(t, cur,
		"accepting would exceed the per-admin resource limit",
		func() { AcceptAdmin(cross(cur), "vault") },
	)
	uassert.Equal(t, string(admin), GetAdmin("vault"))

	// freeing a slot lets the handoff complete
	DeleteResource(cross(cur), "own_0")
	AcceptAdmin(cross(cur), "vault")
	uassert.Equal(t, string(newAdmin), GetAdmin("vault"))
	uassert.Equal(t, MaxResourcesPerAdmin, adminResources[newAdmin])
}

func TestTransferAdmin_NominationDiesWithResource(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))
	TransferAdmin(cross(cur), "vault", newAdmin)
	DeleteResource(cross(cur), "vault")
	uassert.Equal(t, "none", GetPendingAdmin("vault"))

	// re-created by the former admin: no stale nomination is inherited
	CreateResource(cross(cur), "vault")
	uassert.Equal(t, "none", GetPendingAdmin("vault"))
	testing.SetRealm(testing.NewUserRealm(newAdmin))
	uassert.AbortsWithMessage(t, cur, "no pending admin transfer for vault",
		func() { AcceptAdmin(cross(cur), "vault") })
	uassert.Equal(t, string(admin), GetAdmin("vault"))
}

// ---------- stray coins (Y5) ----------

func TestStraySendRejected(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross(cur), "vault", "withdraw", alice)
	TransferAdmin(cross(cur), "vault", newAdmin)

	// this realm holds no banker and exposes no withdrawal path, so
	// coins attached to any entrypoint would strand at the realm address
	// forever — every crossing function must abort (which reverts them)
	msg := "this realm does not accept coins"
	testing.SetOriginSend(chain.Coins{{Denom: "ugnot", Amount: 5}})
	uassert.AbortsWithMessage(t, cur, msg, func() { CreateResource(cross(cur), "paid") })
	uassert.AbortsWithMessage(t, cur, msg, func() { Grant(cross(cur), "vault", "deposit", bob) })
	uassert.AbortsWithMessage(t, cur, msg, func() { Revoke(cross(cur), "vault", "withdraw", alice) })
	uassert.AbortsWithMessage(t, cur, msg, func() { TransferAdmin(cross(cur), "vault", bob) })
	uassert.AbortsWithMessage(t, cur, msg, func() { CancelAdminTransfer(cross(cur), "vault") })
	uassert.AbortsWithMessage(t, cur, msg, func() { DeleteResource(cross(cur), "vault") })

	testing.SetRealm(testing.NewUserRealm(newAdmin))
	testing.SetOriginSend(chain.Coins{{Denom: "ugnot", Amount: 5}})
	uassert.AbortsWithMessage(t, cur, msg, func() { AcceptAdmin(cross(cur), "vault") })
	testing.SetOriginSend(nil)

	// nothing was mutated by any of the rejected calls
	uassert.Equal(t, string(admin), GetAdmin("vault"))
	uassert.Equal(t, string(newAdmin), GetPendingAdmin("vault"))
	uassert.True(t, Has("vault", "withdraw", alice), "rejected revoke must not stick")
	uassert.Equal(t, "not found", GetAdmin("paid"))

	// with nothing attached the same call succeeds
	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross(cur), "paid")
	uassert.Equal(t, string(admin), GetAdmin("paid"))
}

// ---------- queries + render ----------

func TestGetPermissions(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross(cur), "vault", "withdraw", alice)
	Grant(cross(cur), "vault", "deposit", alice)
	Grant(cross(cur), "vault", "deposit", bob)

	uassert.Equal(t, "withdraw, deposit", GetPermissions("vault", alice))
	uassert.Equal(t, "deposit", GetPermissions("vault", bob))
	uassert.Equal(t, "none", GetPermissions("vault", attacker))
	uassert.Equal(t, "none", GetPermissions("ghost", alice))
}

func TestRender(cur realm, t *testing.T) {
	resetState()
	uassert.Equal(t, "# Permission Registry\n\nNo resources registered.\n", Render(""))

	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))
	Grant(cross(cur), "vault", "withdraw", alice)

	out := Render("")
	uassert.True(t, strings.Contains(out, "## vault"), "render must show the resource")
	uassert.True(t, strings.Contains(out, "withdraw"), "render must show the permission")
	uassert.True(t, strings.Contains(out, string(alice)), "render must show the holder")

	// a pending handoff is visible to consumers reading the page
	TransferAdmin(cross(cur), "vault", newAdmin)
	uassert.True(t, strings.Contains(Render(""), "**Pending admin:**"),
		"render must disclose a pending admin handoff")
}

// Y3 (audit 2026-09-21): Render walks the whole registry and is
// reachable by any viewer, so its cost lands on third parties. It must
// bound its own output rather than scale with the declared caps.
func TestRender_Bounded(cur realm, t *testing.T) {
	resetState()

	total := MaxRenderResources + 5
	fill(cur, total)

	out := Render("")
	uassert.True(t, strings.Contains(out, "Registered resources: "+itoa(total)),
		"render must report the true total")
	uassert.True(t, strings.Contains(out, "more resource(s) not shown"),
		"render must announce resource truncation")
	uassert.False(t, strings.Contains(out, "## res_"+itoa(total-1)),
		"render must not emit resources beyond the cap")

	// holder lists are truncated too, from a fully sorted set so the
	// shown subset is a deterministic function of state
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))
	for i := 0; i < MaxRenderHolders+3; i++ {
		Grant(cross(cur), "vault", "withdraw", testutils.TestAddress("h"+itoa(i)))
	}
	uassert.True(t, strings.Contains(Render(""), "… +3 more"),
		"render must truncate an oversized holder list")

	// and permission lists
	for i := 0; i < MaxRenderPermissions+2; i++ {
		Grant(cross(cur), "vault", "perm_"+itoa(i), alice)
	}
	uassert.True(t, strings.Contains(Render(""), "more permission(s) on this resource"),
		"render must announce permission truncation")
}

// ---------- re-audit regressions (2026-09-02) ----------

func skipSeconds(sec int64) {
	testing.SkipHeights((sec + 4) / 5)
}

func TestReservation_ExpiresAndFreesTheName(cur realm, t *testing.T) {
	resetState()
	createVault(cur)
	testing.SetRealm(testing.NewUserRealm(admin))
	DeleteResource(cross(cur), "vault")

	// re-audit P1: within the window the name stays reserved...
	testing.SetRealm(testing.NewUserRealm(attacker))
	uassert.AbortsWithMessage(t, cur,
		"resource name is reserved for its former admin: vault",
		func() { CreateResource(cross(cur), "vault") },
	)

	// ...after expiry it frees for anyone. SkipHeights resets the test
	// context, so re-arm the calling realm explicitly rather than
	// relying on the SetRealm above surviving the skip.
	skipSeconds(ReservationPeriod + 10)
	testing.SetRealm(testing.NewUserRealm(attacker))
	CreateResource(cross(cur), "vault")
	uassert.Equal(t, string(attacker), GetAdmin("vault"))
	// the lapsed tombstone is reclaimed rather than left behind
	uassert.Equal(t, 0, len(retired))
}

func TestReservation_OriginalCreatorCanReclaim(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	// re-audit P2: hostile admin-transferee deletes the resource — the
	// ORIGINAL creator can still re-create during the window
	handOff(cur, admin, attacker, "vault")
	testing.SetRealm(testing.NewUserRealm(attacker))
	DeleteResource(cross(cur), "vault")

	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross(cur), "vault")
	uassert.Equal(t, string(admin), GetAdmin("vault"))
}

// ---------- round-3 audit regressions (2026-09-02) ----------

func TestReservation_CreatorSurvivesHostileRecycle(cur realm, t *testing.T) {
	resetState()
	createVault(cur)

	// round-3 P2: hostile admin-transferee deletes and INSTANTLY
	// re-creates — the original creator must survive the recycle
	handOff(cur, admin, attacker, "vault")
	testing.SetRealm(testing.NewUserRealm(attacker))
	DeleteResource(cross(cur), "vault")
	CreateResource(cross(cur), "vault")
	uassert.Equal(t, string(admin), string(resourceCreators["vault"]),
		"in-window re-create must preserve the original creator")

	// so when the attacker abandons again, the original can reclaim
	DeleteResource(cross(cur), "vault")
	testing.SetRealm(testing.NewUserRealm(admin))
	CreateResource(cross(cur), "vault")
	uassert.Equal(t, string(admin), GetAdmin("vault"))
}
