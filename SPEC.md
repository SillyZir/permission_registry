# permission_registry — Technical Specification

## Overview

`permission_registry` is a Gno realm that provides a shared, on-chain access control system. Realms register named resources, define arbitrary permissions, and grant them to addresses. Any realm can query the registry to enforce access checks without implementing its own permission logic.

## Data Model

### Storage

```
resources        map[string]address                    // resource name → current admin
resourceNames    []string                              // registration-ordered resource names
permissions      map[string]map[string]map[address]bool // resource → permission → address → granted
permList         map[string][]string                   // resource → ordered permission names
retired          map[string]*Reservation               // deleted name → time-bounded hold
resourceCreators map[string]address                    // resource → ORIGINAL creator (immutable)
adminResources   map[address]int                       // admin → live resource count (quota)
pendingAdmins    map[string]address                    // resource → nominated admin
```

The three-level `permissions` map provides O(1) lookup for the most critical operation: `Has(resource, permission, addr)`.

`permList` maintains insertion order of permission names per resource, so `GetPermissions` and `Render` produce deterministic output.

### Why three-level nesting

The alternatives:
- A flat `map[composite_key]bool` requires string concatenation on every lookup and is fragile with separator collisions.
- A struct-based approach requires iterating lists for each check.
- The nested map gives direct O(1) access: `permissions[resource][perm][addr]`.

## Authentication

Every write operation is a crossing function `func F(cur realm, ...)` and derives the
caller from its own `cur.Previous().Address()`, inline at the entrypoint. This is the
runtime-current capability token for the immediately-preceding crossing, so it names the
immediate caller — an EOA or the calling realm — and cannot be spoofed.

Identity is deliberately **not** resolved by a shared non-crossing helper. A helper using
the stack-walking `unsafe.PreviousRealm()` returns the realm before the most recent
boundary regardless of which frame it runs in; that is correct only as long as every call
site happens to be a crossing entrypoint, and nothing in the type system enforces it.
Threading `cur` makes the binding structural instead of conventional.

The caller address is **never** passed as a parameter to a write operation.

| Operation | Caller requirement |
|-----------|--------------------|
| CreateResource | Anyone, subject to the per-admin quota and global cap (caller becomes admin) |
| DeleteResource | Must be resource admin |
| Grant | Must be resource admin |
| Revoke | Must be resource admin |
| TransferAdmin | Must be resource admin (nominates only) |
| AcceptAdmin | Must be the nominee |
| CancelAdminTransfer | Must be resource admin |
| Has / GetPermissions / GetAdmin / GetPendingAdmin / ListResources / Render | Anyone (read-only) |

### Coins

The realm holds no banker, exposes no payable path and has no withdrawal function. Every
crossing entrypoint aborts if coins are attached; the abort reverts the transfer, so value
cannot be stranded at the realm address.

## Invariants

1. **Unique resources**: `CreateResource` panics if the name is already taken.
2. **Name grammar**: resource and permission names are 1–64 characters of `[a-z0-9_]`. Names enter composite trust decisions and rendered markdown, so no delimiter or markup character may appear in one.
3. **No empty addresses**: `Grant` and `TransferAdmin` reject empty or malformed addresses.
4. **No duplicate grants**: `Grant` panics if the permission is already granted to the address. This prevents silent no-ops that could mask bugs.
5. **No phantom revokes**: `Revoke` panics if the permission was not granted.
6. **Admin-only mutations**: only the address stored in `resources[name]` can modify that resource's permissions.
7. **Consented handoff**: `resources[name]` changes to a new address only when that address itself calls `AcceptAdmin`.
8. **Quota conservation**: `adminResources[a]` always equals the number of live resources `a` administers. It is incremented on create and on accepted handoff, decremented on delete and on handoff away, and the key is removed at zero.
9. **Bounded state**: at most 1000 resources, 20 per admin, 50 permissions per resource, 200 holders per permission.
10. **Bounded render**: `Render`'s output size is independent of how large the registry grows; truncation is always announced alongside the true total.
11. **Reservation**: a deleted name is claimable for 90 days only by its former admin or its original creator. The original creator survives admin transfers and delete/re-create cycles.

## Operations

### CreateResource

```
who = cur.Previous().Address()
reject attached coins; validate name; reject duplicate
if name is retired:
    if the hold lapsed: drop the tombstone
    else: require who ∈ {former admin, original creator}
          and carry the ORIGINAL creator forward
enforce global cap, then per-admin quota
resources[name]        = who
adminResources[who]   += 1
resourceCreators[name] = creator
permissions[name]      = {}
permList[name]         = []
```

Carrying the original creator forward through an in-window re-create is what stops a
hostile admin-transferee from delete/re-create cycling to erase the original project's
reclaim right.

### Grant

```
mustBeAdmin(resource)
permissions[resource][perm][addr] = true
if perm is new: append to permList[resource]
```

### Revoke

```
mustBeAdmin(resource)
delete(permissions[resource][perm], addr)
```

Revoking the last holder of a permission prunes the permission from both `permissions[resource]` and `permList[resource]`, which frees a slot against `MaxPermissionsPerResource`. A permission with no holders is not a defined capability — it is indistinguishable from one that was never created.

### Has (critical path)

```
return permissions[resource][perm][addr]
```

Three map lookups. No iteration, no string operations. This is the function other realms call on every access check, so performance matters.

### GetPermissions

```
for perm in permList[resource]:
    if permissions[resource][perm][addr]:
        result = append(result, perm)
return join(result, ", ")
```

Linear in the number of permission names on the resource (not in the number of holders).

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| `Has` on nonexistent resource | Returns false (no panic) |
| `Has` on nonexistent permission | Returns false (no panic) |
| `Grant` same permission twice | Panics: prevents silent duplicates |
| `Revoke` non-granted permission | Panics: prevents phantom operations |
| `CreateResource` with taken name | Panics |
| `TransferAdmin` then `Grant` | Nothing changes until `AcceptAdmin`: the sitting admin still grants |
| `AcceptAdmin` by anyone but the nominee | Panics |
| `AcceptAdmin` when the nominee is at quota | Panics; the handoff stays pending |
| `DeleteResource` with a nomination pending | The nomination dies with the resource and is not inherited by a re-create |
| `TransferAdmin` to the sitting admin | Panics |
| Resource with no permissions | Renders as "No permissions defined" |
| Names outside `[a-z0-9_]{1,64}` | Panics with the name rule |
| Coins attached to any write | Panics; the transfer reverts |
| Registry larger than the render caps | Renders a bounded prefix plus a truncation notice and the true total |

## Cross-Realm Integration

Other realms import and query the registry at runtime:

```go
import "gno.land/r/permission_registry"

func ProtectedAction(cur realm) {
    addr := cur.Previous().Address()   // THIS function's own caller
    if !permission_registry.Has("my_resource", "execute", addr) {
        panic("unauthorized")
    }
    // proceed
}
```

`Has` authenticates nothing on the consumer's behalf — it answers *"does this address hold
this permission"*, not *"may my caller do this"*. The consumer must derive the subject
address from its own crossing entrypoint. Resolving it inside a non-crossing helper with
`unsafe.PreviousRealm()` yields the consumer's caller's caller and is a designation-forgery
bug in the consumer, not in the registry.

The registry realm's state is shared across all callers. Permissions granted in one transaction are immediately visible to all subsequent queries.

## Limitations

- No wildcard permissions (e.g., "grant all"). Each permission must be granted individually.
- No permission hierarchies (e.g., "admin implies mint"). Hierarchies must be implemented by the consuming realm.
- No expiration or time-based grants. Permissions are permanent until explicitly revoked.
- No event emission. Consumers must query state to observe changes.
- Resource names are global and first-come-first-served. There is no namespace isolation.
- **Sybil resistance is partial.** The per-admin quota raises monopolizing the 1000-slot
  namespace from one funded key to fifty, but does not eliminate it. Closing the gap
  entirely requires a fee, a stake, or an allowlist, each of which changes the realm's
  economic and trust model; none is in scope for this design.
- **Expired reservations are not swept.** `retired` grows with delete churn and is only
  reclaimed lazily when a lapsed name is re-created. It is never iterated, so there is no
  gas amplification onto other users, and every entry is paid for by the caller's own
  storage deposit.
