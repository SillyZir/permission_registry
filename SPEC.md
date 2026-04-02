# permission_registry — Technical Specification

## Overview

`permission_registry` is a Gno realm that provides a shared, on-chain access control system. Realms register named resources, define arbitrary permissions, and grant them to addresses. Any realm can query the registry to enforce access checks without implementing its own permission logic.

## Data Model

### Storage

```
resources   map[string]std.Address                         // resource name → admin
permissions map[string]map[string]map[std.Address]bool     // resource → permission → address → granted
permList    map[string][]string                            // resource → ordered permission names
```

The three-level `permissions` map provides O(1) lookup for the most critical operation: `Has(resource, permission, addr)`.

`permList` maintains insertion order of permission names per resource, so `GetPermissions` and `Render` produce deterministic output.

### Why three-level nesting

The alternatives:
- A flat `map[composite_key]bool` requires string concatenation on every lookup and is fragile with separator collisions.
- A struct-based approach requires iterating lists for each check.
- The nested map gives direct O(1) access: `permissions[resource][perm][addr]`.

## Authentication

All write operations use `std.PreviousRealm().Address()` to identify the caller. This returns the address of the immediate caller — either an EOA (externally-owned account) or the calling realm's address.

The caller address is **never** passed as a parameter. This prevents:
- Intermediate contracts from impersonating users
- Parameter-based spoofing of admin identity

| Operation | Caller requirement |
|-----------|--------------------|
| CreateResource | Anyone (caller becomes admin) |
| Grant | Must be resource admin |
| Revoke | Must be resource admin |
| TransferAdmin | Must be resource admin |
| Has | Anyone (read-only) |
| GetPermissions | Anyone (read-only) |

## Invariants

1. **Unique resources**: `CreateResource` panics if the name is already taken.
2. **No empty names**: resource names and permission names must be non-empty.
3. **No empty addresses**: `Grant`, `Revoke`, and `TransferAdmin` reject empty addresses.
4. **No duplicate grants**: `Grant` panics if the permission is already granted to the address. This prevents silent no-ops that could mask bugs.
5. **No phantom revokes**: `Revoke` panics if the permission was not granted.
6. **Admin-only mutations**: only the address stored in `resources[name]` can modify that resource's permissions.

## Operations

### CreateResource

```
caller = std.PreviousRealm().Address()
resources[name] = caller
permissions[name] = {}
permList[name] = []
```

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

Note: revoking the last holder of a permission does not remove the permission name from `permList`. The permission still exists as a defined capability; it just has no holders.

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
| `TransferAdmin` then `Grant` | New admin can grant; old admin cannot |
| Resource with no permissions | Renders as "No permissions defined" |
| Very long permission names | Accepted — no length limit enforced |

## Cross-Realm Integration

Other realms import and query the registry at runtime:

```go
import "gno.land/r/permission_registry"

func ProtectedAction(cross realm) {
    addr := std.PreviousRealm().Address()
    if !permission_registry.Has("my_resource", "execute", addr) {
        panic("unauthorized")
    }
    // proceed
}
```

The registry realm's state is shared across all callers. Permissions granted in one transaction are immediately visible to all subsequent queries.

## Limitations

- No wildcard permissions (e.g., "grant all"). Each permission must be granted individually.
- No permission hierarchies (e.g., "admin implies mint"). Hierarchies must be implemented by the consuming realm.
- No expiration or time-based grants. Permissions are permanent until explicitly revoked.
- No event emission. Consumers must query state to observe changes.
- Resource names are global and first-come-first-served. There is no namespace isolation.
