# permission_registry

Shared, on-chain permission management for Gno.land realms.

## Problem

Every realm that needs access control reinvents its own. One realm uses an `owner` address. Another maintains an `admins` map. A third checks a `whitelist`. None of them are compatible, none of them are queryable by other contracts, and the patterns get copy-pasted with subtle bugs each time.

The result: fragmented security logic, inconsistent access models, and no way for one realm to ask "does this address have permission X on resource Y?" without coupling directly to another realm's internal state.

## Solution

`permission_registry` is a shared realm where any contract or developer can:

1. **Register a resource** — a named scope of permissions (e.g., `"my_token"`, `"dao_treasury"`)
2. **Define permissions** — arbitrary named capabilities (e.g., `"mint"`, `"pause"`, `"upgrade"`)
3. **Grant and revoke** — assign permissions to specific addresses
4. **Query from anywhere** — any realm can call `Has("my_token", "mint", addr)` to enforce access

The admin of a resource is the address that created it. Only the admin can grant, revoke, or transfer control.

## Why this matters

- **Realm developers** stop reimplementing access control from scratch
- **DAOs** get a central, auditable permission ledger for all their contracts
- **Multi-contract systems** can share a permission model without tight coupling
- **Frontends** can query a single realm to show what a user is authorized to do
- **Auditors** can inspect all permissions for a resource in one place

## How it works

Permissions are stored as a three-level map: `resource → permission → address → bool`. This gives O(1) lookups for the critical path: checking whether an address has a specific permission.

The admin is determined by caller authentication (`std.PreviousRealm().Address()`), not by a caller-supplied address parameter. This means permissions cannot be spoofed by intermediate contracts.

## Usage

### Register a resource

```
CreateResource(cross, "my_token")
// caller becomes admin of "my_token"
```

### Grant a permission

```
Grant(cross, "my_token", "mint", g1alice...)
Grant(cross, "my_token", "pause", g1bob...)
```

### Check a permission (from any realm)

```
has := permission_registry.Has("my_token", "mint", g1alice...)
// returns: true
```

### Revoke

```
Revoke(cross, "my_token", "mint", g1alice...)
```

### List permissions for an address

```
GetPermissions("my_token", g1alice...)
// returns: "mint, pause" or "none"
```

### Transfer admin control

```
TransferAdmin(cross, "my_token", g1new_admin...)
```

## Integrating from another realm

Any realm can import and query the permission registry:

```go
import "gno.land/r/permission_registry"

func MintTokens(cross realm, amount int) {
    if !permission_registry.Has("my_token", "mint", std.PreviousRealm().Address()) {
        panic("unauthorized: missing 'mint' permission")
    }
    // proceed with minting
}
```

This decouples access control from business logic. The token realm doesn't maintain its own admin list — it delegates to the registry.

## API

| Function | Access | Description |
|----------|--------|-------------|
| `CreateResource(cross, name)` | Anyone | Register a resource. Caller becomes admin. |
| `Grant(cross, resource, perm, addr)` | Admin | Grant a permission to an address. |
| `Revoke(cross, resource, perm, addr)` | Admin | Remove a permission from an address. |
| `TransferAdmin(cross, resource, newAdmin)` | Admin | Hand off admin control. |
| `Has(resource, perm, addr)` | Anyone | Check if address holds a permission. Returns bool. |
| `GetPermissions(resource, addr)` | Anyone | List all permissions for an address on a resource. |
| `GetAdmin(resource)` | Anyone | Get the admin address of a resource. |
| `Render(path)` | Anyone | Markdown table of all resources and permissions. |

## Query on Gno.land

```
gnokey query vm/qeval --data 'gno.land/r/permission_registry.Has("my_token", "mint", "g1alice...")' --remote <rpc>
gnokey query vm/qeval --data 'gno.land/r/permission_registry.GetPermissions("my_token", "g1alice...")' --remote <rpc>
```

Visit `/r/permission_registry` on any Gno.land node to see all resources, admins, and permission tables.

---
