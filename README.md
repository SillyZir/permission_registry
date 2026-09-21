`Gno.land` · `Smart Contracts` · `Infrastructure`

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

The admin of a resource is the address that created it. Only the admin can grant, revoke, or hand off control.

Each address may administer at most **20** resources at once, and the registry holds at most **1000** in total. The per-address quota exists so no single key can occupy the shared namespace and lock every other tenant out.

## Why this matters

- **Realm developers** stop reimplementing access control from scratch
- **DAOs** get a central, auditable permission ledger for all their contracts
- **Multi-contract systems** can share a permission model without tight coupling
- **Frontends** can query a single realm to show what a user is authorized to do
- **Auditors** can inspect all permissions for a resource in one place

## How it works

Permissions are stored as a three-level map: `resource → permission → address → bool`. This gives O(1) lookups for the critical path: checking whether an address has a specific permission.

The admin is determined by caller authentication — every write entrypoint is a crossing function that derives identity from its own `cur.Previous().Address()`, never from a caller-supplied address parameter. This means permissions cannot be spoofed by intermediate contracts.

Deleting a resource does not immediately free its name: the name is held for 90 days for the former admin **and** the original creator, so nobody can re-create a freed name and silently inherit every consumer's authorization decisions.

## Usage

### Register a resource

```
CreateResource(cross(cur), "my_token")
// caller becomes admin of "my_token"
```

### Grant a permission

```
Grant(cross(cur), "my_token", "mint", g1alice...)
Grant(cross(cur), "my_token", "pause", g1bob...)
```

### Check a permission (from any realm)

```
has := permission_registry.Has("my_token", "mint", g1alice...)
// returns: true
```

### Revoke

```
Revoke(cross(cur), "my_token", "mint", g1alice...)
```

### List permissions for an address

```
GetPermissions("my_token", g1alice...)
// returns: "mint, pause" or "none"
```

### Transfer admin control (two-step)

Handing off admin control takes two transactions: the sitting admin nominates, and the
nominee accepts. Nominating changes nothing — the sitting admin keeps full control until
consent arrives, and can withdraw the offer at any time. A one-step transfer to a
well-formed but unowned address would strand the resource permanently, since nobody could
then grant, revoke, transfer or delete it.

```
TransferAdmin(cross(cur), "my_token", g1new_admin...)   // admin nominates
AcceptAdmin(cross(cur), "my_token")                     // nominee accepts — now it is theirs
CancelAdminTransfer(cross(cur), "my_token")             // admin withdraws a pending offer
GetPendingAdmin("my_token")                             // "g1new_admin..." or "none"
```

## Integrating from another realm

Any realm can import and query the permission registry:

```go
import "gno.land/r/permission_registry"

func MintTokens(cur realm, amount int) {
    // derive the subject address from THIS function's own cur — the
    // registry authenticates nothing on your behalf
    if !permission_registry.Has("my_token", "mint", cur.Previous().Address()) {
        panic("unauthorized: missing 'mint' permission")
    }
    // proceed with minting
}
```

> **Integrator contract.** `Has` takes the subject address explicitly and performs no
> caller authentication — it answers *"does this address hold this permission"*, not
> *"may my caller do this"*. Derive the address from your own crossing entrypoint's
> `cur.Previous().Address()`. Resolving it inside a non-crossing helper with
> `unsafe.PreviousRealm()` returns your caller's caller, not your caller, and is a
> designation-forgery bug in the consuming realm.

This decouples access control from business logic. The token realm doesn't maintain its own admin list — it delegates to the registry.

## API

| Function | Access | Description |
|----------|--------|-------------|
| `CreateResource(cross(cur), name)` | Anyone | Register a resource. Caller becomes admin. Subject to the per-admin quota and the global cap. Deleted names stay reserved for 90 days. |
| `DeleteResource(cross(cur), name)` | Admin | Remove a resource and all its permissions; the name stays reserved for the former admin and the original creator. |
| `Grant(cross(cur), resource, perm, addr)` | Admin | Grant a permission to an address. |
| `Revoke(cross(cur), resource, perm, addr)` | Admin | Remove a permission from an address. A permission left with no holders is pruned. |
| `TransferAdmin(cross(cur), resource, newAdmin)` | Admin | **Nominate** a new admin. Takes effect only on `AcceptAdmin`. |
| `AcceptAdmin(cross(cur), resource)` | Nominee | Complete a pending handoff. Checks the nominee's quota at consent time. |
| `CancelAdminTransfer(cross(cur), resource)` | Admin | Withdraw a pending nomination. |
| `Has(resource, perm, addr)` | Anyone | Check if address holds a permission. Returns bool. Never panics. |
| `GetPermissions(resource, addr)` | Anyone | List all permissions for an address on a resource. |
| `GetAdmin(resource)` | Anyone | Get the admin address of a resource. |
| `GetPendingAdmin(resource)` | Anyone | Get the nominated admin awaiting acceptance, or "none". |
| `ListResources()` | Anyone | All registered resource names in registration order. |
| `Render(path)` | Anyone | Markdown overview. Bounded output — large registries are truncated with a notice pointing at the queries above. |

The realm holds no banker and has no payable path. Coins attached to any entrypoint are
rejected, which reverts the transfer, so nothing can be stranded at the realm address.

## Limits

| Limit | Value | Why |
|-------|-------|-----|
| Resources per admin | 20 | Stops one key monopolizing the shared namespace |
| Resources total | 1000 | Global state bound |
| Permissions per resource | 50 | Bounds per-resource iteration |
| Holders per permission | 200 | Bounds grant lists |
| Name length | 64, `[a-z0-9_]` | Names enter trust decisions and rendered output |
| Name reservation after delete | 90 days | Stops squatters inheriting a freed name's consumers |

## Query on Gno.land

```
gnokey query vm/qeval --data 'gno.land/r/permission_registry.ListResources()' --remote <rpc>
gnokey query vm/qeval --data 'gno.land/r/permission_registry.Has("my_token", "mint", "g1alice...")' --remote <rpc>
gnokey query vm/qeval --data 'gno.land/r/permission_registry.GetPermissions("my_token", "g1alice...")' --remote <rpc>
```

Visit `/r/permission_registry` on any Gno.land node to see all resources, admins, and permission tables.

## Stack

- [Gno](https://gno.land) — Go-like smart contract language
- [Gno.land](https://gno.land) — Layer 1 blockchain

## Part of the Gno Infrastructure Stack

| Realm | Layer |
|-------|-------|
| [fee_split](https://github.com/SillyZir/fee-split) | Revenue & value flow |
| **permission_registry** | **Access control** |
| [service_registry](https://github.com/SillyZir/service_registry) | Discovery |
| [upgrade_registry](https://github.com/SillyZir/upgrade_registry) | Upgrade tracking |
| [timelock_guardian](https://github.com/SillyZir/timelock_guardian) | Security |

---
