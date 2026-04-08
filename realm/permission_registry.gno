package permission_registry

import (
	"sort"
	"std"
	"strings"
)

// resources maps a resource name to the admin address that controls it.
var resources map[string]std.Address

// resourceNames tracks the insertion-ordered list of resource names so
// ListResources can iterate without scanning the map.
var resourceNames []string

// permissions maps resource -> permission -> address -> granted.
// Three-level nesting gives O(1) lookup for Has().
var permissions map[string]map[string]map[std.Address]bool

// permList tracks the ordered list of distinct permission names per
// resource, so GetPermissions can iterate without scanning the full map.
var permList map[string][]string

func init() {
	resources = make(map[string]std.Address)
	resourceNames = []string{}
	permissions = make(map[string]map[string]map[std.Address]bool)
	permList = make(map[string][]string)
}

// caller returns the address of the immediate external caller.
func caller() std.Address {
	return std.PreviousRealm().Address()
}

// mustBeAdmin panics if the caller is not the admin of the resource.
func mustBeAdmin(resource string) {
	admin, exists := resources[resource]
	if !exists {
		panic("resource not found: " + resource)
	}
	if caller() != admin {
		panic("permission denied: caller is not admin of " + resource)
	}
}

// ---------- write operations ----------

// CreateResource registers a new named resource. The caller becomes its
// admin and is the only address that can grant or revoke permissions on
// it. Panics if the name is empty or already taken.
func CreateResource(_ realm, resourceName string) {
	if resourceName == "" {
		panic("resource name must not be empty")
	}
	if _, exists := resources[resourceName]; exists {
		panic("resource already exists: " + resourceName)
	}

	resources[resourceName] = caller()
	resourceNames = append(resourceNames, resourceName)
	permissions[resourceName] = make(map[string]map[std.Address]bool)
	permList[resourceName] = []string{}
}

// Grant gives an address a named permission on a resource. Only the
// resource admin can call this. Panics if the permission is already
// granted to avoid silent no-ops.
func Grant(_ realm, resourceName, permission string, addr std.Address) {
	mustBeAdmin(resourceName)
	if permission == "" {
		panic("permission name must not be empty")
	}
	if addr == "" {
		panic("address must not be empty")
	}

	perms := permissions[resourceName]
	if perms[permission] == nil {
		perms[permission] = make(map[std.Address]bool)
		permList[resourceName] = append(permList[resourceName], permission)
	}

	if perms[permission][addr] {
		panic("permission already granted: " + permission + " to " + string(addr))
	}
	perms[permission][addr] = true
}

// Revoke removes a permission from an address. Only the resource admin
// can call this. Panics if the permission was not granted.
func Revoke(_ realm, resourceName, permission string, addr std.Address) {
	mustBeAdmin(resourceName)

	perms := permissions[resourceName]
	if perms[permission] == nil || !perms[permission][addr] {
		panic("permission not granted: " + permission + " to " + string(addr))
	}
	delete(perms[permission], addr)
}

// TransferAdmin hands administrative control of a resource to a new
// address. Only the current admin can call this.
func TransferAdmin(_ realm, resourceName string, newAdmin std.Address) {
	mustBeAdmin(resourceName)
	if newAdmin == "" {
		panic("new admin must not be empty")
	}
	resources[resourceName] = newAdmin
}

// ---------- read-only queries ----------

// Has returns true if addr holds the named permission on the resource.
// Returns false (never panics) for unknown resources or permissions.
func Has(resourceName, permission string, addr std.Address) bool {
	perms, exists := permissions[resourceName]
	if !exists {
		return false
	}
	holders := perms[permission]
	if holders == nil {
		return false
	}
	return holders[addr]
}

// GetPermissions returns all permission names granted to addr on a
// resource, as a comma-separated string. Returns "none" if the address
// has no permissions.
func GetPermissions(resourceName string, addr std.Address) string {
	perms, exists := permissions[resourceName]
	if !exists {
		return "none"
	}

	var result []string
	for _, perm := range permList[resourceName] {
		holders := perms[perm]
		if holders != nil && holders[addr] {
			result = append(result, perm)
		}
	}
	if len(result) == 0 {
		return "none"
	}
	return strings.Join(result, ", ")
}

// ListResources returns all registered resource names as a comma-separated
// string in registration order. Returns "none" if no resources exist.
func ListResources() string {
	if len(resourceNames) == 0 {
		return "none"
	}
	return strings.Join(resourceNames, ", ")
}

// GetAdmin returns the admin address of a resource.
func GetAdmin(resourceName string) string {
	admin, exists := resources[resourceName]
	if !exists {
		return "not found"
	}
	return string(admin)
}

// ---------- render ----------

// Render returns a markdown overview. Never panics.
func Render(path string) string {
	if resources == nil || len(resources) == 0 {
		return "# Permission Registry\n\nNo resources registered.\n"
	}

	var b strings.Builder
	b.WriteString("# Permission Registry\n\n")

	for _, name := range resourceNames {
		admin := resources[name]
		b.WriteString("## " + name + "\n\n")
		b.WriteString("**Admin:** `" + string(admin) + "`\n\n")

		perms, exists := permissions[name]
		if !exists || len(perms) == 0 {
			b.WriteString("_No permissions defined._\n\n")
			continue
		}

		b.WriteString("| Permission | Addresses |\n")
		b.WriteString("|------------|-----------|\n")

		for _, perm := range permList[name] {
			holders := perms[perm]
			if holders == nil || len(holders) == 0 {
				continue
			}
			var addrs []string
			for addr := range holders {
				if holders[addr] {
					addrs = append(addrs, string(addr))
				}
			}
			sort.Strings(addrs)
			for i, a := range addrs {
				addrs[i] = "`" + a + "`"
			}
			b.WriteString("| " + perm + " | " + strings.Join(addrs, ", ") + " |\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}
