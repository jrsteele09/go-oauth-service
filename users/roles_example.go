package users

// This file provides usage examples for the role system.
// It is not part of the production code.

// Example 1: Creating a super admin
func ExampleSuperAdmin() *User {
	return &User{
		ID:          "super-admin-001",
		Email:       "super@example.com",
		Username:    "superadmin",
		SystemRoles: []RoleType{RoleSuperAdmin},
		Tenants:     []TenantMembership{}, // Super admins don't need tenant memberships
		Verified:    true,
		Blocked:     false,
	}
}

// Example 2: Creating a tenant admin (admin of multiple tenants)
func ExampleTenantAdmin() *User {
	return &User{
		ID:          "tenant-admin-001",
		Email:       "admin@tenant-a.com",
		Username:    "tenantadmin",
		SystemRoles: []RoleType{}, // No system roles
		Tenants: []TenantMembership{
			{
				TenantID: "tenant-a",
				Roles:    []RoleType{RoleTenantAdmin},
			},
			{
				TenantID: "tenant-b",
				Roles:    []RoleType{RoleTenantUser}, // Just a regular user here
			},
		},
		Verified: true,
		Blocked:  false,
	}
}

// Example 3: Creating a regular user
func ExampleRegularUser() *User {
	user := &User{
		ID:          "user-001",
		Email:       "user@tenant-a.com",
		Username:    "regularuser",
		SystemRoles: []RoleType{}, // No system roles
		Tenants: []TenantMembership{
			{
				TenantID: "tenant-a",
				Roles:    []RoleType{RoleTenantUser},
			},
		},
		Verified: true,
		Blocked:  false,
	}
	// Sync the TenantIDs slice for backward compatibility
	user.SyncTenantIDs()
	return user
}

// Example 4: Checking permissions
func ExamplePermissionChecks() {
	superAdmin := ExampleSuperAdmin()
	tenantAdmin := ExampleTenantAdmin()
	regularUser := ExampleRegularUser()

	// Super admin checks
	_ = superAdmin.IsSuperAdmin()                   // true
	_ = superAdmin.CanManageTenant("any-tenant-id") // true

	// Tenant admin checks
	_ = tenantAdmin.IsSuperAdmin()                            // false
	_ = tenantAdmin.CanManageTenant("tenant-a")               // true
	_ = tenantAdmin.CanManageTenant("tenant-b")               // false (only a user there)
	_ = tenantAdmin.IsAdminOfTenant("tenant-a")               // true
	_ = tenantAdmin.HasTenantRole("tenant-b", RoleTenantUser) // true

	// Regular user checks
	_ = regularUser.IsSuperAdmin()                // false
	_ = regularUser.CanManageTenant("tenant-a")   // false
	_ = regularUser.HasTenant("tenant-a")         // true
	_ = regularUser.GetRolesForTenant("tenant-a") // [RoleTenantUser]
}

// Example 5: Adding a user to a new tenant
func ExampleAddTenantMembership(user *User, tenantID string, roles []RoleType) {
	// Add new tenant membership
	user.Tenants = append(user.Tenants, TenantMembership{
		TenantID: tenantID,
		Roles:    roles,
	})

	// Sync the TenantIDs for backward compatibility
	user.SyncTenantIDs()
}

// Example 6: Management API authorization check
func ExampleAuthorizationCheck(user *User, tenantID string, requiredRole RoleType) bool {
	// Super admins can do anything
	if user.IsSuperAdmin() {
		return true
	}

	// Check if user has the required role for this tenant
	return user.HasTenantRole(tenantID, requiredRole)
}
