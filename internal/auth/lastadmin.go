package auth

// Last-administrator protection.
//
// Deleting the seeded `admin` account is a good idea and is meant to work: a known username with
// administrative rights left on a security console is exactly the account an attacker tries first.
// What must not be possible is doing it, or any other user change, in an order that leaves the
// deployment with nobody who can manage users.
//
// That failure has no recovery path inside the product. There is no second console to log into and
// no break-glass account: EnsureAdmin only seeds when the users table is completely EMPTY, so it
// does not help a deployment that still has users, none of whom can administer it. The way out is
// hand-editing the database, which is not something an operator should discover by needing it.
//
// The check reuses User.Can rather than reimplementing the rule in SQL, because the question it
// asks has to be the same question the middleware asks on every request. An explicit permission
// override replaces the role's defaults entirely, so an "admin" whose override omits manage_users
// cannot administer anything, and a "viewer" whose override includes it can.

import "context"

// canManageUsers answers, for a role plus an optional explicit override set, exactly what the
// middleware would answer for the same user.
func canManageUsers(role Role, perms []Permission) bool {
	u := User{Role: role, Permissions: perms}
	return u.Can(PermManageUsers)
}

// remainingAdmins counts the users who would still be able to manage users after a change to one
// of them. after == nil means that user is being deleted; otherwise it is their post-change state.
//
// Disabled users do not count. Login rejects them, so a disabled administrator is not an
// administrator anyone can reach.
func (s *Store) remainingAdmins(ctx context.Context, targetID string, after *UserInfo) (int, error) {
	users, err := s.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.ID == targetID {
			if after == nil {
				continue // being deleted
			}
			u = *after
		}
		if u.Disabled {
			continue
		}
		if canManageUsers(u.Role, u.Permissions) {
			n++
		}
	}
	return n, nil
}

// ErrLastAdmin is returned when a change would leave nobody able to manage users. Its text is shown
// to the operator, so it says what to do rather than only what was refused.
type ErrLastAdmin struct{ action string }

func (e ErrLastAdmin) Error() string {
	return "refusing to " + e.action + ": this is the only account that can manage users, and " +
		"there is no way back into user administration without it. Create another administrator " +
		"first, sign in as them, then retry."
}

// guardLastAdmin refuses a change that would leave no administrator. action names the operation for
// the message ("delete this user", "change this user's role").
func (s *Store) guardLastAdmin(ctx context.Context, targetID string, after *UserInfo, action string) error {
	n, err := s.remainingAdmins(ctx, targetID, after)
	if err != nil {
		// Fail closed. A change of this kind is never urgent enough to be worth applying while the
		// check that it is safe could not be run.
		return err
	}
	if n == 0 {
		return ErrLastAdmin{action: action}
	}
	return nil
}
