package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Bootstrap creates the first administrator, named username, with the
// password in passwordFile, if no administrator exists. The file is read
// only then, so it can be removed after the first start. One trailing
// newline in the file is ignored. It reports whether it created the user.
func (s *Service) Bootstrap(ctx context.Context, username, passwordFile string) (bool, error) {
	if ok, err := s.HasAdmin(); err != nil || ok {
		return false, err
	}
	b, err := os.ReadFile(passwordFile)
	if err != nil {
		return false, fmt.Errorf("auth: reading the bootstrap administrator's password: %w", err)
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if err := checkPassword(pw); err != nil {
		return false, fmt.Errorf("auth: the bootstrap administrator's password in %s: %w", passwordFile, err)
	}
	_, err = s.createUser(ctx, nil, username, pw, true, nil)
	if errors.Is(err, errUserExists) {
		return false, fmt.Errorf("auth: no administrator exists, and the bootstrap administrator %q already exists as a user "+
			"who is not one; choose another auth.bootstrapAdmin.username", username)
	}
	if err != nil {
		return false, fmt.Errorf("auth: creating the bootstrap administrator: %w", err)
	}
	s.log.Info("created the bootstrap administrator", "user", username)
	return true, nil
}
