package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// TestHashAndCheckPassword verifies the core end-to-end lifecycle.
func TestHashAndCheckPassword(t *testing.T) {
	password := "EnterpriseAppSec!2026"
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password %v", err)
	}

	if !strings.HasPrefix(hashed, "$argon2id$v=19$") {
		t.Errorf("Hash does not have correct PHC format, got: %s", hashed)
	}

	match, err := CheckPassword(password, hashed)
	if err != nil {
		t.Fatalf("Check Passsword returned an unexpected error: %v", err)
	}
	if !match {
		t.Errorf("Expected password to match, but it failed")
	}
}

// TestCheckPasswordFailures uses Table-Driven Testing to simulate hacker inputs.

func TestCheckPasswordFailure(t *testing.T) {
	validPassword := "EnterpriseAppSec!2026"
	validHash, _ := HashPassword(validPassword)

	tests := []struct {
		name        string
		password    string
		encodedHash string
		expectMatch bool
		expectError bool
	}{
		{
			name:        "Wrong Password",
			password:    "HackerPassword123!",
			encodedHash: validHash,
			expectMatch: false,
			expectError: false,
		},
		{
			name:        "Empty Password",
			password:    "",
			encodedHash: validHash,
			expectMatch: false,
			expectError: true, // Our validatePasswordInput should catch this and throw an error
		},
		{
			name:        "Corrupted Hash Format",
			password:    validPassword,
			encodedHash: "$argon2id$v=19$m=64$badhash", // Missing parts of the PHC string
			expectMatch: false,
			expectError: true, // parsePHCString should fail and throw an error
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match, err := CheckPassword(tc.password, tc.encodedHash)
			if tc.expectError && err == nil {
				t.Errorf("Expect an error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Did not expect error but got: %v", err)
			}
			if match != tc.expectMatch {
				t.Errorf("Expect match=%v got match = %v", tc.expectMatch, match)
			}
		})
	}
}

func TestUpgradeHashIfNeeded(t *testing.T) {
	password := "EnterpriseAppSec!2026"

	// 1. Generate a current, strong hash (Uses your default 64MB memory)
	strongHash, _ := HashPassword(password)

	// 2. Forge a legacy, weak hash (Uses only 1MB memory)
	weakHash := generateWeakHashForTest(t, password)

	tests := []struct {
		name          string
		password      string
		encodedHash   string
		expectUpgrade bool
		expectError   bool
	}{
		{
			name:          "Happy Path: No Upgrade Needed (Current Hash)",
			password:      password,
			encodedHash:   strongHash,
			expectUpgrade: false,
			expectError:   false,
		},
		{
			name:          "Actionable Path: Upgrade Needed (Legacy Weak Hash)",
			password:      password,
			encodedHash:   weakHash,
			expectUpgrade: true,
			expectError:   false,
		},
		{
			name:          "Unhappy Path: Failed Upgrade (Wrong Password)",
			password:      "HackerPassword123!",
			encodedHash:   strongHash,
			expectUpgrade: false, // Won't upgrade if the hacker doesn't even know the password
			expectError:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Action: Checking upgrade requirement for scenario '%s'", tc.name)

			newHash, didUpgrade, err := UpgradeHashIfNeeded(tc.password, tc.encodedHash)

			// 1. Check Error State
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error but got nil")
				} else {
					t.Logf("Success: Caught expected error: %v", err)
				}
				return // Stop testing this scenario, it failed exactly as expected
			}

			if err != nil {
				t.Fatalf("Did not expect an error, but got: %v", err)
			}

			// 2. Check Upgrade State
			if didUpgrade != tc.expectUpgrade {
				t.Errorf("Expected didUpgrade=%v, got %v", tc.expectUpgrade, didUpgrade)
			} else {
				t.Logf("Success: didUpgrade correctly returned %v", didUpgrade)
			}

			// 3. Verify the newly generated hash
			if didUpgrade {
				t.Logf("Action: Verifying the newly upgraded hash works...")
				match, _ := CheckPassword(tc.password, newHash)
				if !match {
					t.Errorf("CRITICAL: The newly upgraded hash is invalid and rejected the password!")
				} else {
					t.Logf("Success: The newly upgraded hash is valid and secure.")
				}
			}
		})
	}
}

// generateWeakHashForTest manually builds a legally valid Argon2id string using
// parameters that are deliberately lower than your current OWASP defaults.
func generateWeakHashForTest(t *testing.T, password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("Failed to generate test salt: %v", err)
	}

	// Deliberately weak parameters: 1 iteration, 1024 KiB memory, 1 thread
	weakHashBytes := argon2.IDKey([]byte(password), salt, 1, 1024, 1, 32)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(weakHashBytes)

	// Format: $argon2id$v=19$m=1024,t=1,p=1$<salt>$<hash>
	return fmt.Sprintf("$argon2id$v=19$m=1024,t=1,p=1$%s$%s", b64Salt, b64Hash)
}

func TestBenchmarkHashDuration(t *testing.T) {
	password := "EnterpriseAppSec!2026"

	// We only run 1 iteration so the test doesn't slow down our CI/CD pipeline
	duration, err := BenchmarkHashDuration(password, 1)

	if err != nil {
		t.Fatalf("BenchmarkHashDuration failed: %v", err)
	}

	if duration <= 0 {
		t.Errorf("Expected duration to be greater than 0, got %f", duration)
	}

	t.Logf("Success: Benchmark completed in %f seconds", duration)
}
