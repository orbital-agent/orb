package doctor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

// Check represents a single diagnostic check
type Check struct {
	Name    string
	Status  string // "ok", "warn", "fail"
	Message string
}

// Service performs diagnostic checks
type Service struct {
	checks []Check
}

// NewService creates a new doctor service
func NewService() *Service {
	return &Service{
		checks: []Check{},
	}
}

// RunAll runs all diagnostic checks and returns the results
func (s *Service) RunAll() []Check {
	s.checkEnvVariables()
	s.checkConfigFile()
	s.checkCloudflaredInstalled()
	s.checkCloudflaredService()
	s.checkCloudflareAPIToken()
	s.checkInternetConnectivity()
	s.checkDNSResolution()

	return s.checks
}

// addCheck adds a check result
func (s *Service) addCheck(name, status, message string) {
	s.checks = append(s.checks, Check{
		Name:    name,
		Status:  status,
		Message: message,
	})
}

// checkEnvVariables verifies required environment variables are set
func (s *Service) checkEnvVariables() {
	required := []string{
		"DOMAIN",
		"CONFIG_PATH",
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_ZONE_ID",
		"CLOUDFLARE_ACCOUNT_ID",
	}

	missing := []string{}
	for _, env := range required {
		if os.Getenv(env) == "" {
			missing = append(missing, env)
		}
	}

	if len(missing) == 0 {
		s.addCheck("Environment variables", "ok", "All required variables are set")
	} else {
		s.addCheck("Environment variables", "fail", fmt.Sprintf("Missing: %s", strings.Join(missing, ", ")))
	}

	// Check optional but recommended
	if os.Getenv("USER_EMAIL") == "" {
		s.addCheck("USER_EMAIL (optional)", "warn", "Not set - required for private access level")
	}
}

// checkConfigFile verifies the cloudflared config file exists and is readable
func (s *Service) checkConfigFile() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		s.addCheck("Config file", "fail", "CONFIG_PATH not set")
		return
	}

	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		s.addCheck("Config file", "fail", fmt.Sprintf("File not found: %s", configPath))
		return
	}
	if err != nil {
		s.addCheck("Config file", "fail", fmt.Sprintf("Cannot access: %v", err))
		return
	}

	if info.IsDir() {
		s.addCheck("Config file", "fail", fmt.Sprintf("Path is a directory: %s", configPath))
		return
	}

	s.addCheck("Config file", "ok", fmt.Sprintf("Found at %s", configPath))
}

// checkCloudflaredInstalled verifies cloudflared is installed
func (s *Service) checkCloudflaredInstalled() {
	cmd := exec.Command("which", "cloudflared")
	output, err := cmd.Output()
	if err != nil {
		s.addCheck("cloudflared binary", "fail", "Not found in PATH - install from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
		return
	}

	// Get version
	versionCmd := exec.Command("cloudflared", "--version")
	versionOutput, err := versionCmd.Output()
	if err != nil {
		s.addCheck("cloudflared binary", "ok", fmt.Sprintf("Found at %s", strings.TrimSpace(string(output))))
		return
	}

	version := strings.TrimSpace(string(versionOutput))
	s.addCheck("cloudflared binary", "ok", version)
}

// checkCloudflaredService checks if cloudflared service is running
func (s *Service) checkCloudflaredService() {
	// First try to find any cloudflared service
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain")
	output, err := cmd.Output()
	if err != nil {
		s.addCheck("cloudflared service", "warn", "Cannot check systemd services")
		return
	}

	lines := strings.Split(string(output), "\n")
	var foundServices []string
	for _, line := range lines {
		if strings.Contains(line, "cloudflared") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				foundServices = append(foundServices, parts[0])
			}
		}
	}

	if len(foundServices) == 0 {
		s.addCheck("cloudflared service", "fail", "No cloudflared service running")
		return
	}

	s.addCheck("cloudflared service", "ok", fmt.Sprintf("Running: %s", strings.Join(foundServices, ", ")))
}

// checkCloudflareAPIToken validates the Cloudflare API token
func (s *Service) checkCloudflareAPIToken() {
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		s.addCheck("Cloudflare API token", "fail", "CLOUDFLARE_API_TOKEN not set")
		return
	}

	api, err := cloudflare.NewWithAPIToken(token)
	if err != nil {
		s.addCheck("Cloudflare API token", "fail", fmt.Sprintf("Invalid token format: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// VerifyAPIToken calls /user/tokens/verify, which only knows about user-owned tokens.
	if result, verr := api.VerifyAPIToken(ctx); verr != nil {
		if strings.HasPrefix(token, "cfat_") {
			s.addCheck("Cloudflare API token", "ok",
				"Account-owned token (cfat_); validated by the access checks below")
		} else {
			s.addCheck("Cloudflare API token", "fail",
				fmt.Sprintf("Token verification failed: %v", verr))
			return
		}
	} else if result.Status != "active" {
		s.addCheck("Cloudflare API token", "fail", fmt.Sprintf("Token status: %s", result.Status))
		return
	} else {
		s.addCheck("Cloudflare API token", "ok", "Token is valid and active")
	}

	// Check zone access
	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	if zoneID != "" {
		_, err := api.ZoneDetails(ctx, zoneID)
		if err != nil {
			s.addCheck("Zone access", "fail", fmt.Sprintf("Cannot access zone %s: %v", zoneID, err))
		} else {
			s.addCheck("Zone access", "ok", fmt.Sprintf("Zone %s accessible", zoneID))
		}
	}

	// Check account access.
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	if accountID != "" {
		_, _, err := api.ListAccessApplications(ctx,
			cloudflare.AccountIdentifier(accountID),
			cloudflare.ListAccessApplicationsParams{})
		if err != nil {
			s.addCheck("Account access", "fail",
				fmt.Sprintf("Cannot use Access API on account %s: %v", accountID, err))
		} else {
			s.addCheck("Account access", "ok",
				fmt.Sprintf("Account %s accessible (Access API)", accountID))
		}
	}
}

// checkInternetConnectivity verifies internet connectivity
func (s *Service) checkInternetConnectivity() {
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get("https://cloudflare.com")
	if err != nil {
		s.addCheck("Internet connectivity", "fail", fmt.Sprintf("Cannot reach cloudflare.com: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		s.addCheck("Internet connectivity", "ok", "Can reach cloudflare.com")
	} else {
		s.addCheck("Internet connectivity", "warn", fmt.Sprintf("cloudflare.com returned status %d", resp.StatusCode))
	}
}

// checkDNSResolution verifies DNS resolution works
func (s *Service) checkDNSResolution() {
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		return // Already reported in env check
	}

	cmd := exec.Command("dig", "+short", domain)
	output, err := cmd.Output()
	if err != nil {
		// Try nslookup as fallback
		cmd = exec.Command("nslookup", domain)
		output, err = cmd.Output()
		if err != nil {
			s.addCheck("DNS resolution", "warn", fmt.Sprintf("Cannot resolve %s (dig/nslookup failed)", domain))
			return
		}
	}

	if strings.TrimSpace(string(output)) == "" {
		s.addCheck("DNS resolution", "warn", fmt.Sprintf("No DNS records found for %s", domain))
		return
	}

	s.addCheck("DNS resolution", "ok", fmt.Sprintf("Domain %s resolves correctly", domain))
}

// PrintResults prints all check results in a formatted way
func (s *Service) PrintResults() {
	fmt.Println("\nOrb Doctor - System Diagnostics")
	fmt.Println(strings.Repeat("=", 40))

	okCount := 0
	warnCount := 0
	failCount := 0

	for _, check := range s.checks {
		var icon string
		switch check.Status {
		case "ok":
			icon = "✔"
			okCount++
		case "warn":
			icon = "⚠"
			warnCount++
		case "fail":
			icon = "✖"
			failCount++
		}

		fmt.Printf("\n%s %s\n", icon, check.Name)
		fmt.Printf("  %s\n", check.Message)
	}

	fmt.Println(strings.Repeat("=", 40))
	fmt.Printf("\nSummary: %d passed, %d warnings, %d failed\n", okCount, warnCount, failCount)

	if failCount > 0 {
		fmt.Println("\nFix the failed checks above to ensure orb works correctly.")
	} else if warnCount > 0 {
		fmt.Println("\nAll critical checks passed. Review warnings above if needed.")
	} else {
		fmt.Println("\nAll checks passed! Orb is ready to use.")
	}
}

// HasFailures returns true if any check failed
func (s *Service) HasFailures() bool {
	for _, check := range s.checks {
		if check.Status == "fail" {
			return true
		}
	}
	return false
}
