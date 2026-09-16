package tunnel

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"orb/internal/dns"

	"github.com/olekukonko/tablewriter"
)

// Service struct for tunnel operations
type Service struct {
	config     *ConfigManager
	cloudflare *dns.Client
	env        *Environment
}

// NewService creates a new tunnel service
func NewService() (*Service, error) {
	// Validate environment variables first
	env, err := LoadEnvironment()
	if err != nil {
		return nil, err
	}

	// Create Cloudflare client
	client, err := dns.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create cloudflare client: %w", err)
	}

	return &Service{
		config:     NewConfigManager(env.ConfigPath),
		cloudflare: client,
		env:        env,
	}, nil
}

// Expose makes a local port accessible through a Cloudflare Tunnel subdomain
func (s *Service) Expose(subdomain, port, serviceType, accessLevel, expires string) error {
	// validation of arguments and if server is running
	if err := ValidateSubdomain(subdomain); err != nil {
		return err
	}
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateServiceType(serviceType); err != nil {
		return err
	}
	if err := ValidateAccessLevel(accessLevel); err != nil {
		return err
	}
	if expires != "" {
		if err := ValidateExpiresDuration(expires); err != nil {
			return err
		}
		// --expires only makes sense with group access
		if accessLevel == AccessLevelPublic || accessLevel == AccessLevelPrivate {
			return fmt.Errorf("--expires can only be used with group access (e.g., --access friends --expires 24h)")
		}
	}

	// get hostname and service
	host := HostnameFor(subdomain, s.env.Domain)
	svc := ServiceURL(port, serviceType)

	// get cloudflare config yaml
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	// ensures if there exists ingress and last ingress is catch all
	if err := s.config.EnsureCatchAllLast(cfg); err != nil {
		return err
	}

	// checks if hostname already exists in the ingress
	if idx := s.config.FindIngressIndex(cfg, host); idx != -1 {
		existing := cfg.Ingress[idx].Service
		if existing == svc {
			fmt.Printf("ℹ️  %s already points to %s (no changes needed)\n", host, svc)
			return nil
		}
		return fmt.Errorf("✖ %s is already mapped to %s\n  Run `orb tunnel unexpose %s` first, or use a different subdomain", host, existing, subdomain)
	}

	// start of TRANSACTION
	orginalCfg := s.config.Backup(cfg)

	// combine catchall and new subdomain to form new cloudlfare yaml
	catchAll := cfg.Ingress[len(cfg.Ingress)-1]

	configSaved := false
	dnsAdded := false

	defer func() {
		if !dnsAdded {
			return
		}

		// rollback and remove dns route
		fmt.Printf("Rolling back: Removing DNS route for %s...\n", host)
		if err := s.cloudflare.RemoveDNSRoute(orginalCfg.Tunnel, host); err != nil {
			fmt.Printf("Failed to rollback DNS route for %s: %v\n", host, err)
		}

		if configSaved {
			fmt.Println("Rolling back: Restoring original config...")
			if err := s.config.Save(orginalCfg); err != nil {
				fmt.Printf("Failed to restore original config: %v\n", err)
			}
		}
	}()

	cfg.Ingress = append(cfg.Ingress[:len(cfg.Ingress)-1], IngressRule{Hostname: host, Service: svc}, catchAll)

	// save to yaml file
	if err := s.config.Save(cfg); err != nil {
		return err
	}
	configSaved = true

	// create dns route
	fmt.Printf("Creating DNS route for %s...\n", host)
	if err := s.cloudflare.CreateDNSRoute(cfg.Tunnel, host); err != nil {
		return fmt.Errorf("config updated but failed to create DNS route: %w", err)
	}
	dnsAdded = true

	// flush local DNS cache to pick up new record immediately
	s.cloudflare.FlushLocalDNSCache()

	// create access policy if not public
	if accessLevel != AccessLevelPublic {
		fmt.Printf("Creating Zero Trust access policy (%s)...\n", accessLevel)
		userEmail := os.Getenv("USER_EMAIL")
		if userEmail == "" && accessLevel == AccessLevelPrivate {
			return fmt.Errorf("USER_EMAIL environment variable required for private access")
		}
		if err := s.cloudflare.CreateAccessPolicy(host, accessLevel, userEmail); err != nil {
			return fmt.Errorf("failed to create access policy: %w", err)
		}
	}

	// get tunnel name from tunnel ID
	tunnelName, err := s.cloudflare.GetTunnelName(cfg.Tunnel)
	if err != nil {
		return fmt.Errorf("failed to get tunnel name: %w", err)
	}

	// restart cloudflared service
	if err := s.cloudflare.RestartCloudflaredService(tunnelName, host); err != nil {
		return fmt.Errorf("failed to restart cloudflared service: %w", err)
	}

	// reset rollback
	configSaved = false
	dnsAdded = false

	// schedule access expiry if specified
	if expires != "" && accessLevel != AccessLevelPublic && accessLevel != AccessLevelPrivate {
		duration, _ := ParseExpiresDuration(expires) // already validated
		expiryTime := time.Now().Add(duration)
		if err := s.scheduleAccessExpiry(subdomain, duration); err != nil {
			fmt.Printf("⚠ Warning: failed to schedule access expiry: %v\n", err)
		} else {
			fmt.Printf("  Access reverts to private: %s (in %s)\n", expiryTime.Format("2006-01-02 15:04:05"), expires)
		}
	}

	fmt.Printf("✔ Exposed %s → %s", host, svc)
	if accessLevel != AccessLevelPublic {
		fmt.Printf(" [%s access]", accessLevel)
	}
	fmt.Printf("\n  Visit: https://%s\n", host)
	return nil
}

// Unexpose removes a subdomain from the Cloudflare Tunnel
func (s *Service) Unexpose(subdomain string) error {
	// validate subdomain
	if err := ValidateSubdomain(subdomain); err != nil {
		return err
	}

	// get hostname for subdomain
	host := HostnameFor(subdomain, s.env.Domain)

	// load cloudflare config
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	// get ingress index for hostname
	idx := s.config.FindIngressIndex(cfg, host)
	if idx == -1 {
		return fmt.Errorf("✖ %s is not currently exposed", host)
	}

	// start of TRANSACTION
	orginalCfg := s.config.Backup(cfg)
	oldService := cfg.Ingress[idx].Service

	configSaved := false
	dnsRemoved := false

	defer func() {
		if !dnsRemoved {
			return
		}

		// rollback and re create dns route
		fmt.Printf("Rolling back: Re-adding DNS route for %s...\n", host)
		if err := s.cloudflare.CreateDNSRoute(orginalCfg.Tunnel, host); err != nil {
			fmt.Printf("Failed to rollback DNS route for %s: %v\n", host, err)
		}

		if configSaved {
			fmt.Println("Rolling back: Restoring original config...")
			if err := s.config.Save(orginalCfg); err != nil {
				fmt.Printf("Failed to restore original config: %v\n", err)
			}
		}
	}()

	// save new yaml without previous ingress rule
	cfg.Ingress = append(cfg.Ingress[:idx], cfg.Ingress[idx+1:]...)

	// save to yaml
	if err := s.config.Save(cfg); err != nil {
		return err
	}
	configSaved = true

	// remove domain from cloudflare dashboard
	fmt.Printf("Removing DNS route for %s...\n", host)
	if err := s.cloudflare.RemoveDNSRoute(cfg.Tunnel, host); err != nil {
		return fmt.Errorf("config updated but failed to remove DNS route: %w", err)
	}
	dnsRemoved = true

	// flush local DNS cache to remove stale record immediately
	s.cloudflare.FlushLocalDNSCache()

	// remove access policy if it exists
	fmt.Printf("Removing Zero Trust access policy (if any)...\n")
	if err := s.cloudflare.RemoveAccessPolicy(host); err != nil {
		fmt.Printf("Warning: failed to remove access policy: %v\n", err)
		// Don't fail the whole operation if access policy removal fails
	}

	// get tunnel name from tunnel ID
	tunnelName, err := s.cloudflare.GetTunnelName(cfg.Tunnel)
	if err != nil {
		return fmt.Errorf("failed to get tunnel name: %w", err)
	}

	// restart cloudflared service
	if err := s.cloudflare.RestartCloudflaredService(tunnelName, host); err != nil {
		return fmt.Errorf("failed to restart cloudflared service: %w", err)
	}

	// disable rollback
	dnsRemoved = false
	configSaved = false

	fmt.Printf("✔ Removed %s (was → %s)\n", host, oldService)
	return nil
}

// Update changes the port mapping for an existing subdomain
func (s *Service) Update(subdomain, port, serviceType string) error {
	// validate arguments
	if err := ValidateSubdomain(subdomain); err != nil {
		return err
	}
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateServiceType(serviceType); err != nil {
		return err
	}

	// load cloudflare config
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	// start of TRANSACTION
	orginalCfg := s.config.Backup(cfg)

	configSaved := false

	defer func() {
		if !configSaved {
			return
		}

		fmt.Println("Rolling back: Restoring original config...")
		if err := s.config.Save(orginalCfg); err != nil {
			fmt.Printf("Failed to restore original config: %v\n", err)
		}
	}()

	// modify subdomain port in config
	if err := s.config.ModifySubdomainPort(cfg, subdomain, port, serviceType, s.env.Domain); err != nil {
		return err
	}

	// save to yaml
	if err := s.config.Save(cfg); err != nil {
		return err
	}
	configSaved = true

	// restart cloudflared service
	if err := s.cloudflare.RestartCloudflaredService(cfg.Tunnel, HostnameFor(subdomain, s.env.Domain)); err != nil {
		return fmt.Errorf("failed to restart cloudflared service: %w", err)
	}

	// reset rollback
	configSaved = false

	fmt.Printf("✔ Updated %s to point to %s\n", HostnameFor(subdomain, s.env.Domain), ServiceURL(port, serviceType))
	return nil
}

// Health checks if a subdomain is healthy and reachable
func (s *Service) Health(subdomain string) error {
	// validate subdomain
	if err := ValidateSubdomain(subdomain); err != nil {
		return err
	}

	// get hostname for subdomain
	host := fmt.Sprintf("%s.%s", subdomain, s.env.Domain)

	// load cloudflare config
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	// check if subdomain exists in config
	idx := s.config.FindIngressIndex(cfg, host)
	if idx == -1 {
		return fmt.Errorf("✖ %s is not currently exposed", host)
	}

	url := fmt.Sprintf("https://%s", host)
	fmt.Printf("Checking health of %s...\n", url)

	// create http client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	// make request
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("✖ %s is unhealthy\n", host)
		fmt.Printf("  Error: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		fmt.Printf("✔ %s is healthy (status: %d %s)\n", host, resp.StatusCode, http.StatusText(resp.StatusCode))
	} else {
		fmt.Printf("⚠ %s returned status %d %s\n", host, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}

// Restart restarts the cloudflared service
func (s *Service) Restart() error {
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	tunnelName, err := s.cloudflare.GetTunnelName(cfg.Tunnel)
	if err != nil {
		return err
	}

	fmt.Printf("Restarting cloudflared-%s service...\n", tunnelName)
	if err := s.cloudflare.RestartCloudflaredService(tunnelName, ""); err != nil {
		return err
	}
	fmt.Printf("✔ cloudflared-%s service restarted successfully\n", tunnelName)
	return nil
}

// Status shows the cloudflared service status
func (s *Service) Status() error {
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	tunnelName, err := s.cloudflare.GetTunnelName(cfg.Tunnel)
	if err != nil {
		return err
	}

	output, err := s.cloudflare.GetServiceStatus(tunnelName)
	if err != nil {
		return err
	}
	fmt.Print(output)
	return nil
}

// Logs shows the cloudflared service logs, optionally filtered by subdomain
func (s *Service) Logs(subdomain string, lines int, follow bool) error {
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	tunnelName, err := s.cloudflare.GetTunnelName(cfg.Tunnel)
	if err != nil {
		return err
	}

	var hostname string
	if subdomain != "" {
		if err := ValidateSubdomain(subdomain); err != nil {
			return err
		}
		hostname = fmt.Sprintf("%s.%s", subdomain, s.env.Domain)

		// check if subdomain exists in config
		idx := s.config.FindIngressIndex(cfg, hostname)
		if idx == -1 {
			return fmt.Errorf("✖ %s is not currently exposed", hostname)
		}
	}

	if follow {
		return s.cloudflare.FollowServiceLogs(tunnelName, hostname)
	}

	output, err := s.cloudflare.GetServiceLogs(tunnelName, lines, hostname)
	if err != nil {
		return err
	}
	fmt.Print(output)
	return nil
}

// checkHealth makes an HTTP request to check if a hostname is healthy
func (s *Service) checkHealth(hostname string) string {
	url := fmt.Sprintf("https://%s", hostname)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return "✖ unhealthy"
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return "✔ healthy"
	}
	return fmt.Sprintf("⚠ %d", resp.StatusCode)
}

// serviceInfo holds the result of parallel health/access checks
type serviceInfo struct {
	hostname string
	service  string
	access   string
	status   string
}

// List displays all exposed subdomains and their port mappings
func (s *Service) List() error {
	// load cloudflare config
	cfg, err := s.config.Load()
	if err != nil {
		return err
	}

	// check if ingress rule is less than or equal to 1
	if len(cfg.Ingress) <= 1 {
		fmt.Println("No services exposed (only catch-all rule present)")
		return nil
	}

	// Filter out catch-all rule and count services
	var rules []IngressRule
	for _, rule := range cfg.Ingress {
		if rule.Hostname != "" {
			rules = append(rules, rule)
		}
	}

	fmt.Println("\nChecking health of exposed services...")

	// Use goroutines to check health and access in parallel
	var wg sync.WaitGroup
	results := make(chan serviceInfo, len(rules))

	for _, rule := range rules {
		wg.Add(1)
		go func(r IngressRule) {
			defer wg.Done()
			results <- serviceInfo{
				hostname: r.Hostname,
				service:  r.Service,
				access:   s.cloudflare.GetAccessInfo(r.Hostname),
				status:   s.checkHealth(r.Hostname),
			}
		}(rule)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and build table
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("URL", "Target", "Access", "Status")

	for info := range results {
		if err := table.Append(
			fmt.Sprintf("https://%s", info.hostname),
			info.service,
			info.access,
			info.status,
		); err != nil {
			return fmt.Errorf("failed to add table row: %w", err)
		}
	}

	// render table
	fmt.Println("\nExposed services:")
	if err := table.Render(); err != nil {
		return fmt.Errorf("failed to render table: %w", err)
	}

	return nil
}

// CreateAccessGroup creates a Cloudflare Access group with email addresses
func (s *Service) CreateAccessGroup(groupName, emails string) error {
	return s.cloudflare.CreateAccessGroup(groupName, emails)
}

// ListAccessGroups lists all Cloudflare Access groups
func (s *Service) ListAccessGroups() error {
	return s.cloudflare.ListAccessGroupsFormatted()
}

// DeleteAccessGroup deletes a Cloudflare Access group by name
func (s *Service) DeleteAccessGroup(groupName string) error {
	return s.cloudflare.DeleteAccessGroup(groupName)
}

// UpdateAccessGroupMembers adds or removes members from an Access group
func (s *Service) UpdateAccessGroupMembers(groupName string, addEmails, removeEmails []string) error {
	return s.cloudflare.UpdateAccessGroupMembers(groupName, addEmails, removeEmails)
}

// GetAccessGroupMembers returns the list of members in an Access group
func (s *Service) GetAccessGroupMembers(groupName string) ([]string, error) {
	return s.cloudflare.GetAccessGroupMembers(groupName)
}

// RevokeAccess removes group access from a subdomain, reverting to private (owner-only)
func (s *Service) RevokeAccess(subdomain string) error {
	if err := ValidateSubdomain(subdomain); err != nil {
		return err
	}

	host := HostnameFor(subdomain, s.env.Domain)

	fmt.Printf("Revoking group access for %s...\n", host)
	if err := s.cloudflare.RevokeGroupAccess(host); err != nil {
		return fmt.Errorf("failed to revoke group access: %w", err)
	}

	fmt.Printf("✔ Access reverted to private for %s\n", host)
	return nil
}

// scheduleAccessExpiry schedules a systemd timer to revoke group access after the specified duration
func (s *Service) scheduleAccessExpiry(subdomain string, duration time.Duration) error {
	// Subdomain is already validated by ValidateSubdomain() before this function is called But we double-check to ensure no injection is possible.
	if err := ValidateSubdomain(subdomain); err != nil {
		return fmt.Errorf("invalid subdomain for scheduling: %w", err)
	}

	// Use systemd-run to schedule the revoke command Format.
	durationStr := fmt.Sprintf("%ds", int(duration.Seconds()))

	// Pass arguments separately to prevent command injection
	cmd := exec.Command("systemd-run",
		"--user",
		"--on-active="+durationStr,
		"--unit=orb-expire-"+subdomain,
		"--description=Revoke group access for "+subdomain,
		"/usr/local/bin/orb", "tunnel", "revoke-access", subdomain,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to schedule expiry timer: %w\nOutput: %s", err, string(output))
	}

	return nil
}
