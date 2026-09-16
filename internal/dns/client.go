package dns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudflare/cloudflare-go"
)

// Client wraps the Cloudflare API for DNS management
type Client struct {
	api       *cloudflare.API
	zoneID    string
	accountID string
}

// New creates a new Cloudflare DNS client
func New() (*Client, error) {
	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		return nil, fmt.Errorf("failed to create cloudflare client: %w", err)
	}

	return &Client{
		api:       api,
		zoneID:    os.Getenv("CLOUDFLARE_ZONE_ID"),
		accountID: os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
	}, nil
}

// GetTunnelName retrieves the tunnel name from the Cloudflare API using the tunnel ID
func (c *Client) GetTunnelName(tunnelID string) (string, error) {
	ctx := context.Background()

	tunnel, err := c.api.GetTunnel(ctx, cloudflare.AccountIdentifier(c.accountID), tunnelID)
	if err != nil {
		return "", fmt.Errorf("failed to get tunnel: %w", err)
	}

	return tunnel.Name, nil
}

// CreateDNSRoute creates a CNAME DNS record for the tunnel
func (c *Client) CreateDNSRoute(tunnelID, hostname string) error {
	ctx := context.Background()

	target := fmt.Sprintf("%s.cfargotunnel.com", tunnelID)

	params := cloudflare.CreateDNSRecordParams{
		Type:    "CNAME",
		Name:    hostname,
		Content: target,
		Proxied: cloudflare.BoolPtr(true),
		TTL:     1,
	}

	_, err := c.api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(c.zoneID), params)
	if err != nil {
		return fmt.Errorf("failed to create DNS record: %w", err)
	}

	return nil
}

// RemoveDNSRoute removes CNAME DNS record for the tunnel
func (c *Client) RemoveDNSRoute(tunnelID, hostname string) error {
	ctx := context.Background()

	records, _, err := c.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(c.zoneID), cloudflare.ListDNSRecordsParams{
		Name: hostname,
		Type: "CNAME",
	})
	if err != nil {
		return fmt.Errorf("failed to list DNS records: %w", err)
	}

	if len(records) == 0 {
		return fmt.Errorf("no DNS record found for hostname: %s", hostname)
	}

	for _, record := range records {
		err := c.api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(c.zoneID), record.ID)
		if err != nil {
			return fmt.Errorf("failed to delete DNS record: %w", err)
		}
	}

	return nil
}

// FlushLocalDNSCache flushes the local DNS cache to pick up new DNS records
func (c *Client) FlushLocalDNSCache() error {
	// Try systemd-resolved first (Ubuntu/Debian)
	cmd := exec.Command("sudo", "systemd-resolve", "--flush-caches")
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Try resolvectl (newer systemd)
	cmd = exec.Command("sudo", "resolvectl", "flush-caches")
	if err := cmd.Run(); err == nil {
		return nil
	}

	// If both fail, it's not critical - DNS will eventually refresh
	return nil
}

// RestartCloudflaredService restarts the cloudflared service to apply DNS changes
func (c *Client) RestartCloudflaredService(tunnelName, hostname string) error {
	serviceName := fmt.Sprintf("cloudflared-%s", tunnelName)
	cmd := exec.Command("sudo", "systemctl", "restart", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart %s service: %w\nOutput: %s", serviceName, err, string(output))
	}
	return nil
}

// GetServiceStatus returns the status of the cloudflared service
func (c *Client) GetServiceStatus(tunnelName string) (string, error) {
	serviceName := fmt.Sprintf("cloudflared-%s", tunnelName)
	cmd := exec.Command("systemctl", "status", serviceName, "--no-pager")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// systemctl status returns exit code 3 if service is not running, but still outputs status
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3 {
			return string(output), nil
		}
		return "", fmt.Errorf("failed to get %s service status: %w\nOutput: %s", serviceName, err, string(output))
	}
	return string(output), nil
}

// GetServiceLogs returns the logs of the cloudflared service, optionally filtered by hostname
func (c *Client) GetServiceLogs(tunnelName string, lines int, hostname string) (string, error) {
	serviceName := fmt.Sprintf("cloudflared-%s", tunnelName)
	args := []string{"-u", serviceName, "--no-pager", "-n", fmt.Sprintf("%d", lines)}

	if hostname != "" {
		args = append(args, "--grep", hostname)
	}

	cmd := exec.Command("journalctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get %s service logs: %w\nOutput: %s", serviceName, err, string(output))
	}
	return string(output), nil
}

// FollowServiceLogs follows the logs of the cloudflared service in real-time
func (c *Client) FollowServiceLogs(tunnelName string, hostname string) error {
	serviceName := fmt.Sprintf("cloudflared-%s", tunnelName)
	args := []string{"-u", serviceName, "-f"}

	if hostname != "" {
		args = append(args, "--grep", hostname)
	}

	cmd := exec.Command("journalctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// accessAppName is the Access application name orb uses for a hostname.
func accessAppName(hostname string) string {
	return fmt.Sprintf("orb-%s", hostname)
}

// accessAppsFor returns every Access application orb owns for hostname.
func (c *Client) accessAppsFor(ctx context.Context, hostname string) ([]cloudflare.AccessApplication, error) {
	// Empty params leaves cloudflare-go's auto-pagination on, so this sees every application instead of only the first page.
	apps, _, err := c.api.ListAccessApplications(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessApplicationsParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to list access applications: %w", err)
	}

	name := accessAppName(hostname)
	var owned []cloudflare.AccessApplication
	for _, app := range apps {
		if app.Name == name {
			owned = append(owned, app)
		}
	}

	return owned, nil
}

// deleteAccessApps deletes each application, skipping keepID, and reports every failure rather than the first — a partial cleanup that stops early is what leaves duplicates behind.
func (c *Client) deleteAccessApps(ctx context.Context, apps []cloudflare.AccessApplication, keepID string) error {
	var errs []error
	for _, app := range apps {
		if app.ID == keepID {
			continue
		}
		if err := c.api.DeleteAccessApplication(ctx, cloudflare.AccountIdentifier(c.accountID), app.ID); err != nil {
			errs = append(errs, fmt.Errorf("delete access application %s: %w", app.ID, err))
		}
	}

	return errors.Join(errs...)
}

// CreateAccessPolicy creates a Cloudflare Access policy for a hostname accessLevel can be "public", "private", or a group name Re-exposing a hostname replaces its policy rather than stacking another one.
func (c *Client) CreateAccessPolicy(hostname, accessLevel, userEmail string) error {
	ctx := context.Background()

	// If access level is public, don't create a policy
	if accessLevel == "public" {
		return nil
	}

	superseded, err := c.accessAppsFor(ctx, hostname)
	if err != nil {
		return err
	}

	// Create the access application
	createdApp, err := c.api.CreateAccessApplication(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.CreateAccessApplicationParams{
		Name:   accessAppName(hostname),
		Domain: hostname,
		Type:   "self_hosted",
	})
	if err != nil {
		return fmt.Errorf("failed to create access application: %w", err)
	}

	// An application with no usable policy is worse than no application, and it would sit alongside the ones it was meant to replace.
	if err := c.createAccessPolicies(ctx, createdApp.ID, hostname, accessLevel, userEmail); err != nil {
		if rollbackErr := c.deleteAccessApps(ctx, []cloudflare.AccessApplication{createdApp}, ""); rollbackErr != nil {
			return errors.Join(err, rollbackErr)
		}
		return err
	}

	return c.deleteAccessApps(ctx, superseded, createdApp.ID)
}

// createAccessPolicies attaches orb's policies to an application.
func (c *Client) createAccessPolicies(ctx context.Context, appID, hostname, accessLevel, userEmail string) error {
	// Always create owner policy first (precedence 1 - highest priority, cannot be altered)
	_, err := c.api.CreateAccessPolicy(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.CreateAccessPolicyParams{
		ApplicationID: appID,
		Name:          fmt.Sprintf("orb-%s-owner", hostname),
		Decision:      "allow",
		Include: []any{
			cloudflare.AccessGroupEmail{Email: struct {
				Email string `json:"email"`
			}{Email: userEmail}},
		},
		Precedence: 1,
	})
	if err != nil {
		return fmt.Errorf("failed to create owner access policy: %w", err)
	}

	// Private means owner-only, so there is no group to add.
	if accessLevel == "private" {
		return nil
	}

	groupID, err := c.accessGroupID(ctx, accessLevel)
	if err != nil {
		return err
	}

	// Create group policy (precedence 2)
	_, err = c.api.CreateAccessPolicy(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.CreateAccessPolicyParams{
		ApplicationID: appID,
		Name:          fmt.Sprintf("orb-%s-group", hostname),
		Decision:      "allow",
		Include: []any{
			cloudflare.AccessGroupAccessGroup{Group: struct {
				ID string `json:"id"`
			}{ID: groupID}},
		},
		Precedence: 2,
	})
	if err != nil {
		return fmt.Errorf("failed to create group access policy: %w", err)
	}

	return nil
}

// accessGroupID resolves an Access group name to its ID.
func (c *Client) accessGroupID(ctx context.Context, groupName string) (string, error) {
	groups, _, err := c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
	if err != nil {
		return "", fmt.Errorf("failed to list access groups: %w", err)
	}

	for _, group := range groups {
		if group.Name == groupName {
			return group.ID, nil
		}
	}

	return "", fmt.Errorf("access group %q not found - create it with `orb access create %s <emails>` first", groupName, groupName)
}

// GetAccessInfo returns the access level for a hostname (e.g., "public", "private", or group name)
func (c *Client) GetAccessInfo(hostname string) string {
	ctx := context.Background()

	apps, err := c.accessAppsFor(ctx, hostname)
	if err != nil || len(apps) == 0 {
		return "public"
	}

	// CreateAccessPolicy prunes superseded applications, so there should only ever be one.
	app := apps[0]

	// Get the policies for this application
	policies, _, err := c.api.ListAccessPolicies(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessPoliciesParams{
		ApplicationID: app.ID,
	})
	if err != nil || len(policies) == 0 {
		return "protected"
	}

	// Check the first policy's include rules to determine type
	for _, include := range policies[0].Include {
		// Check if it's an email-based rule (private)
		if emailRule, ok := include.(cloudflare.AccessGroupEmail); ok && emailRule.Email.Email != "" {
			return "private"
		}
		// Check if it's a group-based rule
		if groupRule, ok := include.(cloudflare.AccessGroupAccessGroup); ok && groupRule.Group.ID != "" {
			// Look up the group name by ID
			groups, _, err := c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
			if err == nil {
				for _, group := range groups {
					if group.ID == groupRule.Group.ID {
						return group.Name
					}
				}
			}
			return "group"
		}
	}

	return "protected"
}

// RemoveAccessPolicy removes the Cloudflare Access policy for a hostname.
func (c *Client) RemoveAccessPolicy(hostname string) error {
	ctx := context.Background()

	apps, err := c.accessAppsFor(ctx, hostname)
	if err != nil {
		return err
	}

	return c.deleteAccessApps(ctx, apps, "")
}

// RevokeGroupAccess removes only the group policy, keeping the owner policy intact This is used when temporary access expires - reverts to private (owner-only) Revoking across every application orb owns for the hostname, rather than the first, means a duplicate left by an older orb cannot keep group access alive after the expiry has supposedly reverted the host to private.
func (c *Client) RevokeGroupAccess(hostname string) error {
	ctx := context.Background()

	apps, err := c.accessAppsFor(ctx, hostname)
	if err != nil {
		return err
	}

	groupPolicyName := fmt.Sprintf("orb-%s-group", hostname)

	var errs []error
	for _, app := range apps {
		policies, _, err := c.api.ListAccessPolicies(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessPoliciesParams{
			ApplicationID: app.ID,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("list access policies for %s: %w", app.ID, err))
			continue
		}

		// Delete only the group policy, never the owner policy.
		for _, policy := range policies {
			if policy.Name != groupPolicyName {
				continue
			}
			if err := c.api.DeleteAccessPolicy(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.DeleteAccessPolicyParams{
				ApplicationID: app.ID,
				PolicyID:      policy.ID,
			}); err != nil {
				errs = append(errs, fmt.Errorf("delete group policy %s: %w", policy.ID, err))
			}
		}
	}

	return errors.Join(errs...)
}

// CreateAccessGroup creates a new Access group with email addresses
func (c *Client) CreateAccessGroup(groupName, emails string) error {
	ctx := context.Background()

	// Parse comma-separated emails
	emailList := []string{}
	for _, email := range strings.Split(emails, ",") {
		emailList = append(emailList, strings.TrimSpace(email))
	}

	// Build include rules with email addresses
	var include []any
	for _, email := range emailList {
		include = append(include, cloudflare.AccessGroupEmail{Email: struct {
			Email string `json:"email"`
		}{Email: email}})
	}

	// Create the access group
	_, err := c.api.CreateAccessGroup(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.CreateAccessGroupParams{
		Name:    groupName,
		Include: include,
	})
	if err != nil {
		return fmt.Errorf("failed to create access group: %w", err)
	}

	fmt.Printf("✔ Created Access group %q with %d email(s)\n", groupName, len(emailList))
	return nil
}

// ListAccessGroupsFormatted lists all Access groups in a formatted table
func (c *Client) ListAccessGroupsFormatted() error {
	ctx := context.Background()

	groups, _, err := c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
	if err != nil {
		return fmt.Errorf("failed to list access groups: %w", err)
	}

	if len(groups) == 0 {
		fmt.Println("No Access groups found")
		return nil
	}

	fmt.Printf("\nAccess Groups (%d):\n", len(groups))
	for _, group := range groups {
		fmt.Printf("  • %s (ID: %s)\n", group.Name, group.ID)
	}

	return nil
}

// UpdateAccessGroupMembers adds or removes members from an Access group
func (c *Client) UpdateAccessGroupMembers(groupName string, addEmails, removeEmails []string) error {
	ctx := context.Background()

	// Find the group by name
	groups, _, err := c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
	if err != nil {
		return fmt.Errorf("failed to list access groups: %w", err)
	}

	var group cloudflare.AccessGroup
	var found bool
	for _, g := range groups {
		if g.Name == groupName {
			group = g
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("access group %q not found", groupName)
	}

	// Extract current emails from the group's include rules
	currentEmails := make(map[string]bool)
	for _, include := range group.Include {
		if emailRule, ok := include.(map[string]interface{}); ok {
			if emailObj, ok := emailRule["email"].(map[string]interface{}); ok {
				if email, ok := emailObj["email"].(string); ok {
					currentEmails[email] = true
				}
			}
		}
	}

	// Add new emails
	for _, email := range addEmails {
		email = strings.TrimSpace(email)
		if email != "" {
			currentEmails[email] = true
		}
	}

	// Remove emails
	for _, email := range removeEmails {
		email = strings.TrimSpace(email)
		delete(currentEmails, email)
	}

	if len(currentEmails) == 0 {
		return fmt.Errorf("cannot remove all members from group - delete the group instead")
	}

	// Build new include rules
	var include []any
	for email := range currentEmails {
		include = append(include, cloudflare.AccessGroupEmail{Email: struct {
			Email string `json:"email"`
		}{Email: email}})
	}

	// Update the group
	_, err = c.api.UpdateAccessGroup(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.UpdateAccessGroupParams{
		ID:      group.ID,
		Name:    groupName,
		Include: include,
	})
	if err != nil {
		return fmt.Errorf("failed to update access group: %w", err)
	}

	if len(addEmails) > 0 {
		fmt.Printf("✔ Added %d member(s) to %q\n", len(addEmails), groupName)
	}
	if len(removeEmails) > 0 {
		fmt.Printf("✔ Removed %d member(s) from %q\n", len(removeEmails), groupName)
	}
	fmt.Printf("  Group now has %d member(s)\n", len(currentEmails))

	return nil
}

// GetAccessGroupMembers returns the list of email addresses in an Access group
func (c *Client) GetAccessGroupMembers(groupName string) ([]string, error) {
	ctx := context.Background()

	groups, _, err := c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to list access groups: %w", err)
	}

	for _, group := range groups {
		if group.Name == groupName {
			var emails []string
			for _, include := range group.Include {
				if emailRule, ok := include.(map[string]interface{}); ok {
					if emailObj, ok := emailRule["email"].(map[string]interface{}); ok {
						if email, ok := emailObj["email"].(string); ok {
							emails = append(emails, email)
						}
					}
				}
			}
			return emails, nil
		}
	}

	return nil, fmt.Errorf("access group %q not found", groupName)
}

// DeleteAccessGroup deletes an Access group by name
func (c *Client) DeleteAccessGroup(groupName string) error {
	ctx := context.Background()

	// Find the group by name
	groups, _, err := c.api.ListAccessGroups(ctx, cloudflare.AccountIdentifier(c.accountID), cloudflare.ListAccessGroupsParams{})
	if err != nil {
		return fmt.Errorf("failed to list access groups: %w", err)
	}

	var groupID string
	for _, group := range groups {
		if group.Name == groupName {
			groupID = group.ID
			break
		}
	}

	if groupID == "" {
		return fmt.Errorf("access group %q not found", groupName)
	}

	// Delete the group
	err = c.api.DeleteAccessGroup(ctx, cloudflare.AccountIdentifier(c.accountID), groupID)
	if err != nil {
		return fmt.Errorf("failed to delete access group: %w", err)
	}

	fmt.Printf("✔ Deleted Access group %q\n", groupName)
	return nil
}
