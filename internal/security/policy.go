package security

import (
	"errors"
	"fmt"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
)

var ErrSecurityViolation = errors.New("security invariant violation")

type PolicySummary struct {
	CommandPolicy          string `json:"command_policy"`
	HostExecutionAllowed   bool   `json:"host_execution_allowed"`
	DockerSocketMounted    bool   `json:"docker_socket_mounted"`
	HostMountsAllowed      bool   `json:"host_mounts_allowed"`
	ScratchWritableOnly    bool   `json:"scratch_writable_only"`
	OutboundNetworkEnabled bool   `json:"outbound_network_enabled"`
	HostGatewayEnabled     bool   `json:"host_gateway_enabled"`
	ExportAllowed          bool   `json:"export_allowed"`
}

func GetPolicySummary(cfg *config.Config) PolicySummary {
	return PolicySummary{
		CommandPolicy:          "container-only",
		HostExecutionAllowed:   false,
		DockerSocketMounted:    false,
		HostMountsAllowed:      false,
		ScratchWritableOnly:    true,
		OutboundNetworkEnabled: cfg.Network.OutboundEnabled,
		HostGatewayEnabled:     cfg.Network.HostGatewayEnabled,
		ExportAllowed:          cfg.Security.AllowExport,
	}
}

func VerifyHostExecutionProhibited(hostCommand string) error {
	return fmt.Errorf("%w: direct host command execution ('%s') is prohibited by policy", ErrSecurityViolation, hostCommand)
}
