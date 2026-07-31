package security

import (
	"errors"
	"fmt"
)

var ErrSecurityViolation = errors.New("security invariant violation")

// SecurityInvariants documents and verifies the 20 code-level security invariants of AI Security Lab Runner.
//
// Invariant 1: Agent commands never execute on the host. (Enforced in internal/docker/client.go)
// Invariant 2: Agent commands execute only in a verified runner container. (Enforced in internal/lab/engine.go)
// Invariant 3: The runner container never receives the Docker socket. (Enforced in internal/docker/compose_generator.go)
// Invariant 4: Workspace is read-only. (Enforced in internal/docker/compose_generator.go)
// Invariant 5: Scratch is the only persistent writable agent directory. (Enforced in internal/lab/engine.go)
// Invariant 6: Target and runner use an internal Docker network. (Enforced in internal/docker/compose_generator.go)
// Invariant 7: Host port publication is disabled by default. (Enforced in internal/config/config.go & compose_generator.go)
// Invariant 8: Export is disabled by default. (Enforced in internal/config/config.go & internal/lab/engine.go)
// Invariant 9: All host paths remain inside configured roots. (Enforced in internal/pathsafe/host.go)
// Invariant 10: All container paths remain inside their allowed roots. (Enforced in internal/pathsafe/container.go)
// Invariant 11: Destructive Docker operations require verified labels. (Enforced in internal/docker/client.go)
// Invariant 12: Session identifiers are unpredictable. (Enforced in internal/session/session.go)
// Invariant 13: Command output is bounded. (Enforced in internal/output/bounded_writer.go)
// Invariant 14: Command duration is bounded. (Enforced in internal/lab/engine.go)
// Invariant 15: CPU, memory, and process counts are bounded. (Enforced in internal/docker/compose_generator.go)
// Invariant 16: Containers run without additional Linux capabilities (cap_drop: ALL). (Enforced in internal/docker/compose_generator.go)
// Invariant 17: Containers use no-new-privileges:true. (Enforced in internal/docker/compose_generator.go)
// Invariant 18: The runner uses a non-root user (agent UID 10001). (Enforced in runner/Dockerfile)
// Invariant 19: MCP stdout contains no non-protocol output. (Enforced in internal/mcp/server.go)
// Invariant 20: Secrets are redacted from audit records. (Enforced in internal/audit/audit.go)

type PolicySummary struct {
	CommandPolicy           string `json:"command_policy"`
	HostExecutionAllowed    bool   `json:"host_execution_allowed"`
	DockerSocketMounted     bool   `json:"docker_socket_mounted"`
	WorkspaceReadOnly       bool   `json:"workspace_read_only"`
	ScratchWritableOnly     bool   `json:"scratch_writable_only"`
	InternalNetworkRequired bool   `json:"internal_network_required"`
	HostPortPublishAllowed  bool   `json:"host_port_publish_allowed"`
	ExportAllowed           bool   `json:"export_allowed"`
}

func GetPolicySummary(allowExport, allowPortPublish, allowInternet bool) PolicySummary {
	return PolicySummary{
		CommandPolicy:           "container-only",
		HostExecutionAllowed:    false,
		DockerSocketMounted:     false,
		WorkspaceReadOnly:       true,
		ScratchWritableOnly:     true,
		InternalNetworkRequired: !allowInternet,
		HostPortPublishAllowed:  allowPortPublish,
		ExportAllowed:           allowExport,
	}
}

func VerifyHostExecutionProhibited(hostCommand string) error {
	return fmt.Errorf("%w: direct host command execution ('%s') is prohibited by policy", ErrSecurityViolation, hostCommand)
}
