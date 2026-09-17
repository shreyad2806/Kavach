// Cedar authorization policies for Kavach Shield
// These policies define which agents can perform which actions on which resources.
// Deny-by-default: any request without a matching permit is denied.

// ============================================================================
// Research Agent Policies
// ============================================================================
permit (
    principal == Agent::"research-01",
    action == Action::"research.search",
    resource == Resource::"research-data"
);

permit (
    principal == Agent::"research-01",
    action == Action::"research.read",
    resource == Resource::"research-data"
);

// ============================================================================
// Coding Agent Policies
// ============================================================================
permit (
    principal == Agent::"coding-01",
    action == Action::"coding.read",
    resource == Resource::"workspace"
);

permit (
    principal == Agent::"coding-01",
    action == Action::"coding.write",
    resource == Resource::"workspace"
);

permit (
    principal == Agent::"coding-01",
    action == Action::"coding.test",
    resource == Resource::"test-environment"
);

// ============================================================================
// Deployment Agent Policies
// ============================================================================
permit (
    principal == Agent::"deployment-01",
    action == Action::"deployment.preview",
    resource == Resource::"staging-environment"
);

permit (
    principal == Agent::"deployment-01",
    action == Action::"deployment.deploy",
    resource == Resource::"production-environment"
);

// ============================================================================
// No policies for:
// - orchestrator-01
// - verification-01
// - deployment.deploy
// - cross-agent delegation
// - quarantine
// - suspicious behavior
// - risk scores
// - provenance
// - capability checks
//
// Deny-by-default: requests without a matching permit are denied.
// ============================================================================
