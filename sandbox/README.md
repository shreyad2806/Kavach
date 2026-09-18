# KAVACH Sandbox Layer

The Sandbox layer provides **Runtime Security** and boundary enforcement for autonomous agents.

## Architecture

The sandbox operates as a set of abstractions over raw OS primitives and transport layers. It enforces the principle of least privilege, ensuring that agents cannot escape their designated boundaries.

The sandbox enforces the following isolations:

1. **Filesystem Isolation**
   Agents interact with a `SafeWorkspace` which restricts all file operations (read/write) strictly to the agent's assigned directory. It blocks path traversal attacks (e.g., `../../`) and rejects absolute paths outside the workspace.

2. **Communication Isolation**
   The `MessageBus` implements an explicit allowlist of allowed agent-to-agent communication routes. Attempting to send messages outside this allowlist drops the message and logs a security event.

3. **Network Isolation**
   The `NetworkManager` enforces that only specific agents (e.g., `research`) are allowed to perform network operations, such as simulated web searches. All other network operations are blocked.

4. **Tool Isolation**
   The main `Sandbox` acts as a wrapper around the `ToolExecutor`. It uses the explicitly declared agent capabilities (from `AgentIdentity`) to allow or deny tool executions.

5. **Process Isolation**
   Arbitrary command execution (e.g., `subprocess`, `os.system`) is strictly prohibited. The sandbox intercepts and blocks these requests before they reach the executor.

6. **Credential Isolation**
   The sandbox verifies that no sensitive credentials (like AWS keys) are exposed to the agent environment before executing tools.

7. **Deployment Isolation**
   All deployment operations remain simulations.

## Security Events

Any blocked action emits a structured `SecurityEvent` to the `EventLogger` (locally stored in `security_events.jsonl`).

Event examples:
- `WORKSPACE_ACCESS_DENIED`
- `COMMUNICATION_DENIED`
- `TOOL_ACCESS_DENIED`
- `NETWORK_ACCESS_DENIED`
- `CREDENTIAL_ACCESS_DENIED`
- `PROCESS_EXECUTION_DENIED`

## KAVACH Authorization vs. Sandbox Isolation

**Sandbox isolation is a runtime boundary.**
It acts as a defensive guardrail around raw execution environments.

**KAVACH authorization is the security authority.**
KAVACH (Cedar policies, dynamic risk analysis) decides *whether* a capability should be granted. The sandbox merely enforces that the granted capability is respected and no raw escape is possible.

## Known Limitations

- The current implementation provides a local Python-based abstraction for demonstration purposes.
- For production, a containerized approach (e.g., Docker) should be used. In a Docker model:
  - Each agent runs in its own container as a non-root user.
  - The workspace is the only host mount.
  - No AWS credentials are provided to the container.
  - Network is restricted via Docker bridge networks.

## Running Tests

Run the comprehensive sandbox test suite to verify all isolation properties:

```bash
python -m scripts.test_sandbox
```

To run the full multi-agent workflow:

```bash
python -m scripts.run_workflow
```

To demonstrate the baseline attack scenario (where KAVACH must step in):

```bash
python -m scripts.run_attack
```
