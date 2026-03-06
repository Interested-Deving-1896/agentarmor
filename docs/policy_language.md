# AgentArmor Policy Language Reference

Policies are YAML files that define what an agent type is allowed to do.
Load a policy with `ArmorConfig.from_yaml("path/to/policy.yaml")`.

---

## File Structure

```yaml
version: "1.0"           # Always "1.0" for now
name: "my_agent"         # Human-readable name
agent_type: "general"    # Used for logging and audit
risk_level: "medium"     # low | medium | high — affects default strictness

# Per-layer configuration (all optional — falls back to defaults)
ingestion: { ... }
storage: { ... }
context: { ... }
planning: { ... }
execution: { ... }
output: { ... }
interagent: { ... }
identity: { ... }

# Declarative rules (evaluated before the layer pipeline)
global_denied_actions: [...]
require_human_approval_for: [...]
rules: [...]
```

---

## Layer Configuration

### ingestion

```yaml
ingestion:
  enabled: true                    # Default: true
  scan_for_injection: true         # Run INJECTION_PATTERNS regex scan
  max_input_size_bytes: 10485760   # 10MB max input size
```

### storage

```yaml
storage:
  enabled: true
  encryption: "aes-256-gcm"        # Only supported algorithm
  encryption_key_env: "AGENTARMOR_ENCRYPTION_KEY"  # Env var holding hex key
  integrity_check: true            # BLAKE3 hash verification on reads
```

### context

```yaml
context:
  enabled: true
  enforce_instruction_separation: true   # Validate system/user message separation
  max_context_tokens: 128000             # Max tokens in assembled context
  prompt_hardening: true                 # Append security directives to system prompt
  canary_tokens: true                    # Inject and monitor canary tokens
```

### planning

```yaml
planning:
  enabled: true
  max_chain_depth: 10          # Max steps in an agent's action plan
  require_plan_validation: true
  denied_actions:              # Hard-deny these action patterns
    - "shell.*"
    - "os.system"
    - "database.drop"
    - "database.truncate"
  allowed_actions:             # If set, ONLY these are permitted (whitelist mode)
    - "read.*"
    - "search.*"
    - "database.query"
```

### execution

```yaml
execution:
  enabled: true
  sandbox_enabled: true
  network_egress_allowed: false        # Default: block all outbound HTTP
  allowed_hosts:                       # If egress enabled, only these hostnames
    - "api.openai.com"
    - "api.anthropic.com"
  rate_limits:                         # Per-action limits per 60s window
    "*": 100                           # Global fallback
    "database.*": 10
    "email.send": 5
    "transfer.*": 3
  require_human_approval:              # Escalate these for human review
    - action: "transfer.*"
      condition: "amount > 100"        # Conditional: field operator value
    - action: "database.delete"        # Unconditional: always require approval
    - action: "email.send"
      condition: "recipients > 10"
```

### output

```yaml
output:
  enabled: true
  pii_redaction: true          # Redact PII using Presidio + regex fallback
  sensitivity_filtering: true  # Block API keys, passwords, tokens in output
  blocked_patterns:            # Custom patterns to redact
    - "INTERNAL-[A-Z0-9]+"
    - "SECRET_[a-z_]+"
```

### interagent

```yaml
interagent:
  enabled: true
  require_mutual_auth: true    # HMAC-SHA256 signature verification
  trust_scoring: true          # Track and decay trust scores
  min_trust_score: 0.7         # Below this score → DENY
  max_delegation_depth: 3      # Max A→B→C→... hops
  message_ttl_seconds: 300     # Signed messages expire after 5 minutes
```

### identity

```yaml
identity:
  enabled: true
  credential_ttl_seconds: 3600   # Tokens expire after 1 hour
  jit_permissions: true          # Allow JIT permission grants
  jit_ttl_seconds: 300           # JIT grants expire after 5 minutes
```

---

## Declarative Rules

Rules are evaluated **before** the layer pipeline runs. They provide fast, readable
policy logic without writing Python.

```yaml
rules:
  - name: "rule_name"               # Required, used in audit logs
    action_pattern: "transfer.*"    # Glob pattern matching action names
    conditions:                     # All conditions must match (AND logic)
      - field: "params.amount"
        operator: ">"
        value: "1000"
      - field: "context.verified"
        operator: "!="
        value: "true"
    verdict: "deny"                 # allow | deny | escalate | audit
    message: "Large unverified transfer"  # Shown in block message
    priority: 100                   # Higher priority rules run first
```

### Condition Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `>` | Greater than (numeric) | `amount > 1000` |
| `<` | Less than (numeric) | `risk_score < 0.3` |
| `>=` | Greater than or equal | `file_count >= 10` |
| `<=` | Less than or equal | `size_mb <= 100` |
| `==` | Exact equality (string) | `env == "production"` |
| `!=` | Not equal | `status != "approved"` |
| `contains` | String contains | `path contains /etc/` |
| `matches` | Regex match | `action matches ^shell\.` |
| `in` | Value in list | `role in [admin, root]` |

### Field Paths

Fields are dot-notation paths into the `AgentEvent` object:

| Path | Refers To |
|------|-----------|
| `params.X` | Tool call parameter named X |
| `context.X` | Agent context key X |
| `metadata.X` | Event metadata key X |
| `action` | The action string itself |
| `agent_id` | The agent's identifier |

---

## Complete Example Policies

### Minimal read-only agent

```yaml
version: "1.0"
name: "readonly_agent"
agent_type: "research"
risk_level: "low"

planning:
  allowed_actions:
    - "read.*"
    - "search.*"
    - "scan.*"

execution:
  network_egress_allowed: true
  allowed_hosts:
    - "wikipedia.org"
    - "arxiv.org"
  rate_limits:
    "*": 50

output:
  pii_redaction: true
```

### High-security financial agent

```yaml
version: "1.0"
name: "financial_agent"
agent_type: "financial"
risk_level: "high"

planning:
  max_chain_depth: 5
  denied_actions:
    - "shell.*"
    - "database.delete"
    - "database.drop"
    - "database.truncate"

execution:
  network_egress_allowed: true
  allowed_hosts:
    - "api.stripe.com"
    - "api.plaid.com"
  rate_limits:
    "transfer.*": 3
    "payment.*": 5
    "*": 50
  require_human_approval:
    - action: "transfer.*"
      condition: "amount > 100"
    - action: "payment.*"
      condition: "amount > 500"

output:
  pii_redaction: true
  sensitivity_filtering: true

identity:
  credential_ttl_seconds: 1800   # 30-minute tokens for financial agents
  jit_permissions: false         # No JIT — only explicitly granted permissions

rules:
  - name: "block_bulk_transfers"
    action_pattern: "transfer.*"
    conditions:
      - field: "context.transfer_count"
        operator: ">="
        value: "5"
    verdict: "deny"
    message: "Bulk transfer limit reached (5 per session)"
    priority: 200
```

### Database editor agent (needs delete, but with guard rails)

```yaml
version: "1.0"
name: "db_editor_agent"
agent_type: "database"
risk_level: "high"

planning:
  max_chain_depth: 8
  denied_actions:
    - "database.drop"       # Never drop tables
    - "database.truncate"   # Never truncate
    - "shell.*"
  allowed_actions:
    - "database.*"          # All DB ops allowed, subject to rules below
    - "scan.*"
    - "read.*"

execution:
  network_egress_allowed: false
  rate_limits:
    "database.delete": 10   # Max 10 deletes per minute
    "database.write": 50
    "*": 100
  require_human_approval:
    - action: "database.delete"
      condition: "params.estimated_rows > 100"

rules:
  - name: "require_where_clause"
    action_pattern: "database.delete"
    conditions:
      - field: "params.where"
        operator: "=="
        value: ""            # Empty WHERE = delete ALL rows
    verdict: "deny"
    message: "DELETE without WHERE clause is forbidden"
    priority: 300
```
