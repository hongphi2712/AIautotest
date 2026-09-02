# Security Test Confirmation Flow Plan

## Problem

AI-generated security tests can be **destructive** (e.g., `POST /password/change` with `new_password=Pwned123!`). If executed without user approval, these tests can:
- Modify production data
- Lock out legitimate users
- Cause data loss

## Solution

Add a **confirmation gate** for destructive tests:
1. AI marks destructive tests with `requires_confirmation: true`
2. Executor pauses before running destructive tests
3. Frontend shows Approve/Reject banner
4. User decides whether to run the test
5. Test runs only if approved

## Data Flow

```
AI generates plan → SecurityTest.requires_confirmation = true
                         ↓
User clicks "Run" → security_run() creates oneshot channel
                         ↓
Executor reaches destructive test → sends ConfirmationRequest via WS
                         ↓
Frontend shows banner → User clicks Approve/Reject
                         ↓
POST /api/security/confirm → Executor receives response → continues/skips
```

---

## Layer 1: Schema (`crates/security/src/types.rs`)

### Add `requires_confirmation` field

```rust
pub struct SecurityTest {
    pub id: String,
    pub flaw: String,
    pub target: Target,
    pub severity: String,
    pub payload_hint: String,
    pub payload: Option<String>,
    pub location: Option<String>,
    pub oracle: Oracle,
    #[serde(default)]
    pub requires_confirmation: bool,  // NEW
}
```

### Add `is_destructive()` method

```rust
impl SecurityTest {
    pub fn is_destructive(&self) -> bool {
        let method = self.target.method.to_uppercase();
        let path_lower = self.target.path.to_lowercase();
        matches!(method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH")
            && (path_lower.contains("password")
                || path_lower.contains("delete")
                || path_lower.contains("remove")
                || path_lower.contains("destroy")
                || path_lower.contains("purge")
                || path_lower.contains("reset")
                || path_lower.contains("disable")
                || self.requires_confirmation)
    }
}
```

### Add confirmation types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationRequest {
    pub run_id: String,
    pub test_id: String,
    pub flaw: String,
    pub method: String,
    pub path: String,
    pub severity: String,
    pub payload_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationResponse {
    pub test_id: String,
    pub approved: bool,
}
```

---

## Layer 2: Executor (`crates/security/src/executor.rs`)

### Add confirmation fields to `SecurityExecutor`

```rust
pub struct SecurityExecutor {
    executor: Arc<RequestExecutor>,
    budget: BudgetTracker,
    limiter: Option<HostRateLimiter>,
    guard: Arc<ScopeGuard>,
    cancel: CancellationToken,
    event_tx: Option<mpsc::Sender<SecurityEvent>>,
    config: SecurityRunConfig,
    // NEW: confirmation
    confirmation_tx: Option<mpsc::Sender<ConfirmationRequest>>,
    pending_confirmations: Arc<Mutex<HashMap<String, oneshot::Sender<ConfirmationResponse>>>>,
}
```

### Add `needs_confirmation` to `SecurityEvent`

```rust
pub struct SecurityEvent {
    pub test_id: String,
    pub flaw: String,
    pub target: String,
    pub status: u16,
    pub passed: bool,
    pub has_finding: bool,
    pub skipped: bool,
    pub evidence: String,
    pub potential: bool,
    #[serde(default)]
    pub needs_confirmation: bool,  // NEW
}
```

### Insert confirmation gate in `execute()` loop

```rust
pub async fn execute(&self, plan: &SecurityTestPlan) -> SecurityRunOutcome {
    for test in plan.tests.iter() {
        // ... existing cancel check, build request, inject auth, scope check ...

        // === NEW: Confirmation gate ===
        if test.is_destructive() {
            if let Some(tx) = &self.confirmation_tx {
                let (resp_tx, resp_rx) = oneshot::channel::<ConfirmationResponse>();

                // Store response sender for REST endpoint
                self.pending_confirmations.lock().unwrap().insert(
                    test.id.clone(),
                    resp_tx,
                );

                // Send confirmation request via WS
                let _ = tx.send(ConfirmationRequest {
                    run_id: /* from config */,
                    test_id: test.id.clone(),
                    flaw: test.flaw.clone(),
                    method: test.target.method.clone(),
                    path: test.target.path.clone(),
                    severity: test.severity.clone(),
                    payload_hint: test.payload_hint.clone(),
                }).await;

                // Emit needs_confirmation event
                if let Some(event_tx) = &self.event_tx {
                    let _ = event_tx.send(SecurityEvent {
                        test_id: test.id.clone(),
                        flaw: test.flaw.clone(),
                        target: format!("{} {}", test.target.method, test.target.path),
                        status: 0,
                        passed: false,
                        has_finding: false,
                        skipped: false,
                        evidence: "awaiting user confirmation".into(),
                        potential: false,
                        needs_confirmation: true,
                    }).await;
                }

                // Wait for response with timeout + cancellation
                let approved = tokio::select! {
                    response = resp_rx => {
                        matches!(response, Ok(ConfirmationResponse { approved: true, .. }))
                    }
                    _ = tokio::time::sleep(Duration::from_secs(60)) => false,
                    _ = self.cancel.cancelled() => false,
                };

                // Cleanup
                self.pending_confirmations.lock().unwrap().remove(&test.id);

                if !approved {
                    skipped += 1;
                    if let Some(event_tx) = &self.event_tx {
                        let _ = event_tx.send(SecurityEvent {
                            test_id: test.id.clone(),
                            flaw: test.flaw.clone(),
                            target: format!("{} {}", test.target.method, test.target.path),
                            status: 0,
                            passed: false,
                            has_finding: false,
                            skipped: true,
                            evidence: "skipped: confirmation not approved or timed out".into(),
                            potential: false,
                            needs_confirmation: false,
                        }).await;
                    }
                    continue;
                }
            }
        }

        // ... existing budget check, rate limit, execute, evaluate ...
    }
}
```

---

## Layer 3: State (`apps/api-tester-server/src/state.rs`)

### Add confirmation storage

```rust
pub struct AppState {
    // ... existing fields ...
    pub security_confirmations: Arc<std::sync::Mutex<
        std::collections::HashMap<String, Arc<tokio::sync::Mutex<Option<oneshot::Sender<ConfirmationResponse>>>>>
    >>,
}
```

Initialize in `AppState::new()`:
```rust
security_confirmations: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
```

---

## Layer 4: Service (`apps/api-tester-server/src/security_service.rs`)

### Modify `security_run()` to create confirmation channels

```rust
pub async fn security_run(&self, req: SecurityRunRequest) -> Result<Value, WorkflowError> {
    // ... existing setup ...

    // NEW: confirmation channel
    let (conf_tx, mut conf_rx) = tokio::sync::mpsc::channel::<ConfirmationRequest>(1);

    // Store reference for REST endpoint
    // (actual oneshot senders are stored in executor's pending_confirmations)

    rt.spawn(async move {
        // ... build executor with confirmation_tx: Some(conf_tx) ...

        // Forward confirmation requests to WS
        let ws_forward = ws.clone();
        let run_id_forward = run_id_clone.clone();
        tokio::spawn(async move {
            while let Some(req) = conf_rx.recv().await {
                let _ = ws_forward.send(
                    serde_json::to_string(&json!({
                        "type": "security_confirm",
                        "run_id": run_id_forward,
                        "test_id": req.test_id,
                        "flaw": req.flaw,
                        "method": req.method,
                        "path": req.path,
                        "severity": req.severity,
                        "payload_hint": req.payload_hint,
                    })).unwrap_or_default(),
                );
            }
        });

        let outcome = exec.execute(&parsed).await;
        // ... rest unchanged ...

        // Cleanup confirmation state
        self.security_confirmations.lock().unwrap().remove(&run_id_clone);
    });
    Ok(json!({"run_id": run_id}))
}
```

### Add `security_confirm()` handler

```rust
#[derive(Deserialize)]
pub struct SecurityConfirmRequest {
    pub run_id: String,
    pub test_id: String,
    pub approved: bool,
}

pub async fn security_confirm(&self, req: SecurityConfirmRequest) -> Result<(), WorkflowError> {
    let confirmations = self.security_confirmations.lock()
        .map_err(|e| WorkflowError::Storage(e.to_string()))?;

    let sender = confirmations.get(&req.run_id)
        .ok_or_else(|| WorkflowError::NotFound("no active security run".into()))?;

    let sender = sender.lock().await;
    if let Some(tx) = sender.as_ref() {
        let _ = tx.send(ConfirmationResponse {
            test_id: req.test_id,
            approved: req.approved,
        });
    }
    Ok(())
}
```

---

## Layer 5: Routes (`apps/api-tester-server/src/routes.rs`)

### Add route

```rust
.route("/api/security/confirm", post(security_confirm))
```

### Add handler

```rust
async fn security_confirm(
    State(state): State<SharedState>,
    Json(body): Json<SecurityConfirmRequest>,
) -> Result<Json<Value>, ApiError> {
    state.security_confirm(body).await.map_err(fail)?;
    Ok(Json(json!({"ok": true})))
}
```

---

## Layer 6: Frontend (`apps/api-tester-server/ui/js/components/analyzer.js`)

### Add WebSocket listener

```js
// In connectedCallback
this.onWsSecConfirm = (event) => this.onSecurityConfirm(event.detail);
window.addEventListener('app:ws-security_confirm', this.onWsSecConfirm);
```

### Add confirmation handler

```js
onSecurityConfirm(detail) {
    if (!this.secRunId || detail.run_id !== this.secRunId) return;

    const box = this.querySelector('#sec-findings');
    const banner = document.createElement('div');
    banner.className = 'sec-confirm-banner';
    banner.dataset.testId = detail.test_id;
    banner.innerHTML = `
        <div class="sec-confirm-info">
            <span class="sec-badge warn">XAC NHIN</span>
            <strong>${escapeHtml(detail.method)} ${escapeHtml(detail.path)}</strong>
            <span class="muted">${escapeHtml(detail.flaw)} / ${escapeHtml(detail.severity)}</span>
        </div>
        <div class="sec-confirm-hint">${escapeHtml(detail.payload_hint)}</div>
        <div class="sec-confirm-timer">Auto-skip trong <span class="sec-confirm-countdown">60</span>s</div>
        <div class="sec-confirm-actions">
            <button class="btn primary sec-confirm-approve">Approve</button>
            <button class="btn danger sec-confirm-reject">Reject</button>
        </div>
    `;
    box.appendChild(banner);
    box.scrollTop = box.scrollHeight;

    // Countdown timer
    let remaining = 60;
    const timer = setInterval(() => {
        remaining--;
        const el = banner.querySelector('.sec-confirm-countdown');
        if (el) el.textContent = remaining;
        if (remaining <= 0) {
            clearInterval(timer);
            banner.remove();
        }
    }, 1000);

    // Button handlers
    banner.querySelector('.sec-confirm-approve').addEventListener('click', () => {
        clearInterval(timer);
        this.secSendConfirmation(detail.test_id, true);
        banner.classList.add('sec-confirm-pending');
        banner.querySelector('.sec-confirm-actions').innerHTML = '<span class="muted">Dang xu ly...</span>';
    });

    banner.querySelector('.sec-confirm-reject').addEventListener('click', () => {
        clearInterval(timer);
        this.secSendConfirmation(detail.test_id, false);
        banner.remove();
    });
}

async secSendConfirmation(testId, approved) {
    try {
        await apiPost('/api/security/confirm', {
            run_id: this.secRunId,
            test_id: testId,
            approved: approved,
        });
    } catch (e) {
        showError('Confirmation failed: ' + e);
    }
}
```

### Add cleanup

```js
// In disconnectedCallback
window.removeEventListener('app:ws-security_confirm', this.onWsSecConfirm);
```

---

## CSS (`apps/api-tester-server/ui/styles/features/analyzer.css`)

```css
.sec-confirm-banner {
    border: 2px solid var(--orange);
    border-radius: 6px;
    padding: 12px;
    margin: 8px 0;
    background: var(--panel-3);
}
.sec-confirm-info {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
}
.sec-confirm-hint {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 8px;
}
.sec-confirm-timer {
    font-size: 11px;
    color: var(--orange);
    margin-bottom: 8px;
}
.sec-confirm-actions {
    display: flex;
    gap: 8px;
}
.sec-confirm-pending {
    opacity: 0.7;
    pointer-events: none;
}
```

---

## Security Prompt Update (`crates/ai/src/security_prompt.rs`)

Add to `SECURITY_SYSTEM_PROMPT`:

```
- CRITICAL: ALL tests MUST be non-destructive and read-only when possible.
- For CSRF: Set "requires_confirmation": true if the test would actually submit a form that modifies data.
- For auth_bypass: Send requests WITHOUT credentials and check response does NOT leak sensitive data.
- For rate_limit: Send only 2-3 requests to check for 429 response. Do NOT flood.
- NEVER target endpoints that change passwords, delete accounts, or perform financial transactions without "requires_confirmation": true.
```

---

## Verification Plan

| Step | Command | Expected |
|------|---------|----------|
| 1 | `cargo check --package api-tester-security` | No errors |
| 2 | `cargo check --package api-tester-server` | No errors |
| 3 | `cargo test --workspace` | All pass |
| 4 | `node -c analyzer.js` | No syntax errors |
| 5 | Generate plan with destructive test | `requires_confirmation: true` |
| 6 | Run plan | Banner appears for destructive test |
| 7 | Click Approve | Test executes |
| 8 | Click Reject | Test skipped |
| 9 | Wait 60s | Test auto-skipped |

---

## Files Summary

| File | Change | Lines |
|------|--------|-------|
| `crates/security/src/types.rs` | Add field + method + types | ~30 |
| `crates/security/src/executor.rs` | Add confirmation gate | ~50 |
| `apps/api-tester-server/src/state.rs` | Add HashMap field | ~5 |
| `apps/api-tester-server/src/security_service.rs` | Channel + WS + handler | ~40 |
| `apps/api-tester-server/src/routes.rs` | Add route + handler | ~15 |
| `apps/api-tester-server/ui/js/components/analyzer.js` | Banner UI + handlers | ~60 |
| `apps/api-tester-server/ui/styles/features/analyzer.css` | Banner styles | ~25 |
| `crates/ai/src/security_prompt.rs` | Update prompt | ~5 |
| **Total** | | **~230 lines** |
