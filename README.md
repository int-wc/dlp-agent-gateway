# DLP Agent Gateway

[中文](#中文) · [English](#english)

## 中文

这是一个可运行的上传环节 DLP（数据防泄漏）策略执行网关参考项目。它在文件发送到预先配置的下游系统**之前**完成检查，将不可绕过的安全规则与可选的本地大模型上下文研判结合，并记录尽量少包含敏感内容的审计信息。本项目用于作品展示和授权测试，**不是可直接用于生产环境的安全产品**。

### v0.1 已实现

| 模块 | 能力 |
| --- | --- |
| 上传网关 | 需认证的检查/转发接口；只能选择服务端配置的目标；文件上限 8 MiB；仅当判定为 `allow` 时转发刚刚检查过的同一份文件。 |
| 内容提取 | UTF-8 文本、代码、CSV、JSON，文字型 PDF（最多 30 页）和 DOCX；可选 Tesseract 图片 OCR（PNG/JPEG）。不支持、加密、空白或无法解析的文件进入 `review`，不会直接放行。 |
| 风险决策 | 内置密钥与个人信息候选特征、可配置的字面关键词策略、离职/重点人员状态，以及可选的本地 Ollama 研判。模型不能降低规则判定；已启用模型但模型不可用时进入人工复核。 |
| 运营与审计 | SQLite 审计元数据（不保存文件正文）、策略与人员状态管理、按人员+目标+SHA-256 限定且会过期的策略例外、管理员操作记录、误报反馈及 1–90 天统计接口。 |
| 界面 | 本地运营台 `/console`；OpenAPI 接口说明 `/docs`。 |

这里的“Agent”受到刻意约束：可选的本地模型只读取一段有长度上限的文本并给出风险等级，不能自行修改策略、批准例外或选择外发目标。未启用 Ollama 时，系统明确以纯规则模式运行。

### 本地运行

需要 Python 3.11 或更高版本。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
cp .env.example .env
# 把两个示例密钥分别替换为不同的随机值，长度至少 24 个字符。
# .env 已被 Git 忽略，不要上传。
.venv/bin/uvicorn dlp_gateway.main:app --env-file .env --host 127.0.0.1 --port 18080
```

可分别运行 `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'` 生成密钥。多个上传身份可通过 `DLP_CLIENT_KEYS_JSON` 配置为“身份 ID → 不同密钥”的 JSON 对象；身份由密钥确定，不接受客户端自行填写的身份请求头。默认提供 `internal-demo` 和 `external-demo` 两个**仅检查**的目标。只有配置了目标 URL、显式调用 `/v1/forward/...` 且结果为 `allow`，文件才会被转发。

打开 [http://127.0.0.1:18080/console](http://127.0.0.1:18080/console)，输入管理员密钥。运营台只在当前页面会话中使用该密钥。用自造的测试文件试一次检查：

```bash
curl -sS -H "Authorization: Bearer YOUR_CLIENT_KEY" \
  -F 'file=@synthetic.txt;type=text/plain' \
  http://127.0.0.1:18080/v1/check/external-demo
```

请自行创建仅包含虚构内容的 `synthetic.txt`。例如，文件内的 `Call 13800138000` 会在外部目标触发 `review`；虚构的 `-----BEGIN PRIVATE KEY-----` 标记会触发 `block`。这些只是候选特征，不代表识别出了真实密钥或已验证的身份信息。不要向演示实例上传真实企业或个人敏感数据。

如需演示真实转发，在 `DLP_DESTINATIONS_JSON` 中配置固定下游 URL，例如 `{"internal-demo":{"kind":"internal","url":"http://127.0.0.1:9000/upload"}}`，再调用 `/v1/forward/internal-demo`。非本机目标必须使用 HTTPS；接收服务需自行准备。网关不接受客户端指定任意 URL，也不会跟随下游重定向；下游返回非 2xx、重定向或超时均报错，不标记为已转发，也不会将下游响应正文返回给调用方。

可选模型：在本机启动 Ollama、拉取适用的 Qwen 模型，设置 `DLP_OLLAMA_MODEL=qwen2.5:7b` 后重启。网关最多向本机环回模型服务发送 2,000 个字符，超时为 4 秒；这段文字仍可能包含敏感内容，因此模型服务也必须保持本地且受控。配置了模型但服务不可用时，上传进入复核。图片 OCR 还需安装 `pip install -e ".[ocr]"` 和系统的 `tesseract` 命令；未安装时图片进入复核。

Docker 演示：用真实随机密钥准备 `.env` 后运行 `docker compose up --build`。服务仅绑定 `127.0.0.1:18080`（容器内部仍使用 8080）；容器配置不包含 TLS、SSO、反向代理请求体限制、解析沙箱或生产加固。

### 接口与人工闭环

1. 受信任的业务集成使用对应人员密钥认证，以 multipart 字段 `file` 调用 `POST /v1/check/{destination}` 或 `POST /v1/forward/{destination}`。
2. 返回结果为 `allow`、`review` 或 `block`，同时给出原因**代码**、SHA-256 摘要和审计 ID。`review` 和 `block` 绝不转发。
3. 管理员通过 `/v1/admin/...` 管理字面关键词策略和人员状态；这些管理操作另有操作记录。
4. 客户端可针对命中策略的审计 ID 调用 `POST /v1/exceptions`，提交 `audit_id` 和 `justification`。管理员批准 1–24 小时或驳回。批准后，同一身份须向同一目标重新上传**完全相同的文件字节**。例外仅跳过可配置的策略命中，不跳过内置密钥/人员硬规则、个人信息复核或模型故障。
5. 管理员可通过 `PUT /v1/admin/audits/{id}/feedback` 将告警标记为 `false_positive`。`/v1/admin/report` 汇总待复盘的策略候选，**不会自动修改阈值或策略**。

运营台覆盖常见操作，完整请求与响应结构见 `/docs`。数据库仍会保存文件名、人员 ID 和申请理由，这些元数据本身可能敏感；实际使用时须保护数据库并制定保留、轮换及删除规则。

### 判定流程

```text
已认证身份 + 服务端允许的目标
  → 有上限的文件读取 → 格式解析
  → 不可绕过的内置规则 + 配置策略
  → 可选本地模型建议（只能提高审查强度）
  → 审计元数据 → 放行 / 人工复核 / 阻断
  → 放行 + 显式转发 + 已配置接收端 → 同一文件字节发往下游
```

### 安全边界与未实现能力

- 这是供授权企业测试使用的**参考实现**，不是透明流量拦截器。业务系统必须主动接入；绕过网关的上传也会绕过检查。
- 共享人员密钥只适合演示。生产使用前需要 mTLS/SSO 或签名的工作负载身份、应用级权限、密钥轮换、审批分权，以及加密并有保留期限的审计存储。
- 解析器和 OCR 在同一进程内运行，恶意文件可能消耗 CPU 或内存。应改为有时间/内存配额的隔离解析任务，并增加恶意软件扫描与反向代理请求体限制。框架可能在应用检查 8 MiB 限制**之前**将 multipart 内容暂存到磁盘。提取文本超过 100,000 字符会进入复核而不是只检查前半部分后放行；某些格式特性仍可能完全未提取，不能将结果视为全覆盖。
- 扫描件 PDF 尚不支持页面 OCR（目前只支持独立图片 OCR）；嵌套压缩包、XLSX/PPTX、加密文件、未知编码及复杂嵌入内容均未解析，进入复核。原生 PDF/DOCX 的提取也不能保证完整。
- 正则特征会误报，模型可能误判或受文件中指令影响，二者都不应独自决定不可逆操作。可配置的策略阻断可申请复核；演示版内置的外发密钥和离职人员硬规则不可通过例外绕过。
- SQLite 是单实例演示存储；尚无 Elasticsearch、消息队列、LDAP/HR 自动同步、高可用、多租户隔离、合规映射或自动周报邮件。统计接口可供运营人员自行导出。
- 公开 issue、测试数据、截图和提交中不得出现真实敏感数据。接入托管模型前应另行评估隐私与数据处理要求。

信任边界和部署检查清单见 [SECURITY.md](SECURITY.md)。运行测试：`.venv/bin/python -m pytest -q`。

### 后续里程碑

1. 解析任务沙箱化，增加完整覆盖的分块提取、PDF 图片 OCR、内容类型核验和端到端上传大小限制。
2. 接入签名身份/HR 同步、职责分离审批、审计保留与加密及 RBAC。
3. 增加大文件异步隔离、可靠的下游幂等投递、Elasticsearch/OpenSearch 导出、趋势面板与定期报表。
4. 用合成或已获同意的标注样本评估模型；策略优化须经人工批准并通过回归测试。

MIT 许可。贡献内容应使用合成数据并附上测试。

## English

A runnable reference implementation of an upload-time DLP policy enforcement point. It checks files **before** a configured downstream upload, combines hard safety rules with optional local LLM context review, and records a privacy-minimized audit trail. Built as a portfolio/demo project, **not a production security product**.

## What works in v0.1

| Area | Implementation |
| --- | --- |
| Upload gateway | Authenticated check/forward endpoints; only server-configured destinations; up to 8 MiB; forward the exact bytes checked, and only on `allow`. |
| Extraction | UTF-8 text/code/CSV/JSON, text-based PDF (30 pages max), DOCX; optional PNG/JPEG OCR with Tesseract. Unsupported, encrypted, empty and unreadable files go to `review`. |
| Decision | Built-in secret/PII candidate signals, configurable literal-keyword policies, departing/privileged user status, optional local Ollama assessment. Rules cannot be downgraded by the model. Model outages require review when enabled. |
| Operations | SQLite audit metadata (no file bodies), policy and personnel controls, expiring actor+destination+SHA-256 policy exceptions, admin action log, false-positive feedback and 1–90-day report query. |
| UI | Local admin console at `/console`; OpenAPI docs at `/docs`. |

The “Agent” is deliberately constrained: an optional local model reviews a bounded text excerpt and returns a risk category. It does not autonomously change policy, grant exceptions or choose where data goes. Without Ollama the gateway runs in clearly labeled `rules-only` mode.

## Run locally

Requires Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
cp .env.example .env
# Replace BOTH example keys with DIFFERENT random values, at least 24 characters each.
# Keep .env private; it is ignored by Git.
.venv/bin/uvicorn dlp_gateway.main:app --env-file .env --host 127.0.0.1 --port 18080
```

Generate each key with `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`. For multiple actors, set `DLP_CLIENT_KEYS_JSON` to a JSON object mapping actor IDs to distinct keys; actor identity comes from the key, not a client-supplied header. The example config provides two **check-only** destinations by default (`internal-demo`, `external-demo`). No bytes leave the gateway unless a destination URL is configured and `/v1/forward/...` is explicitly called after an `allow` decision.

Open [http://127.0.0.1:18080/console](http://127.0.0.1:18080/console) and enter the admin key. The console keeps it only in the page session. To try a synthetic file:

```bash
curl -sS -H "Authorization: Bearer YOUR_CLIENT_KEY" \
  -F 'file=@synthetic.txt;type=text/plain' \
  http://127.0.0.1:18080/v1/check/external-demo
```

Use a locally created file with invented text. For example, a file containing `Call 13800138000` yields `review` at an external destination; an invented `-----BEGIN PRIVATE KEY-----` marker yields `block`. These are candidate signals, **not** proof of a real secret or a validated identity number. Do not submit actual corporate or personal data to a demo instance.

To exercise actual forwarding, put a fixed downstream URL in `DLP_DESTINATIONS_JSON`, for example `{"internal-demo":{"kind":"internal","url":"http://127.0.0.1:9000/upload"}}`, and call `/v1/forward/internal-demo`. HTTPS is required for non-loopback targets. Configure the receiver yourself; the gateway does not discover or proxy arbitrary client URLs. A downstream non-2xx/redirect or timeout returns an error and is **not** marked forwarded. The downstream response body is never returned.

Optional model: run Ollama locally, pull an appropriate Qwen model, set `DLP_OLLAMA_MODEL=qwen2.5:7b`, then restart. Only a maximum 2,000-character excerpt is sent to the loopback model service, with a 4-second timeout; that excerpt can still contain sensitive content, so keep Ollama local and controlled. If configured but unavailable, uploads require review. OCR requires `pip install -e ".[ocr]"` and the system `tesseract` binary. Unavailable OCR means image uploads require review.

Docker demo: `docker compose up --build` after creating `.env` with real random keys. It binds only to `127.0.0.1:18080` (the container still listens on 8080); no TLS, SSO, upload-size reverse proxy, parser sandbox or production hardening is included.

## API / workflow

1. A trusted integration authenticates with its actor-specific client key and calls `POST /v1/check/{destination}` or `POST /v1/forward/{destination}` with multipart field `file`.
2. A decision contains `allow`, `review` or `block`, reason **codes**, a SHA-256 hash and an audit ID. `review` and `block` never forward.
3. Administrators manage literal keyword policies and personnel status with `/v1/admin/...`; all such changes have an admin-event record.
4. A client may request an exception for a policy-hit audit using `POST /v1/exceptions` with `audit_id` and `justification`. An administrator approves for 1–24 hours or rejects it. The client re-uploads the *same bytes* to the *same destination* under the *same actor key*. An approval bypasses only policy hits, never hard secret/personnel guards, PII review or model outages.
5. Administrators mark an audit as `false_positive` via `PUT /v1/admin/audits/{id}/feedback`. `/v1/admin/report` counts policy candidates for review; no automatic threshold or rule mutation occurs.

The console implements common operations; the complete schema is available at `/docs`. Database rows retain filenames, actor IDs and approval justifications, which may themselves be sensitive. Protect and rotate the database, and set a retention/deletion policy for your environment.

## Decision flow

```text
authenticated actor + allowlisted destination
  → bounded multipart read → format extraction
  → non-bypassable guards + configured policies
  → optional local model advisory (may escalate only)
  → audit metadata → allow / review / block
  → allow + explicit forward + configured receiver → same bytes upstream
```

## Security boundaries and limitations

- This is a **reference implementation** for authorized enterprise testing, not a transparent network interceptor. Applications must intentionally integrate the endpoint; bypassing it bypasses DLP.
- The shared actor keys are suitable only for a demo integration. Before production, add mTLS/SSO or signed workload identity, per-application authorization, key rotation, robust approval separation, and encrypted/retained audit storage.
- Parsers and OCR run in-process; hostile documents may consume CPU/memory. Put parsing in a sandboxed worker with time/memory quotas, malware scanning, and reverse-proxy request limits. Multipart spooling can use disk *before* the application enforces its 8 MiB file limit. Extraction exceeding 100,000 characters requires review rather than a partial allow. Some format features are not extracted at all, so do not assume complete coverage.
- PDF scan-only pages need OCR (currently image OCR only); nested archives, XLSX/PPTX, encrypted files, unknown encodings and complex embedded content are not extracted. They go to review. Native PDF/DOCX extraction is not guaranteed complete.
- Regex signals can be false positives; a model can misclassify or follow document-borne instructions. Neither should be a sole basis for irreversible decisions. Configurable policy blocks are reviewable; built-in external secret/departing guards remain non-bypassable in this demo.
- SQLite is a single-instance demo backend; there is no Elasticsearch, queue, LDAP/HR synchronization, HA, tenant isolation, compliance mapping or automatic weekly mailer. The report endpoint supplies aggregates for an operator to export.
- Avoid real sensitive data in public issues, test fixtures, screenshots and commits. Do not enable hosted model APIs without a separate privacy/data-processing assessment.

See [SECURITY.md](SECURITY.md) for the trust model and deployment checklist. Run tests with `.venv/bin/python -m pytest -q`.

## Next milestones

1. Sandbox parsers and add full-coverage chunked extraction, OCR for PDF images, content-type verification and end-to-end upload-size enforcement.
2. Add a signed identity/HR connector and separation-of-duties approval with audit retention, encryption and RBAC.
3. Add asynchronous large-file quarantine, resilient upstream idempotency, Elasticsearch/OpenSearch export, trend dashboards and scheduled reports.
4. Calibrate model evaluation against synthetic/consented labeled cases; human-approved policy tuning only, with regression tests.

MIT licensed. Contributions should use synthetic data and include tests.
