# DLP Agent Gateway

[中文](#中文) · [English](#english)

## 中文

一个可运行的企业上传环节 DLP（数据防泄漏）参考实现。Go 网关在文件进入预配置的下游系统之前完成鉴权、解析编排、策略判定、审计和受控转发；独立 Python Worker 负责 PDF、DOCX 和图片 OCR 等复杂格式解析；可选的本地 Ollama 模型只提供上下文风险建议，不能放宽硬规则。

本项目用于作品展示、架构验证和授权测试，**不是可直接部署到生产环境的安全产品**。请只使用合成数据。

### 架构

```text
业务系统
   │ Bearer 或已验证 mTLS 工作负载身份
   ▼
Go Gateway (:18080)
   ├─ 上传限制 / SHA-256 / 鉴权
   ├─ 内置硬规则 + 动态策略 + 人员状态
   ├─ PostgreSQL 审计 / 策略 / 审批存储
   ├─ OIDC + Casbin RBAC 运营身份
   ├─ 可选本地 Ollama 建议
   └─ 仅 allow 时向固定业务连接器转发同一份字节
           │
           └─ PDF / DOCX / 图片 ──► Python Analyzer (:19090)
                                      有界解析 / 可选 Tesseract OCR
```

核心路径按分层边界组织：`cmd/dlp-gateway` 负责进程生命周期，`internal/httpapi` 负责 HTTP 契约，`internal/access` 负责 OIDC、RBAC 与 mTLS，`internal/connector` 负责固定下游连接，`internal/policy` 负责决策，`internal/analyzer` 负责编排解析服务，`internal/store` 提供 PostgreSQL 和单机 JSON 两种仓储实现。React 运营台构建后嵌入 Go 二进制。

### 当前能力

| 模块 | 已实现 |
| --- | --- |
| 上传网关 | Go 标准库 HTTP 服务；Bearer 或 mTLS 业务身份；8 MiB 文件上限；服务端目标白名单；TLS、安全响应头、超时与优雅关闭。 |
| 内容解析 | Go 直接处理 UTF-8 文本、代码、CSV、JSON；可选 Python Worker 处理文字型 PDF（最多 30 页）、DOCX 和 PNG/JPEG OCR。解析失败、空白、超限和不支持格式均进入 `review`。 |
| 风险决策 | 私钥、AWS Access Key、身份证号/手机号候选特征；动态字面关键词策略；离职/重点人员状态；可选本地 Ollama。模型只可提高审查强度。 |
| 运营闭环 | PostgreSQL 自动迁移；内容判定与传输结果分开留痕；审计、事件处置、策略、人员、临时例外、误报反馈和完整 1–90 天统计。数据库状态读取失败时上传失败关闭。 |
| 运营台与身份 | React + TypeScript + Ant Design + TanStack Query + ECharts；OIDC 授权码 + PKCE；`viewer`、`operator`、`admin` 三档 Casbin RBAC；静态管理员密钥仅作本地兼容。 |
| 受控转发 | 只有调用 `/v1/forward/...`、判定为 `allow` 且目标预先配置时才转发；下游支持间接环境变量 Bearer 和 mTLS，禁止任意 URL与重定向。 |
| 探针 | `/health` 报告存储、OIDC、mTLS、Analyzer 和模型模式；`/ready` 同时检查数据库和已配置 Analyzer。 |

### 快速开始

需要 Go 1.23+。仓库已经包含构建后的运营台；只有修改前端时才需要 Node.js 22+。Python 3.11+ 仅在启用复杂文档解析 Worker 或运行 Python 回归测试时需要。

1. 准备配置。示例密钥不能直接使用，管理员和客户端密钥必须不同且至少 24 个字符：

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

`.env` 已被 Git 忽略，不要提交。Go 标准库不会自动读取 `.env`，请先把变量加载到当前终端：

```bash
set -a
source .env
set +a
```

2. 启动 Go 网关：

```bash
go run ./cmd/dlp-gateway
```

此时为 rules-only 模式：受支持的 UTF-8 文本可正常检查，PDF、DOCX、图片及未知格式会失败关闭为 `review`。

3. 可选：在另一个终端启动 Python Analyzer，再重启已配置 `DLP_ANALYZER_URL=http://127.0.0.1:19090` 的网关：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/uvicorn dlp_gateway.worker:app --host 127.0.0.1 --port 19090
```

图片 OCR 还需安装 `pip install -e ".[ocr]"` 和系统的 `tesseract`。缺少 OCR 依赖时图片进入 `review`。

4. 打开 [http://127.0.0.1:18080/console/](http://127.0.0.1:18080/console/)，通过标准账号登录页面进入运营台，再到“集成与测试”使用客户端身份验证合成文件。当前未配置 OIDC 的本地演示环境仅将密码字段适配到静态管理员凭据；页面不会保存密码，账号只用于为后续真实身份接口预留交互。也可以使用命令行：

```bash
curl -sS -H "Authorization: Bearer YOUR_CLIENT_KEY" \
  -F 'file=@synthetic.txt;type=text/plain' \
  http://127.0.0.1:18080/v1/check/external-demo
```

例如 `Call 13800138000` 会在外部目标触发 `review`；虚构的 `-----BEGIN PRIVATE KEY-----` 标记会触发 `block`。这些只是候选特征，不证明存在真实秘密或个人身份。

### Docker Compose

准备包含随机密钥的 `.env` 后运行：

```bash
docker compose up --build
```

Compose 启动 Go Gateway、Python Analyzer 和 PostgreSQL。网关只映射到 `127.0.0.1:18080`，不会占用 `8080`；Analyzer 与数据库只在 Compose 内部网络暴露，审计数据保存在 PostgreSQL 命名卷。首次启动会自动执行内嵌的版本化迁移。

### 企业身份与业务入口

- 运营人员：配置 `DLP_OIDC_*` 后，控制台使用 OIDC 授权码流程、PKCE、带签名的 HttpOnly 会话 Cookie。身份提供方角色映射为 `dlp-viewer`、`dlp-operator`、`dlp-admin`；名称可以通过环境变量调整。
- 上传工作负载：可继续使用每身份 Bearer 密钥，或配置网关 TLS、客户端 CA、`DLP_MTLS_ACTORS_JSON`。证书只在 TLS 验证链有效且 URI/DNS/Email/CN 明确映射时产生业务身份。
- 下游业务系统：`DLP_DESTINATIONS_JSON` 中只保存固定 HTTPS 地址和秘密所在的环境变量名；连接器支持固定 multipart 字段、私有 CA、Bearer 或客户端证书，不接受请求方提供 URL。
- 真正连接 OA、GitLab 或其他业务系统前，需要得到该系统所有者授权，并在私有环境配置 URL、证书或服务令牌。仓库和示例不包含真实接口或凭据。

### API 工作流

1. 业务集成以对应身份密钥调用 `POST /v1/check/{destination}` 或 `POST /v1/forward/{destination}`，multipart 字段名为 `file`。
2. 返回 `allow`、`review` 或 `block`，以及原因代码、SHA-256、审计 ID 和独立的 `transfer_status`。`review` 与 `block` 永不转发；显式转发会区分 `pending`、`not_configured`、`failed` 和 `forwarded`。
3. 管理员通过 `/v1/admin/...` 管理策略、人员状态、例外、反馈、审计和报告。
4. 对可配置策略命中的审计，客户端可向 `POST /v1/exceptions` 提交 `audit_id` 和理由；批准只对同一身份、目标和完全相同的文件字节有效，且不能绕过秘密、人员、个人信息或模型故障规则。
5. 误报反馈只生成策略优化候选，不自动修改策略。

默认目标 `internal-demo` 和 `external-demo` 仅检查。要接入获授权的业务上传接口，在私有配置中增加固定 URL，例如 `{"business-upload":{"kind":"internal","url":"https://business.example/upload","credential_env":"BUSINESS_UPLOAD_TOKEN","upload_field":"file"}}`。非本机目标必须使用 HTTPS。下游非 2xx、重定向或超时均不会标记为成功，也不会把下游响应正文返回客户端。

### 本地模型

在本机启动 Ollama 并设置 `DLP_OLLAMA_MODEL=qwen2.5:7b` 后，Go 网关最多发送 2,000 个字符到环回模型服务，超时为 4 秒。文本仍可能敏感，因此模型服务必须保持本地且受控。已配置模型但服务不可用时，上传进入 `review`。模型输出只能提升审查强度，不能覆盖硬阻断或批准例外。

### 测试

```bash
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run build
go test -race ./...
go build ./cmd/dlp-gateway
.venv/bin/python -m pytest -q
```

GitHub Actions 同时构建前端、运行 Go race 测试（包含临时 PostgreSQL 服务）、Go 构建、Python 回归测试和两个容器构建。测试数据全部为合成内容。

### 安全边界

- 这是主动接入的策略执行点，不是透明流量拦截器；绕过网关的上传也会绕过检查。
- OIDC、mTLS 与 RBAC 已提供集成能力，但是否符合生产要求仍取决于身份提供方、PKI、入口代理、证书轮换、会话策略、TLS 终止和职责分离配置。
- Python Worker 与网关分进程，但当前容器配置仍不是强沙箱。生产环境需要解析任务队列、CPU/内存/时间配额、恶意软件扫描、内容类型核验和反向代理级请求限制。
- Docker Compose 已使用 PostgreSQL；直接运行二进制且未设置 `DLP_DATABASE_URL` 时仍回退到单实例原子 JSON。生产部署还必须配置 PostgreSQL TLS、备份恢复、加密、保留与删除、不可变导出和高可用，而不是把“用了 PostgreSQL”等同于审计合规。
- 应用会记录通过身份认证后的上传判定与早期拒绝；无法识别身份的鉴权失败不写入应用 JSON，以免匿名请求造成同步磁盘写入型拒绝服务。生产环境应由限流的入口代理或 SIEM 记录这类访问安全日志。
- PDF 扫描页 OCR、XLSX/PPTX、嵌套压缩包、加密文档和复杂嵌入内容尚未覆盖，均应进入复核。格式提取不等于内容全覆盖。
- 正则会误报，模型会误判或受文档中指令干扰。任何策略优化都应人工批准并经过回归测试。
- 不要在公开 issue、日志、截图、提交或演示实例中使用真实企业文件、个人数据、密钥或客户数据。

更多信任边界见 [SECURITY.md](SECURITY.md)。

### 路线图

1. 将解析任务迁入带资源配额的隔离队列，增加 PDF 页面 OCR、XLSX/PPTX、文件类型校验和恶意软件扫描。
2. 增加可靠的异步大文件隔离、幂等下游投递、OpenSearch/Elasticsearch 导出和可计划交付的报告。
3. 完成 PostgreSQL 备份恢复、保留/删除、不可变导出，以及生产 PKI/OIDC 部署指南和安全基线。
4. 使用合成或明确授权的标注样本评估模型，建立人工审批的策略优化回归闭环。

MIT License。贡献内容须使用合成数据并附测试。主要依赖许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## English

A runnable reference implementation of an enterprise upload-time DLP enforcement point. The Go gateway performs authentication, parser orchestration, policy decisions, audit recording, and controlled forwarding before a file reaches a configured downstream system. A separate Python worker handles PDF, DOCX, and optional image OCR. An optional local Ollama model supplies context risk advice only and cannot relax hard rules.

This repository is intended for portfolio demonstration, architecture evaluation, and authorized testing. It is **not a production-ready security product**. Use synthetic data only.

### Architecture

```text
business application
   │ Bearer or verified mTLS workload identity
   ▼
Go Gateway (:18080)
   ├─ upload bounds / SHA-256 / authentication
   ├─ hard guards + dynamic policies + personnel state
   ├─ PostgreSQL audit / policy / approval store
   ├─ OIDC + Casbin RBAC for operators
   ├─ optional local Ollama advisory
   └─ forwards exact bytes through a fixed connector only after allow
           │
           └─ PDF / DOCX / image ──► Python Analyzer (:19090)
                                      bounded parsing / optional Tesseract OCR
```

The primary path is split by responsibility: `cmd/dlp-gateway` owns process lifecycle, `internal/httpapi` owns HTTP contracts, `internal/access` owns OIDC, RBAC, and mTLS, `internal/connector` owns fixed downstream integration, `internal/policy` owns decisions, `internal/analyzer` orchestrates parsing, and `internal/store` provides PostgreSQL and standalone JSON repositories. The built React console is embedded in the Go binary.

### Current capabilities

| Area | Implemented |
| --- | --- |
| Upload gateway | Go standard-library HTTP server; Bearer or mTLS workload identity; 8 MiB limit; destination allowlist; TLS, security headers, timeouts, and graceful shutdown. |
| Extraction | Go handles UTF-8 text, code, CSV, and JSON directly. The optional Python worker handles text-based PDF (up to 30 pages), DOCX, and PNG/JPEG OCR. Parse failures, blank input, over-limit input, and unsupported formats require `review`. |
| Decision | Private-key, AWS key, ID/phone candidate signals; dynamic literal policies; departing/privileged personnel state; optional local Ollama. Model output may escalate only. |
| Operations | Automatic PostgreSQL migrations; separate content and transfer outcomes; audit, incident triage, policies, people risk, scoped exceptions, feedback, and full-window 1–90-day reports. Policy-state read failures fail closed. |
| Console and identity | React + TypeScript + Ant Design + TanStack Query + ECharts; OIDC authorization code + PKCE; Casbin `viewer`, `operator`, and `admin` roles; a static admin key remains only for local compatibility. |
| Controlled forwarding | `/v1/forward/...` requires `allow` and a preconfigured target. Connectors support indirect environment-variable Bearer credentials and mTLS. Arbitrary URLs and redirects are rejected. |
| Probes | `/health` reports storage, OIDC, mTLS, Analyzer, and model modes. `/ready` checks the database and the configured Analyzer. |

### Quick start

Go 1.23+ is required. Built console assets are committed; Node.js 22+ is needed only when changing the frontend. Python 3.11+ is needed only for the rich-document Analyzer or Python regression tests.

1. Prepare configuration. Never use the placeholder keys; the admin and client keys must be distinct and at least 24 characters:

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

`.env` is ignored by Git. The Go standard library does not load it automatically, so export it into the current shell:

```bash
set -a
source .env
set +a
```

2. Start the Go gateway:

```bash
go run ./cmd/dlp-gateway
```

This is rules-only mode: supported UTF-8 text is inspected, while PDF, DOCX, images, and unknown formats fail closed to `review`.

3. Optional: start the Python Analyzer in another terminal, then restart the gateway with `DLP_ANALYZER_URL=http://127.0.0.1:19090` configured:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/uvicorn dlp_gateway.worker:app --host 127.0.0.1 --port 19090
```

Image OCR additionally requires `pip install -e ".[ocr]"` and the system `tesseract` binary. Images require `review` when OCR is unavailable.

4. Open [http://127.0.0.1:18080/console/](http://127.0.0.1:18080/console/) and enter through the standard account sign-in page, then use Integration & Test Lab with a client identity and a synthetic file. In a local demo without OIDC, only the password field is adapted to the static administrator credential; the page never stores the password, and the account field reserves the interaction contract for a future identity provider. Or use the command line:

```bash
curl -sS -H "Authorization: Bearer YOUR_CLIENT_KEY" \
  -F 'file=@synthetic.txt;type=text/plain' \
  http://127.0.0.1:18080/v1/check/external-demo
```

For example, `Call 13800138000` triggers `review` at an external destination; an invented `-----BEGIN PRIVATE KEY-----` marker triggers `block`. These are candidate signals, not proof of a real secret or identity.

### Docker Compose

After preparing `.env` with random keys, run:

```bash
docker compose up --build
```

Compose starts the Go Gateway, Python Analyzer, and PostgreSQL. The gateway binds only to `127.0.0.1:18080` and does not use `8080`. The Analyzer and database remain on the Compose network, audit state lives in a PostgreSQL volume, and embedded versioned migrations run on startup.

### Enterprise identity and business entry

- Operators: configure `DLP_OIDC_*` to use authorization code flow, PKCE, and a signed HttpOnly session cookie. Provider roles map to `dlp-viewer`, `dlp-operator`, and `dlp-admin` by default.
- Upload workloads: use per-identity Bearer keys, or configure gateway TLS, a client CA, and `DLP_MTLS_ACTORS_JSON`. A certificate creates an actor only when its verification chain is valid and an URI/DNS/Email/CN identity is explicitly mapped.
- Downstream systems: `DLP_DESTINATIONS_JSON` stores a fixed HTTPS address and the name of the environment variable that holds a secret. A connector can set a fixed multipart field, private CA, Bearer credential, or client certificate, and never accepts a caller-provided URL.
- Connecting OA, GitLab, or another real system requires that system owner's authorization and private URL/certificate/service-token configuration. This public repository contains no real endpoint or credential.

### API workflow

1. A business integration authenticates with its actor key and calls `POST /v1/check/{destination}` or `POST /v1/forward/{destination}` using multipart field `file`.
2. The result is `allow`, `review`, or `block` with reason codes, SHA-256, an audit ID, and a separate `transfer_status`. `review` and `block` never forward. Explicit forwarding distinguishes `pending`, `not_configured`, `failed`, and `forwarded`.
3. Administrators use `/v1/admin/...` to manage policies, personnel state, exceptions, feedback, audits, and reports.
4. For a configurable policy hit, a client may submit `audit_id` and a justification to `POST /v1/exceptions`. Approval is restricted to the same actor, destination, and exact file bytes; it cannot bypass secret, personnel, personal-data, or model-outage guards.
5. False-positive feedback creates policy-tuning candidates but never mutates policy automatically.

The default `internal-demo` and `external-demo` destinations are check-only. To connect an authorized business upload endpoint, add a fixed private configuration such as `{"business-upload":{"kind":"internal","url":"https://business.example/upload","credential_env":"BUSINESS_UPLOAD_TOKEN","upload_field":"file"}}`. Non-loopback receivers require HTTPS. Downstream non-2xx responses, redirects, or timeouts are not marked successful, and downstream response bodies are never returned.

### Local model

Run Ollama locally and set `DLP_OLLAMA_MODEL=qwen2.5:7b`. The Go gateway sends at most a 2,000-character excerpt to the loopback model endpoint with a four-second timeout. The excerpt can still be sensitive, so keep the model local and controlled. When a configured model is unavailable, the result requires `review`. Model output can only increase review strength; it cannot override hard blocks or grant exceptions.

### Tests

```bash
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run build
go test -race ./...
go build ./cmd/dlp-gateway
.venv/bin/python -m pytest -q
```

GitHub Actions builds the frontend, runs Go race tests with an ephemeral PostgreSQL service, builds Go, runs Python regressions, and builds both containers. Every fixture is synthetic.

### Security boundaries

- This is an explicitly integrated policy enforcement point, not a transparent network interceptor. Uploads that bypass it also bypass inspection.
- OIDC, mTLS, and RBAC integration is implemented, but production fitness still depends on identity-provider, PKI, ingress, certificate rotation, session, TLS termination, and separation-of-duties configuration.
- The Python worker is a separate process, but the current containers are not a strong parser sandbox. Production needs a queued parser boundary, CPU/memory/time quotas, malware scanning, content-type verification, and reverse-proxy request limits.
- Docker Compose uses PostgreSQL. A directly started binary without `DLP_DATABASE_URL` still falls back to atomic JSON for a standalone demo. Production also requires PostgreSQL TLS, backup recovery, encryption, retention/deletion, immutable export, and HA; using PostgreSQL alone does not make the audit trail compliant.
- The application audits upload decisions and early rejections after actor authentication. Unattributable authentication failures are not synchronously persisted to JSON because anonymous traffic could otherwise cause disk-write denial of service. Use a rate-limited ingress proxy or SIEM for those access-security logs in production.
- OCR for scanned PDF pages, XLSX/PPTX, nested archives, encrypted documents, and complex embedded content are not covered. Such inputs should require review. Format extraction is not proof of full content coverage.
- Regex signals can produce false positives; models can misclassify or follow document-borne instructions. Policy changes require human approval and regression tests.
- Never place real corporate documents, personal data, secrets, or customer-derived material in public issues, logs, screenshots, commits, or demo instances.

See [SECURITY.md](SECURITY.md) for additional trust boundaries.

### Roadmap

1. Move parsing into a resource-limited queue; add PDF page OCR, XLSX/PPTX, file-type verification, and malware scanning.
2. Add reliable asynchronous large-file quarantine, idempotent downstream delivery, OpenSearch/Elasticsearch export, and schedulable report delivery.
3. Add PostgreSQL backup/restore, retention/deletion, immutable export, plus production PKI/OIDC deployment guidance and security baselines.
4. Evaluate the model with synthetic or explicitly consented labeled samples and require human-approved, regression-tested policy tuning.

MIT licensed. Contributions must use synthetic data and include tests. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for primary dependency licenses.
