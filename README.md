# DLP Agent Gateway

[中文](#中文) · [English](#english)

## 中文

一个可运行的企业上传环节 DLP（数据防泄漏）参考实现。Go 网关在文件进入预配置的下游系统之前完成鉴权、解析编排、策略判定、审计和受控转发；独立 Python Worker 负责 PDF、DOCX 和图片 OCR 等复杂格式解析；可选的本地 Ollama 模型只提供上下文风险建议，不能放宽硬规则。

本项目用于作品展示、架构验证和授权测试，**不是可直接部署到生产环境的安全产品**。请只使用合成数据。

### 架构

```text
业务系统
   │ Bearer 身份 + 服务端允许的目标
   ▼
Go Gateway (:18080)
   ├─ 上传限制 / SHA-256 / 鉴权
   ├─ 内置硬规则 + 动态策略 + 人员状态
   ├─ 原子 JSON 审计存储
   ├─ 可选本地 Ollama 建议
   └─ 仅 allow 时转发同一份文件字节
           │
           └─ PDF / DOCX / 图片 ──► Python Analyzer (:19090)
                                      有界解析 / 可选 Tesseract OCR
```

核心路径按分层边界组织：`cmd/dlp-gateway` 负责进程生命周期，`internal/httpapi` 负责传输与认证，`internal/policy` 负责决策，`internal/analyzer` 负责编排解析服务，`internal/store` 隔离持久化实现。存储层可在不改变 HTTP 和策略契约的情况下替换为 PostgreSQL。

### 当前能力

| 模块 | 已实现 |
| --- | --- |
| 上传网关 | Go 标准库 HTTP 服务；Bearer 身份；8 MiB 文件上限；服务端目标白名单；安全响应头；超时与优雅关闭。 |
| 内容解析 | Go 直接处理 UTF-8 文本、代码、CSV、JSON；可选 Python Worker 处理文字型 PDF（最多 30 页）、DOCX 和 PNG/JPEG OCR。解析失败、空白、超限和不支持格式均进入 `review`。 |
| 风险决策 | 私钥、AWS Access Key、身份证号/手机号候选特征；动态字面关键词策略；离职/重点人员状态；可选本地 Ollama。模型只可提高审查强度。 |
| 运营闭环 | 内容判定与传输结果分开留痕；已认证但格式错误或目标无效的上传也记录；支持审计列表、策略/人员状态、临时例外、管理员事件、误报反馈和完整 1–90 天窗口统计。 |
| 控制台与探针 | `/console` 支持空库展示和合成文件检查；`/health` 是进程存活探针，`/ready` 会在已配置 Analyzer 但不可用时返回 503。 |
| 受控转发 | 只有调用 `/v1/forward/...`、判定为 `allow` 且目标预先配置时才转发；禁止任意 URL，禁止跟随重定向。 |

### 快速开始

需要 Go 1.23+。Python 3.11+ 仅在启用复杂文档解析 Worker 或运行 Python 回归测试时需要。

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

4. 打开 [http://127.0.0.1:18080/console](http://127.0.0.1:18080/console)，可直接输入客户端密钥并选择合成文件完成检查；输入管理员密钥后可查看刚生成的审计。也可以使用命令行：

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

Compose 启动 Go Gateway 和 Python Analyzer 两个非 root、只读根文件系统的服务。网关只映射到 `127.0.0.1:18080`，不会占用 `8080`；Analyzer 只在 Compose 内部网络暴露。审计数据保存在命名卷。

### API 工作流

1. 业务集成以对应身份密钥调用 `POST /v1/check/{destination}` 或 `POST /v1/forward/{destination}`，multipart 字段名为 `file`。
2. 返回 `allow`、`review` 或 `block`，以及原因代码、SHA-256、审计 ID 和独立的 `transfer_status`。`review` 与 `block` 永不转发；显式转发会区分 `pending`、`not_configured`、`failed` 和 `forwarded`。
3. 管理员通过 `/v1/admin/...` 管理策略、人员状态、例外、反馈、审计和报告。
4. 对可配置策略命中的审计，客户端可向 `POST /v1/exceptions` 提交 `audit_id` 和理由；批准只对同一身份、目标和完全相同的文件字节有效，且不能绕过秘密、人员、个人信息或模型故障规则。
5. 误报反馈只生成策略优化候选，不自动修改策略。

默认目标 `internal-demo` 和 `external-demo` 仅检查。要演示转发，在 `DLP_DESTINATIONS_JSON` 中配置固定 URL，例如 `{"internal-demo":{"kind":"internal","url":"http://127.0.0.1:9000/upload"}}`。非本机目标必须使用 HTTPS。下游非 2xx、重定向或超时均不会标记为成功，也不会把下游响应正文返回客户端。

### 本地模型

在本机启动 Ollama 并设置 `DLP_OLLAMA_MODEL=qwen2.5:7b` 后，Go 网关最多发送 2,000 个字符到环回模型服务，超时为 4 秒。文本仍可能敏感，因此模型服务必须保持本地且受控。已配置模型但服务不可用时，上传进入 `review`。模型输出只能提升审查强度，不能覆盖硬阻断或批准例外。

### 测试

```bash
go test -race ./...
go build ./cmd/dlp-gateway
.venv/bin/python -m pytest -q
```

GitHub Actions 同时运行 Go 测试、Go 构建和 Python 回归测试。测试数据全部为合成内容。

### 安全边界

- 这是主动接入的策略执行点，不是透明流量拦截器；绕过网关的上传也会绕过检查。
- 当前 Bearer 密钥与本地控制台只适合演示。生产环境需要 mTLS/SSO 或签名工作负载身份、RBAC、职责分离、密钥轮换、TLS 和集中式密钥管理。
- Python Worker 与网关分进程，但当前容器配置仍不是强沙箱。生产环境需要解析任务队列、CPU/内存/时间配额、恶意软件扫描、内容类型核验和反向代理级请求限制。
- 当前原子 JSON 存储提供 `0600` 权限、临时文件写入、文件及目录 `fsync` 和原子重命名，只适合单实例演示。它可留痕但不可防篡改，也没有事务数据库的并发、查询、备份、加密和高可用能力；生产环境应替换为 PostgreSQL 或其他受管数据库，并配置审计保留、导出与删除策略。
- 应用会记录通过身份认证后的上传判定与早期拒绝；无法识别身份的鉴权失败不写入应用 JSON，以免匿名请求造成同步磁盘写入型拒绝服务。生产环境应由限流的入口代理或 SIEM 记录这类访问安全日志。
- PDF 扫描页 OCR、XLSX/PPTX、嵌套压缩包、加密文档和复杂嵌入内容尚未覆盖，均应进入复核。格式提取不等于内容全覆盖。
- 正则会误报，模型会误判或受文档中指令干扰。任何策略优化都应人工批准并经过回归测试。
- 不要在公开 issue、日志、截图、提交或演示实例中使用真实企业文件、个人数据、密钥或客户数据。

更多信任边界见 [SECURITY.md](SECURITY.md)。

### 路线图

1. 将解析任务迁入带资源配额的隔离队列，增加 PDF 页面 OCR、XLSX/PPTX、文件类型校验和恶意软件扫描。
2. 用 PostgreSQL、OIDC/mTLS、RBAC、审计保留与加密替换演示组件。
3. 增加可靠的异步大文件隔离、幂等下游投递、OpenSearch/Elasticsearch 导出和周期报告。
4. 使用合成或明确授权的标注样本评估模型，建立人工审批的策略优化回归闭环。

MIT License。贡献内容须使用合成数据并附测试。

## English

A runnable reference implementation of an enterprise upload-time DLP enforcement point. The Go gateway performs authentication, parser orchestration, policy decisions, audit recording, and controlled forwarding before a file reaches a configured downstream system. A separate Python worker handles PDF, DOCX, and optional image OCR. An optional local Ollama model supplies context risk advice only and cannot relax hard rules.

This repository is intended for portfolio demonstration, architecture evaluation, and authorized testing. It is **not a production-ready security product**. Use synthetic data only.

### Architecture

```text
business application
   │ Bearer identity + server-allowlisted destination
   ▼
Go Gateway (:18080)
   ├─ upload bounds / SHA-256 / authentication
   ├─ hard guards + dynamic policies + personnel state
   ├─ atomic JSON audit store
   ├─ optional local Ollama advisory
   └─ forwards the exact bytes only after allow
           │
           └─ PDF / DOCX / image ──► Python Analyzer (:19090)
                                      bounded parsing / optional Tesseract OCR
```

The primary path is split by responsibility: `cmd/dlp-gateway` owns process lifecycle, `internal/httpapi` owns transport and authentication, `internal/policy` owns decisions, `internal/analyzer` orchestrates the parser service, and `internal/store` isolates persistence. The store can later be replaced with PostgreSQL without changing HTTP or policy contracts.

### Current capabilities

| Area | Implemented |
| --- | --- |
| Upload gateway | Go standard-library HTTP server; Bearer identity; 8 MiB file limit; server-side destination allowlist; security headers; timeouts and graceful shutdown. |
| Extraction | Go handles UTF-8 text, code, CSV, and JSON directly. The optional Python worker handles text-based PDF (up to 30 pages), DOCX, and PNG/JPEG OCR. Parse failures, blank input, over-limit input, and unsupported formats require `review`. |
| Decision | Private-key, AWS key, ID/phone candidate signals; dynamic literal policies; departing/privileged personnel state; optional local Ollama. Model output may escalate only. |
| Operations | Separate content-decision and transfer outcomes; authenticated malformed/unknown-target attempts are audited; audit list, policy/personnel controls, scoped exceptions, admin events, feedback, and full-window 1–90-day reports. |
| Console and probes | `/console` handles an empty store and can inspect a synthetic file; `/health` is liveness, while `/ready` returns 503 when a configured Analyzer is unavailable. |
| Controlled forwarding | Forwarding requires an explicit `/v1/forward/...` call, an `allow` decision, and a preconfigured receiver. Arbitrary URLs and redirects are rejected. |

### Quick start

Go 1.23+ is required. Python 3.11+ is needed only for the rich-document Analyzer or Python regression tests.

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

4. Open [http://127.0.0.1:18080/console](http://127.0.0.1:18080/console). You can enter a client key and inspect a synthetic file directly, then enter the admin key to view the resulting audit. Or use the command line:

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

Compose starts the Go Gateway and Python Analyzer as non-root services with read-only root filesystems. The gateway binds only to `127.0.0.1:18080` and does not use `8080`. The Analyzer is exposed only on the Compose network, and audit state lives in a named volume.

### API workflow

1. A business integration authenticates with its actor key and calls `POST /v1/check/{destination}` or `POST /v1/forward/{destination}` using multipart field `file`.
2. The result is `allow`, `review`, or `block` with reason codes, SHA-256, an audit ID, and a separate `transfer_status`. `review` and `block` never forward. Explicit forwarding distinguishes `pending`, `not_configured`, `failed`, and `forwarded`.
3. Administrators use `/v1/admin/...` to manage policies, personnel state, exceptions, feedback, audits, and reports.
4. For a configurable policy hit, a client may submit `audit_id` and a justification to `POST /v1/exceptions`. Approval is restricted to the same actor, destination, and exact file bytes; it cannot bypass secret, personnel, personal-data, or model-outage guards.
5. False-positive feedback creates policy-tuning candidates but never mutates policy automatically.

The default `internal-demo` and `external-demo` destinations are check-only. To demonstrate forwarding, configure a fixed URL in `DLP_DESTINATIONS_JSON`, for example `{"internal-demo":{"kind":"internal","url":"http://127.0.0.1:9000/upload"}}`. Non-loopback receivers require HTTPS. Downstream non-2xx responses, redirects, and timeouts are not marked successful, and the downstream response body is never returned.

### Local model

Run Ollama locally and set `DLP_OLLAMA_MODEL=qwen2.5:7b`. The Go gateway sends at most a 2,000-character excerpt to the loopback model endpoint with a four-second timeout. The excerpt can still be sensitive, so keep the model local and controlled. When a configured model is unavailable, the result requires `review`. Model output can only increase review strength; it cannot override hard blocks or grant exceptions.

### Tests

```bash
go test -race ./...
go build ./cmd/dlp-gateway
.venv/bin/python -m pytest -q
```

GitHub Actions runs Go tests, a Go build, and Python regression tests. All fixtures are synthetic.

### Security boundaries

- This is an explicitly integrated policy enforcement point, not a transparent network interceptor. Uploads that bypass it also bypass inspection.
- Bearer keys and the local console are demo controls. Production requires mTLS/SSO or signed workload identity, RBAC, separation of duties, key rotation, TLS, and centralized secret management.
- The Python worker is a separate process, but the current containers are not a strong parser sandbox. Production needs a queued parser boundary, CPU/memory/time quotas, malware scanning, content-type verification, and reverse-proxy request limits.
- The atomic JSON store uses `0600` permissions, a temporary file, file/directory `fsync`, and atomic rename. It records activity but is not tamper-proof, and lacks a transactional database's concurrency, query, backup, encryption, and HA properties. Replace it with PostgreSQL or another managed database and define audit retention, export, and deletion.
- The application audits upload decisions and early rejections after actor authentication. Unattributable authentication failures are not synchronously persisted to JSON because anonymous traffic could otherwise cause disk-write denial of service. Use a rate-limited ingress proxy or SIEM for those access-security logs in production.
- OCR for scanned PDF pages, XLSX/PPTX, nested archives, encrypted documents, and complex embedded content are not covered. Such inputs should require review. Format extraction is not proof of full content coverage.
- Regex signals can produce false positives; models can misclassify or follow document-borne instructions. Policy changes require human approval and regression tests.
- Never place real corporate documents, personal data, secrets, or customer-derived material in public issues, logs, screenshots, commits, or demo instances.

See [SECURITY.md](SECURITY.md) for additional trust boundaries.

### Roadmap

1. Move parsing into a resource-limited queue; add PDF page OCR, XLSX/PPTX, file-type verification, and malware scanning.
2. Replace demo controls with PostgreSQL, OIDC/mTLS, RBAC, encrypted audit retention, and separation of duties.
3. Add asynchronous large-file quarantine, idempotent downstream delivery, OpenSearch/Elasticsearch export, and scheduled reporting.
4. Evaluate the model with synthetic or explicitly consented labeled samples and require human-approved, regression-tested policy tuning.

MIT licensed. Contributions must use synthetic data and include tests.
