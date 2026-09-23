# 飞书行为审计接入 / Feishu Behavior-Audit Integration

## 中文

本适配器对接飞书公开的**行为审计 API**，为 DLP 运营台增加飞书内导出、下载、分享、打印、复制和权限变更等行为的事后观察。它不会读取消息或云文档正文，不会修改飞书安全策略，也不能阻断飞书客户端里的操作。网关原有上传检查仍只保护主动经过网关的业务入口。

### 已核实的官方接口

| 用途 | 方法与路径 | 关键参数 / 权限 |
| --- | --- | --- |
| 自建应用获取租户令牌 | `POST /open-apis/auth/v3/tenant_access_token/internal` | `app_id`、`app_secret`；令牌最多有效两小时。 |
| 获取行为审计日志 | `GET /open-apis/admin/v1/audit_infos` | `oldest`、`latest`（秒级时间戳）、`page_size`、`page_token`；需 `admin:audit_info:readonly`。本项目指定 `user_id_type=open_id`，不额外申请员工 user ID 字段权限。 |

官方限制：每分钟最多 100 次；每次查询的起止时间跨度不超过 30 天；可查范围最多最近 180 天。官方功能介绍说明该能力处于内测，需要符合企业套餐条件并由企业侧申请。接口只返回一部分行为事件，不包含管理员日志、消息内容或云文档内容。

只读命令示例（需在已授权的私有租户环境执行）：

```bash
lark-cli api GET /open-apis/admin/v1/audit_infos \
  --params '{"oldest":1700000000,"latest":1700003600,"page_size":20,"user_id_type":"open_id"}'
```

本项目的同步程序使用相同的官方接口，但由专用自建应用获取租户令牌。它只保留文档/会话/邮件/妙记的选定导出、下载、分享与权限事件的唯一 ID、时间、事件名、操作人 ID 和第一个对象 ID；不会保存文件内容、标题、IP、完整事件 JSON 或访问令牌。事件进入独立的 `feishu_audit_events` 表，不会伪装成上传网关的 `allow/review/block` 决策。

### 启用方式与验收

1. 企业管理员确认审计功能可用，批准自建应用的 `admin:audit_info:readonly` 权限及相应数据范围。不要把个人 CLI 的登录态当作网关服务凭据。
2. 在远端私有环境配置 `DLP_DATABASE_URL`、`DLP_FEISHU_APP_ID`、`DLP_FEISHU_APP_SECRET`。不要提交或打印它们。
3. 在远端运行 `bin/dlp-feishu-audit-sync`，成功后可用管理员或只读运营身份查看 `GET /v1/admin/feishu/status`、`GET /v1/admin/feishu/events?limit=50` 和控制台“集成与测试实验室”。建议配置用户级 systemd timer 定期执行，但需要企业授权后才启用。
4. 首次同步默认查询最近一小时。后续从成功时间窗的持久化游标重叠两分钟继续；每轮最多 24 小时、50 页，并按 `unique_id` 去重。失败不推进游标。超过提供方 180 天保留期时需要人工核对缺口，程序不会静默跳过。

测试只使用虚构事件和临时数据库。当前公开演示环境未配置飞书应用，也未拉取真实事件。若希望接入飞书安全套件中具体的 DLP 告警、策略或阻断能力，需要该租户实际产品模块及获授权的接口文档；不能从行为审计接口推断出这些能力。

官方来源：[行为审计功能介绍](https://open.feishu.cn/document/server-docs/security_and_compliance-v1/audit_log/.md)、[获取行为审计日志数据](https://open.feishu.cn/document/server-docs/security_and_compliance-v1/audit_log/audit_data_get.md)、[事件枚举](https://open.feishu.cn/document/server-docs/security_and_compliance-v1/audit_log/appendix.md)、[获取租户访问令牌](https://open.feishu.cn/document/server-docs/authentication-management/access-token/tenant_access_token_internal.md)。核验日期：2026-09-23。

## English

This connector reads Feishu's public **behavior-audit API** to show retrospective export, download, sharing, printing, copying, and permission-change activity. It does not read message or document contents, manage Feishu security policies, or block actions inside Feishu. The gateway's upload enforcement still applies only to applications that explicitly send traffic through it.

The custom-app token endpoint is `POST /open-apis/auth/v3/tenant_access_token/internal` with `app_id` and `app_secret`. The audit endpoint is `GET /open-apis/admin/v1/audit_infos` with Unix-second `oldest`/`latest`, `page_size`, and `page_token`, requiring `admin:audit_info:readonly`. The connector requests `user_id_type=open_id` to avoid the extra employee-ID field scope. The published limit is 100 calls per minute, at most 30 days per query, and a 180-day retention window. Enterprise entitlement and approval are required.

Run `bin/dlp-feishu-audit-sync` only after configuring `DLP_DATABASE_URL`, `DLP_FEISHU_APP_ID`, and `DLP_FEISHU_APP_SECRET` in a private remote environment. The command keeps a durable completed-window cursor, overlaps subsequent windows by two minutes, and deduplicates on the provider's `unique_id`. It stores only minimal metadata in a separate table. A failed or incomplete window does not advance the cursor. The admin API and console expose sync status and recent events without labeling them as upload decisions.

The public demo is not connected to a Feishu tenant. Integrating proprietary Feishu Security Suite DLP alerts, policy management, or enforcement requires the exact authorized product API documentation. Official references are linked above and were checked on 2026-09-23.
