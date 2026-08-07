# OneIssuer 第四阶段开发计划：Token 生命周期与安全退出

> 状态：Approved；P4-00 已接受，实现已完成，发布门禁与 Conformance 待完成
> 计划日期：2026-08-02
> 对应总体方案：[`go-backend-design.md`](./go-backend-design.md) 的“阶段四：生命周期与安全”
> 冻结输入：[`phase-3-development-plan.md`](./phase-3-development-plan.md) 第 25 节与
> [`phase-3-release-notes.md`](./phase-3-release-notes.md)
> 前置版本：`v0.1.0-dev.3`，生产 Schema 11
> 建议版本标识：`v0.1.0-dev.4`
> 建议 Schema：11 → 14；具体迁移编号在 ADR 评审后冻结
> 适用范围：单 Issuer、非多租户、自托管部署
> 初步工作量：单人约 24–34 个有效开发日；在生命周期/并发 Spike 后重新估算

## 1. 阶段定位

第三阶段已经交付并验证最小 OIDC Authorization Code Flow，但 Token 生命周期目前只靠短
TTL 和 UserInfo 在线状态检查：Client 不能刷新，用户不能撤销 Grant，RP 不能发起标准安全
退出，也没有 Revocation/Introspection Endpoint。

第四阶段只沿一条主线扩展：**让离线授权、Token 轮换、撤销、状态查询与浏览器退出共享
同一个 PostgreSQL 权威状态机**。

```text
Authorization Code + offline_access + explicit Consent
→ initial Access/ID/Refresh Token
→ rotating Refresh Token family
→ replay detection and family revocation
→ RFC 7009 Revocation / restricted RFC 7662 Introspection
→ RP-Initiated Logout and current-user Grant revocation
```

本阶段不是“把所有 OAuth 端点打开”。Access Token Audience 继续固定为 OneIssuer
UserInfo；不引入 Resource Server Registry、通用业务 API 授权、Front-/Back-Channel Logout
或真实 React 管理台。所有新增 Metadata 必须与已上线的路由、存储和负向语义同步出现，
不得先返回占位成功。

## 2. 阶段演示

完成后，开发者应能在升级后的持久化环境中执行以下演示：

```text
从 schema 11 原地升级，旧 User/Client/Grant/Access authority 保持有效
→ Public Client A 请求 openid profile offline_access
→ 首次 offline_access 强制 Consent
→ Code 交换一次性返回 ID + Access + Refresh Token
→ A 使用 Refresh Token，旧值被消费并得到新 Access + 新 Refresh Token
→ 重启 OneIssuer，最新一代仍可刷新，旧代仍不可用
→ 并发提交同一 Refresh Token：最多一个响应成功，随后全 family 被复用检测撤销
→ UserInfo 和 Introspection 拒绝该 family 的 Access Token
→ Confidential Client B 只能 introspect/revoke 自己的 Token
→ 未知、过期、跨 Client Revocation 对外均为同一 200 语义
→ 用户在 Account API 撤销 B 的 Grant，B 的 family/Access 立即失效
→ B 发起 RP-Initiated Logout，OneIssuer 展示确认页并只跳回精确登记的 Logout URI
→ 日志、Audit、Metrics、错误和镜像中没有任何 clear Token/Secret/State
```

示例 RP 必须把 Refresh Token 保存在服务器端受限 Session 中，原子替换旧值，不得写入浏览器
Local Storage、URL、日志、命令行或提交到仓库。示例也必须把 `invalid_grant` 视为重新授权，
不能自动循环重试旧 Token。

## 3. 目标与非目标

### 3.1 必须完成

1. 开放 `offline_access`，并把首次/扩展 Consent、`prompt=none` 与 Grant 复用语义冻结；
2. 256-bit 不透明 Refresh Token、摘要存储、family、强制 rotation 与 reuse detection；
3. Token Endpoint 的 `refresh_token` Grant，Public/Confidential Client 都保持现有认证方法；
4. RFC 6749 §6 Scope：request Scope 只控制本次 Access Token 且不得扩大；replacement Refresh
   Token 必须保持 presented Refresh 的相同 family Scope；
5. RFC 7009 Revocation Endpoint，Access 单体撤销与 Refresh family 撤销；
6. RFC 7662 Introspection Endpoint，首版只允许 Confidential owning Client；
7. RP-Initiated Logout 1.0：authority-read-only GET/POST Request、独立 Hosted CSRF confirm、
   精确 Logout URI；
8. 当前用户 Grant 列表与撤销 API，以及 Grant 再授权恢复规则；
9. Session、Grant、User/Client 状态与 Token family/Access metadata 的原子级联矩阵；
10. Access metadata 显式撤销状态、refresh issuance source 和必要的 Session/family 关联；
11. Refresh/Logout 配置边界、保留/清理、容量和升级/恢复 Runbook；
12. 固定 Audit、低基数 Metrics、协议端点限流与隐私扫描；
13. 单元、真实 PostgreSQL、并发/死锁、故障注入、Fuzz、浏览器和适用 Conformance 测试；
14. 示例 Client、Compose `phase-4-smoke`、OpenAPI/接入/运维/排障与 Release Notes 模板。

### 3.2 明确不做

- Front-Channel Logout、Back-Channel Logout、Session Management iframe 或 `sid` Claim；
- Resource Server/Audience Registry、Resource Indicators、多资源 Access Token 或业务权限模型；
- Public Client Introspection、独立 introspection credential 或新的 Client 类型；
- Client Credentials、Device Authorization、ROPC、Token Exchange、Implicit/Hybrid；
- Dynamic Client Registration、PAR、JAR、JARM、Request Object/URI；
- DPoP、mTLS、private-key JWT、`client_secret_post` 或 sender-constrained Token；
- Refresh Token grace window、静态 Refresh Token 或跨 family Token 迁移；
- Pairwise Subject、Organization、Tenant、Realm 或隐藏的多租户列；
- MFA、Passkey、邮箱验证、密码找回、账号合并或上游身份源；
- 自动/热 Key 轮换、HSM/KMS/Vault 或远程签名事务；
- 把 `web/` Mock 接成真实身份/管理状态；真实 Admin/Account UI 仍属于下一阶段；
- OpenID Foundation 认证、FAPI 或生产就绪声明。

## 4. 第三阶段冻结边界

第四阶段不得为了“简化 Refresh”改变以下已验收契约：

- `ONEISSUER_ISSUER` 是唯一 Canonical Issuer，不能从 Host/Forwarded Header 推导；
- 只支持 Authorization Code + `response_mode=query`，所有 Client 强制 S256；
- Redirect URI、Logout URI 都沿用结构校验后逐字节精确匹配，不做通配/前缀/归一化；
- Public=`none`、Confidential=`client_secret_basic`，Secret 只存摘要并统一失败；
- User `sub`、身份规范化、密码、浏览器 Session、CSRF、recent-auth 语义保持兼容；
- Authorization transaction、Consent、Code issue 与 Code exchange 的数据库原子边界不拆散；
- RS256、`kid`、ID/Access Claim、UserInfo Audience 和 Scope→Claim 映射保持兼容；
- Access Token 仍只面向 OneIssuer UserInfo，不因 Introspection 变成通用 API Token；
- HTTP 错误不泄露 Client/Token 是否存在，Redirect 未验证前绝不外跳；
- Audit 只允许固定枚举/字段名，Metrics 不使用 User/Client/Token 等高基数值；
- `serve` 不迁移数据库；生产迁移不可变且必须显式执行；
- React Mock 不是身份、Consent、Session、Token 或设置的权威来源。

Schema 11 的硬化控制——认证限流、每表单五次尝试、Argon2 总预算、250 行 Cleanup 批次、
Audit 失败指标、NUL 拒绝、容器 Digest 固定——全部是第四阶段基线，不重复列为新功能。

## 5. 开工前设计门禁

### 5.1 必须批准的文档

实施 PR 开始前必须完成：

1. 接受 [`adr/0003-phase-four-token-lifecycle.md`](./adr/0003-phase-four-token-lifecycle.md)；
2. 接受 [`phase-4-threat-model.md`](./phase-4-threat-model.md) 并为残余风险指定 owner；
3. 提交 dependency/concurrency Spike，验证 Fosite 可复用边界、锁顺序、Session rotation
   lineage、Logout Hint 时间/Key policy 和事务失败语义；
4. 冻结迁移 12–14 的表、约束、索引、保留与 schema-11 升级样本；
5. 冻结 Discovery/Endpoint/错误/Introspection 响应快照；
6. 冻结示例 RP 的 Refresh 保存/替换/重新授权安全边界；
7. 记录适用 Conformance 模块和非适用项，不能把计划当作认证证据。

### 5.2 本计划的默认提案

| 决策 | 默认提案 |
| --- | --- |
| Refresh rolling TTL | 30 天 |
| Family absolute TTL | 90 天；replacement 不得越过 |
| Rotation | 每次成功都强制，旧 Token 立即 consumed |
| Reuse | 无 grace；撤销整个 family 与其 live Access metadata |
| Refresh response | Access + replacement Refresh；不返回新 ID Token |
| Scope | 省略则 Access 取当前有效 family Scope；显式值只缩小本次 Access；replacement Refresh Scope 与 presented 值相同 |
| Revocation | Access 仅单体；Refresh 撤销 whole family |
| Introspection caller | 仅 Active Confidential owning Client + Basic |
| Inactive response | 精确 `{"active":false}` |
| RP logout | end-session GET/POST 只建事务；clean confirm GET 后，cookie-only confirm POST + Session + transaction-bound CSRF 才变更 |
| Post logout redirect | 必须有可验证 `id_token_hint` 且 URI 精确登记 |
| Session effect | 用户/管理员显式 revoke/logout 级联；被动 expiry 不级联；登录防固定 rotation 继承稳定 binding |
| Signing | 保持启动加载/重启轮换；不热更新 |

任何改动必须先修改已接受的 ADR、Threat Model、协议矩阵和测试清单，而不是在实现中静默
偏离。

### 5.3 规范基线

- OpenID Connect Core 1.0（`offline_access` 与 Refresh ID Token 规则）；
- OpenID Connect RP-Initiated Logout 1.0；
- RFC 6749（Refresh Token Grant 与 Scope）；
- RFC 7009（Token Revocation）；
- RFC 7662（Token Introspection）；
- RFC 8414（OAuth Authorization Server Metadata 扩展字段）；
- RFC 9700（OAuth 2.0 Security Best Current Practice）；
- RFC 7636（S256 PKCE）、RFC 9068（JWT Access Token）、RFC 8725（JWT BCP）；
- 当前固定版本的 Fosite 与 go-jose 文档、变更日志和漏洞记录。

## 6. 推荐模块与依赖边界

```text
internal/
├── oidc/                    # Refresh/Revoke/Introspect/Logout wire parser + errors
├── token/                   # family、rotation、revoke、introspection domain policy
├── logout/                  # 短期退出事务与确认用例；不拥有 Session SQL
├── consent/                 # Grant 评估、列出、撤销、重新激活规则
├── session/                 # 现有浏览器 authority；显式 revoke 调用原子级联边界
├── authorization/           # Code issue；只增加 session/offline 所需绑定
├── client/                  # 复用类型、Secret、Scope 与精确 Logout URI
├── audit/                   # 扩展固定 phase-four 事件/target
├── httpserver/              # 固定路由、大小/类型/安全头/Hosted logout 页面
└── storage/postgres/        # family/Grant/Session/Access 跨表事务与 cleanup
```

边界原则：

- `oidc` 只解析标准参数和形成固定 wire response，不读 Token/Grant/Session SQL；
- `token` 不接收 clear Client Secret，也不把 clear Refresh Token 交给 Repository；
- clear Refresh Token 在 Service 中生成，Repository 只接收 hash/ID/时间/Scope，成功 commit 后
  才允许 Handler 输出 clear value；
- `logout` 只让浏览器通过 dedicated HttpOnly cookie 携带 server-issued opaque transaction；
  Client/URI 来自已验证存储，opaque State 只作为绑定到该 verified pair 的返回值；query/hidden
  form 不形成第二条 transaction channel；
- `consent` 的撤销操作只接受当前 Principal 与已公开的 protocol `client_id`，Repository 再按
  唯一 `(user, client)` 关系解析内部 Grant；浏览器不能声明 User ID 或内部 Grant UUID；
- 跨 Session/Grant/family/Access 的一致性通过明确的 PostgreSQL Repository 方法实现，Handler
  不顺序调用多个 Service 制造半状态；
- Fosite/go-jose 类型仍只存在于协议/Token/Key adapter，不进入 identity/client/session domain；
- 不创建“万能 lifecycle manager”绕过已有服务；每个用例必须有明确 input、authority 和事务 owner。

## 7. 协议与 API 支持矩阵

### 7.1 新增或扩展端点

| 方法 | 路径 | 用途 | 鉴权/缓存 |
| --- | --- | --- | --- |
| `POST` | `/oauth2/token` | 扩展 `refresh_token` Grant | Client method；`no-store` |
| `POST` | `/oauth2/revoke` | RFC 7009 Access/Refresh 撤销 | owning Client；`no-store` |
| `POST` | `/oauth2/introspect` | RFC 7662 Token 状态 | Confidential Basic；`no-store` |
| `GET` | `/oauth2/logout` | 接受 query RP logout request；校验并建立确认上下文 | Browser；`no-store` |
| `POST` | `/oauth2/logout` | 接受 form RP logout request；校验并建立确认上下文 | Browser；`no-store` |
| `GET` | `/oauth2/logout/confirm` | 从短期 HttpOnly cookie 恢复/绑定上下文并显示确认 | Browser Session；`no-store` |
| `POST` | `/oauth2/logout/confirm` | Hosted confirm/cancel 并原子退出 | Browser Session + CSRF；`no-store` |
| `POST` | `/logout` | 保留现有 same-origin local logout，并改走相同 Session-binding cascade | Browser Session + CSRF；`no-store` |
| `GET` | `/api/v1/me/grants` | 当前用户 Grant 列表 | Session；`no-store` |
| `POST` | `/api/v1/me/grants/revoke` | 按严格 JSON body 中的 public `client_id` 撤销自己的 Grant | Session + CSRF；`no-store` |

旧 Discovery/JWKS/Authorize/UserInfo、Session 与 Admin API 保持存在。标准 OAuth/OIDC 端点继续
不重复放进管理 OpenAPI；新增 current-user Grant API 必须更新 `api/openapi.yaml`。

### 7.2 能力矩阵

| 能力 | 第四阶段提案 | 备注 |
| --- | --- | --- |
| Authorization Code | 保持 | 唯一授权入口 |
| Refresh Token Grant | 新增 | 必须 rotation/reuse detection |
| `offline_access` | 新增 | Code + live explicit Grant |
| Revocation | 新增 | Access single / Refresh family |
| Introspection | 新增受限 profile | Confidential owning Client only |
| RP-Initiated Logout | 新增 | Confirmed local OP logout |
| Front-/Back-Channel Logout | 不支持 | Discovery 不声明 |
| ID Token on refresh | 不返回 | 初始 Code exchange 仍返回 |
| General API audience | 不支持 | Access `aud` 仍是 UserInfo |
| Public Introspection | 不支持 | `client_id` 不是 credential |
| Pairwise Subject / `sid` | 不支持 | 保持 public `sub` profile |

## 8. Discovery 准确性

完成全部实现后，Provider Metadata 在第三阶段字段上增加：

```json
{
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "revocation_endpoint": "<issuer>/oauth2/revoke",
  "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
  "introspection_endpoint": "<issuer>/oauth2/introspect",
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
  "end_session_endpoint": "<issuer>/oauth2/logout"
}
```

数组顺序固定并做 snapshot。不能声明 `frontchannel_logout_supported`、
`backchannel_logout_supported`、`sid`、新的签名算法、Resource Indicator 或未实现 Client auth。
Metadata route 与真实路由、认证方法、Token Response 和错误矩阵必须做 live cross-test。

## 9. `offline_access` 与 Consent

### 9.1 Authorize 规则

- `offline_access` 只允许出现在包含 `openid` 的 Code Flow；
- 请求仍必须是 Client 登记 Scope 的子集；
- 首次申请或在旧 Grant 上新增 `offline_access` 时必须进入 Consent；
- `prompt=none` 且没有覆盖 Grant 时返回 `consent_required`，不静默签发；
- `prompt=consent` 始终重显当前完整请求；
- 覆盖 Grant 可按现有规则复用，不要求每次登录都重复确认；
- Consent 页面明确说明长期离线访问，不能只显示成普通 Profile Claim；
- 用户拒绝不会删除已有 Grant，也不会创建 family。

### 9.2 Grant 状态

`consent_grants` 增加 `revoked_at` 和正数 `version`，Scope 约束扩展到最多四个固定值。

- active Grant：`revoked_at IS NULL`；
- revoke：保留行/Scope 作为安全证据，但所有 authority read 立即失败；
- 后续 interactive Consent：清除 revoked，Scope 从本次明确同意集合重建，不与已撤销旧集合 union；
- Grant 每次 authority 变更都递增 `version`；Code 保存签发时版本，exchange 必须精确匹配，
  因此 revoke 后再 Consent 也不能复活此前签发但尚未消费的 Code；
- active Grant 的普通扩展继续使用 union；
- Client 缩小 Scope 后，所有读取仍取当前 Client 交集；
- `offline_access` 从 Client policy 移除时，原子撤销该 Client 的所有 family 与 linked live
  Access；以后重新加入只允许创建新 family，不能复活旧值，即使历史 Grant 仍含该 Scope。

## 10. Refresh Token 模型

### 10.1 Clear value 与 digest

建议格式：

```text
r1_<43-char base64url of 32 random bytes>
```

- 严格长度、prefix、base64url grammar；
- digest domain：`oneissuer:refresh-token:v1:<clear>`；
- clear value 只存在于 Token Service 内存与成功 JSON response；
- Repository、SQL、Audit、Metrics、日志、error、测试快照只使用内部 ID/hash-safe state；
- Access/Refresh/Code/Session prefix 与 digest domain 全部不同，禁止 type confusion。

### 10.2 Family 与 generation

每个初始 offline Code exchange 创建一个 family：

- 绑定 User、Client、Consent Grant、nullable origin Authorization Code/Session，以及稳定的
  Session binding；origin 行的后续清理不改变 authority；
- 保存原始 Refresh authority Scope、created、absolute expiry、revoked time/reason；
- family 下 Token generation 从 0 单调递增并唯一；
- 每个 Refresh generation 继承完全相同的 family Scope，只保存 issued/expiry/consumed time；
- refresh request 的 optional `scope` 只选择本次 Access Token Scope：省略时使用 family、Grant、
  当前 Client policy 的有效交集；显式值必须包含 `openid` 且只能是该交集的子集；
- Access Scope narrowing 不是 sticky，不能缩小 replacement Refresh authority。RFC 6749 §6 要求
  replacement Refresh Scope 与 presented Refresh 相同；若要永久缩权，使用 Grant/Client policy
  变更或 Revocation 后重新授权；
- family revoke 后任何 generation 都返回 `invalid_grant`。

### 10.3 初始 Code exchange 原子流程

当 Code Scope 不含 `offline_access` 时，保持第三阶段行为。当包含时：

1. 锁定 Code，并重检 User、Client、Redirect、PKCE、Grant、Scope；
2. 生成 family ID、generation-0 Refresh clear/hash 与 Access JTI；
3. 在 bounded transaction 内签发 ID/Access JWT；
4. 插入 Access metadata、family、generation 0；
5. consume Code 并插入固定 Audit；
6. commit 后一次返回 ID、Access、Refresh；
7. signing/Audit/insert/commit 任何失败都不消费 Code、不留下 family/Access；
8. commit 后响应丢失时 Code 仍 at-most-once，Client 必须重启 Authorization。

### 10.4 Refresh exchange 原子流程

1. 严格解析 form 与 Client auth，验证 clear Refresh grammar 后仅传 digest；
2. 无锁解析 candidate IDs，随后按固定顺序重新锁定/读取 authority；
3. 重检 owning Client、User active、Client active、Grant active，以及 family 未 revoke/未过 absolute
   deadline；此时尚不以 presented generation 的 rolling expiry 跳过 consumed 检查；
4. 若 presented Token 已 consumed 且 family 仍 active：即使该旧 generation 的 rolling expiry 已过，
   仍在 family absolute window 内原子 revoke family/Access、写一次 reuse Audit，commit 后返回
   `invalid_grant`；
5. 若 Token 未 consumed 但未知、rolling-expired、已撤销或不匹配：统一 `invalid_grant`，不创建可
   放大的 Audit；
6. 计算本次 Access 的 inherited/explicit narrowed Scope 和 replacement expiry；显式 Scope 若
   扩张、含当前无效值或缺少 `openid`，返回 `invalid_scope` 且不消费 Token；replacement Refresh
   保持 family Scope 不变；
7. 生成 replacement clear/hash、generation+1、Access JTI；
8. transaction 内签 Access JWT、consume old、insert replacement/Access/Audit；
9. commit 后返回 Access + Refresh + actual Scope；不返回 ID Token；
10. 任何失败回滚到 old Token 仍未消费的原状态，除非失败本身是已提交的 reuse revoke。

### 10.5 并发与 delivery

同一 Refresh Token 的两个并发请求不是“双赢一输”后继续使用 winner。规定结果为：

- 最多一个 HTTP 请求可先成功获得响应；
- 另一个看到 consumed 后提交 reuse detection；
- family 最终一定 revoked；第一个响应中的 Access/replacement 也不可继续用于 UserInfo/refresh；
- Client 收到任何 `invalid_grant` 都清除本地 family 并重新授权；
- 不增加 grace window 或非标准 idempotency key。

这项 fail-closed 成本必须在示例、接入和运维文档中醒目标出。

## 11. Revocation Endpoint

### 11.1 HTTP/参数边界

- 只接受 `POST application/x-www-form-urlencoded`，Body ≤ 8 KiB，无 query；
- `token` 必须恰好一次；`token_type_hint` 至多一次；其他安全参数重复拒绝；
- 支持 hint `access_token`、`refresh_token`；hint 只可优化查找，命中失败必须继续搜索另一种
  支持类型；按 RFC 7009 §2.2，未知 hint 被忽略且仍返回正常 uniform response，不回显值；
- Public Client 使用一个 `client_id`；Confidential 只使用 Basic；禁止 channel mixing；
- 成功/invalid-token 响应统一为 HTTP `200`、zero-length body（不设 JSON Content-Type）、
  `Cache-Control: no-store`、`Pragma: no-cache`，不含 Token 状态详情。

### 11.2 状态语义

| Presented authority | 持久化动作 | 对外结果 |
| --- | --- | --- |
| owning active Access | 标记该 Access revoked | `200` zero-length body |
| owning Refresh generation + otherwise-live family（generation 可 consumed/rolling-expired） | revoke family + linked live Access | `200` |
| expired/revoked Access，或已 revoked/absolute-expired Refresh family | no-op | `200` |
| unknown/malformed/wrong Client | no authority change | 同一 `200`（通过基本语法/auth 后） |
| invalid Client auth | no lookup detail | `401 invalid_client` |
| DB/Audit failure | rollback | `500 server_error` |

未知 Token 不写每请求 Audit，防止存储 DoS。实际状态变更只写固定 target/event，不记录
clear/digest/token type hint 原文。

## 12. Introspection Endpoint

### 12.1 Caller policy

- HTTP/form/大小/重复参数边界与 Revocation 相同；`token` 恰好一次，optional
  `token_type_hint` 不是 authority；recognized hint 只优化查找，miss 必须继续其他支持类型，
  unknown 值忽略，不能绕过跨类型安全查找或改变响应；
- 只接受 Active Confidential Client 的 `client_secret_basic`；
- Public Client 即使提交自己的 `client_id` 也返回 `invalid_client`；
- caller 只看自己 Client 的 Token；wrong Client 与 unknown 完全相同；
- 不开放 CORS credential shortcut，不把 browser Session 当 introspection credential；
- 若未来新增 Resource Server，必须另写 ADR/迁移/Audience 模型。

### 12.2 Active 判定

`active=true` 同时要求：

- Token 格式/digest/metadata 有效且当前时间在范围内；
- Access 未 revoked；Refresh generation 未 consumed 且 family 未 revoked；
- User/Client/Grant 都 active；
- Scope 是 Token、family/Grant 与当前 Client policy 的有效交集；
- Token 绑定的 Client 等于 authenticated caller；
- Access 的 Issuer/Audience/Claim metadata 仍符合固定 profile。

任一失败只返回：

```json
{"active":false}
```

active response 使用冻结的按类型字段矩阵：

| Token | 唯一允许字段 |
| --- | --- |
| Access | `active`、`token_type="Bearer"`、`client_id`、effective canonical `scope`、`sub`、`iss`、`aud`、`iat`、`exp` |
| Refresh | `active`、`client_id`、effective canonical `scope`、`sub`、`iss`、`iat`、`exp` |

禁止内部 UUID、username/email/role、Session、family、generation、digest、`jti`、Audit 或
arbitrary metadata。Access 的 `scope` 是 Token/Grant/当前 Client policy 的有效交集；Refresh
Scope 不满足 `openid offline_access` 时只会得到 inactive，不返回被移除 Scope。

## 13. RP-Initiated Logout

### 13.1 End-session GET/POST：验证与确认

`GET /oauth2/logout` 的 query 与 `POST /oauth2/logout` 的 form 都必须按 RP-Initiated Logout 1.0
接收标准 Logout Request；两者只执行：

1. GET 只接受 query、无 request body，request target ≤ 8 KiB；POST 只接受
   `application/x-www-form-urlencoded` body ≤ 8 KiB 且无 query。两者都严格拒绝 invalid
   UTF-8/percent/NUL、重复或跨 channel 参数；标准 RP request 不要求 CSRF/同源，因为此阶段
   绝不变更 authority；
2. 按单值/大小边界解析 optional `id_token_hint`、`client_id`、`logout_hint`、
   `post_logout_redirect_uri`、`state`、`ui_locales`；Phase 4 不解释 `logout_hint/ui_locales`，
   但不能因不支持 locale 报错，也不得存储/记录这些原值；
3. 严格验证 hint JWS `alg/kid/iss/aud/azp/sub`；`iat/exp`、clock skew、可接受的 recently-expired
   window 与 verification-key overlap 使用 P4-00 Spike 冻结的单一时间策略，在该策略批准前
   不实现 Hint 接受分支；
4. 通过 hint Audience 恢复 Client；若同时提供 `client_id` 必须精确一致，再逐字节匹配登记
   Logout URI；只有 `client_id` 而无有效 hint 时仍不允许外部 redirect；
5. end-session route 不读取或绑定主 Session cookie；只把已验证的 hint Subject claim 留在受限
   server-side context，等 clean confirmation GET 再与当前 Principal 比较；
6. 把 verified Client/URI 与仅绑定其上的 opaque State 写入短期 logout transaction；lookup token
   只保存 digest。所有 GET/POST request 都先处于 zero-authority pre-confirm stage，不保存
   Session/User authority；
7. 把 clear transaction 只放入 dedicated short-lived、`Secure`（生产）、HttpOnly、host-only、
   `SameSite=Lax` 且 Path 限定为 `/oauth2/logout/confirm` 的 transient cookie，返回 route-specific
   `Referrer-Policy: no-referrer` 的 303 到无 query 的 `/oauth2/logout/confirm`；绝不在
   end-session request 上 revoke authority。

Logout transaction lookup token 与 CSRF proof 都使用独立 domain 的 256-bit CSPRNG value；数据库
只保存各自 32-byte SHA-256 digest 并设 unique/长度约束。它们不复用 Session/Auth transaction/
Refresh prefix 或 digest domain，且 clear lookup value 只能出现在浏览器边界的 transient
`Set-Cookie`/`Cookie` Header。

Hint 无效时不能外跳，也不能把原始错误/URI/State 嵌入页面；用户仍可确认 local logout。
Phase 4 不发布 `sid`，当前 cookie 选择被退出的 Session。

标准兼容性要求保留 GET，但 Client/示例/运维文档应优先使用 form POST，避免 Hint/State 出现在
RP 生成 URL、浏览器历史或上游访问日志。OneIssuer 必须对两种方法都做 query/body redaction；后续
`no-referrer` 303 只能阻止继续传播，不能撤回 RP 已选择 GET 所造成的上游暴露。

GET/POST request 必须在签名验证/数据库写入前使用 global/per-IP limiter；短 TTL 与冻结的
global-rate × TTL/capacity budget 必须给 zero-authority live rows 一个可计算上限。clean GET 绑定时
再执行每个 Session 的 live transaction cap；达到上限时按 P4-00 冻结的 reject/replace 策略处理。
由于 `SameSite=Lax` 主 Session cookie 不保证随跨站 RP POST 发送，303 后的 clean same-origin GET
才允许绑定当前 Session；不得为兼容 POST 把主 Cookie 放宽到 `SameSite=None`，也不得把
transaction 放进 Location。P4-00 已在 Chromium/Firefox 证明 303 不转发原始 Hint/State
Referer、transient cookie 仅发往受限路径且在 terminal 使用同一 Path/属性清理；P4-08 必须把
该证据和 expiry/two-tab/overwrite 矩阵固化为自动化浏览器测试。

### 13.2 Clean confirmation GET

`GET /oauth2/logout/confirm` 只从 transient cookie 恢复 transaction：

- 重检 transaction TTL/attempt/stage；只有 pre-confirm transaction 可锁定并绑定当前
  Session/User，并在该点执行 per-Session live cap；
- 绑定时重检 Hint `sub` 与 Principal，且一次性推进到 bound-confirmable stage；Subject 不一致时
  清除外部 Redirect/State authority，但仍可让当前用户确认 local logout；无有效 Session 则显示
  固定本地结果，不生成可提交的 confirm form；
- 已 bound 的 active transaction 只允许同一 Session/User 重新显示；每次显示都轮换只对当前
  transaction、stage 与 Session 有效的一次性 CSRF proof，并只持久化 proof digest。其他 Session、
  旧页面或另一个 end-session request 覆盖 cookie 后都不能确认当前/新 transaction；
- 返回无 query、无外部资源的 Hosted 页面，使用 `Referrer-Policy: same-origin`，使后续同源表单
  保留有效 Origin/Referer 而不携带原始 RP 参数；
- GET 不 revoke、不 consume、不清主 Session cookie；missing/invalid/expired/terminal transaction
  只产生固定本地结果并清 transient cookie，不外跳、不恢复 authority。

### 13.3 Hosted confirm POST：原子退出

`POST /oauth2/logout/confirm` 与标准 Logout Request 使用不同路由和严格 form schema；transaction
只能从 transient HttpOnly cookie 恢复。确认表单只提交 CSRF 与一个固定枚举
`decision=confirm|cancel`；query、hidden field 或其他 form 参数不得携带/覆盖 transaction：

- transaction 必须已处于 bound-confirmable stage 且精确绑定当前 Session/User；POST 永不把
  pre-confirm transaction 绑定或升级；
- transaction-bound one-time CSRF、Origin/Referer、TTL/attempt/consume 全部校验；cookie 被覆盖、
  旧页面、旧 CSRF proof 或跨 Session 提交只能固定失败；
- 重新检查 verified Client 仍 Active 且 URI 仍逐字节登记；状态变化不阻止用户完成 local
  logout，但必须抑制外部 Redirect/State；
- cancel 只 consume transaction、清 transient cookie 并进入固定本地“未退出”页，不 revoke、
  不外跳、不返回 State；
- confirm atomically revoke current Session binding、关联 family/live Access 与 Audit；
- confirm commit 后才清主 Session cookie 与 transient cookie；
- 只有 confirmed logout commit 后，transaction 中仍然验证通过的 URI 可接收 `state`；
- exact URI 在追加响应参数前完成匹配，Location builder 必须保留已登记 URI 的原始字节并只对
  opaque State 编码；若 registered URI 已含解码后名为 `state` 的 query key，则带 State 的请求
  降级为 local-only，不生成 duplicate/ambiguous State；
- 无 verified URI 时进入固定本地“已退出”页面；
- missing/invalid/expired transaction 清 transient cookie 并返回固定本地错误，不变更 authority；
- 重复 POST/Back/Refresh 因 transaction 已 consume 且 cookie 已清，不能第二次改变状态或重新跳转。

Logout terminal delivery 同样是 at-most-once：若 confirm commit 成功但返回 RP 的 303/State 丢失，
OneIssuer 已退出且不会靠 replay transaction 重放 Redirect；RP/用户只能开始新的安全流程。cancel
响应丢失也不会把 terminal transaction 变成 confirm。该成本必须进入 RP 接入和排障文档。

不向 RP 发送 Front-/Back-Channel 通知；RP 必须自行销毁本地 Session。

现有 `POST /logout` 仍是独立的 same-origin local logout：它不接收 RP 参数、不创建外部 Redirect/
State，继续要求 Session + CSRF + Origin/Referer，但 Phase 4 必须把其 Session revoke 改为同一个
原子 binding/family/Access cascade。管理员/当前用户的显式 Session revoke 同样复用该边界，不能
因为不是 RP route 而只撤销 cookie 行。

## 14. Grant 自助管理

### 14.1 List

`GET /api/v1/me/grants` 复用现有分页上限/错误契约，但使用新的 versioned opaque keyset cursor：
排序键只含 `updated_at + public client_id`，不得复用会编码内部 Grant UUID 的 time/UUID payload。
返回：

- Client 的安全展示名/public `client_id`/状态；不返回内部 Grant UUID；
- canonical Scope、created/updated/revoked time；
- 是否仍有 active offline family 的布尔摘要（不得返回数量/ID）；
- 不返回 Redirect/Logout URI、Secret、Token、family、Session 或其他 User。

### 14.2 Revoke

`POST /api/v1/me/grants/revoke` 使用无 URL identifier 的严格 JSON
`{"client_id":"<public-id>"}`：

- Repository 只按当前 Principal + public `client_id` 解析唯一 Grant；unknown/wrong owner 都是同一
  404，浏览器不能提交 User ID 或内部 Grant UUID；
- 必须 Session + CSRF + same-origin；
- atomically 标记 Grant revoked、递增 version、使旧版本未消费 Code 失效、revoke all
  families/live Access、写固定 Audit；
- 已 revoked 可幂等返回当前安全模型，不重复放大 Audit；
- 不撤销用户其他 Client 的 Grant，也不默认退出浏览器 Session；
- 后续需要 interactive Consent 才能重新激活。

## 15. Authority 级联矩阵

| 事件 | Session | Grant | 未消费 Code | Refresh family | Access metadata |
| --- | --- | --- | --- | --- | --- |
| passive Session expiry | expired | 不变 | 不变 | 不变（offline 可继续） | 仅按自身 TTL |
| active same-principal login/fixation rotation | old revoked；new 继承 binding | 不变 | 不变 | binding 不变、继续有效 | 不变 |
| account switch from active Session | old binding security-revoked；new User 获得 fresh binding | 两个 User 均不变 | 不变 | old binding family revoked | old binding live Access revoked |
| explicit selected Session revoke/logout | selected binding revoked | 不变 | 不变 | binding 下 family revoked | binding 下 live Access revoked |
| revoke one Access Token | 不变 | 不变 | 不变 | 不变 | 目标 revoked |
| revoke Refresh Token | 不变 | 不变 | 不变 | whole family revoked | family live Access revoked |
| consumed Refresh reuse | 不变 | 不变 | 不变 | whole family revoked | family live Access revoked |
| current-user Grant revoke | 不变 | revoked + version++ | 旧 Grant version 永久失效 | Grant 下全部 family revoked | Grant 下 live Access revoked |
| User disable | 全部 security-revoked | 保留原状态；effective=false | disabled 期间 fail closed | 全部 family revoked | 全部 live Access revoked |
| Client disable | 不变 | 保留原状态；effective=false | disabled 期间 fail closed | Client 全部 family revoked | Client live Access revoked |
| Client 移除 `offline_access` | 不变 | 保留 Scope；effective intersection 缩小 | 含 offline Scope 时 fail closed | Client 全部 family revoked | family-linked live Access revoked |
| Client Secret rotate | 不变 | 不变 | 不变 | 默认不变 | 默认不变 |
| signing key rotation | 不变 | 不变 | 不变 | 不变 | JWT 受 JWKS overlap/exp 约束 |

所有“同时变更”都必须由单 PostgreSQL transaction 完成。User/Client 在读取路径继续即时检查，
即使持久化级联因暂时故障未完成也 fail closed；管理事务自身失败时不得只提交一半状态。

Session cascade 不能只看 `revoked_at IS NOT NULL`：security cascade reason 固定为 `logout`、
`user`、`others`、`admin`、`user_disabled`、`role_changed`、`account_switch`；same-principal
`rotation` 与 passive `expired` 不级联。新增 reason 必须同时更新 CHECK、ADR/矩阵和双向竞态
测试，不能默认归类。

## 16. 数据模型与迁移提案

### 16.1 Migration 00012：Phase-four Grant、Session binding 与 Audit vocabulary

- 扩展 `auth_transactions`、`consent_grants`、`authorization_codes` 等持久化协议 Scope
  constraint 到固定四值并允许 `offline_access`；`access_tokens` 的同类约束在 00013 重建；
- 增加 `revoked_at`、positive `version` 与 active/updated 索引；
- `authorization_codes` 增加 positive `consent_grant_version` 并为 schema-11 行安全回填；Code
  exchange 要求版本精确匹配，Grant authority 更新使用 compare-and-increment；
- `login_sessions` 增加 non-null stable `session_binding_id`，旧行以自身 ID 回填；防固定登录
  rotation 仅在 old Session active 且 principal 相同时把 binding 传给 replacement Session；过期
  Session 或账号切换不得跨 User 继承，账号切换对旧 active binding 默认 fail-closed cascade；
- 扩展 Session revoke reason 固定 CHECK 以区分 `account_switch`，禁止借用 non-cascade
  `rotation` 表达跨 User 变更；
- 扩展固定 Audit event/target/changed-field CHECK；
- 增加 reuse Audit 的 bounded uniqueness 约束所需 vocabulary；
- 不修改 00001–00011 checksum。

### 16.2 Migration 00013：Refresh family 与 Access lifecycle

建议新增：

```text
refresh_token_families
  id, origin_authorization_code_id, consent_grant_id, user_id, client_id,
  origin_session_id, session_binding_id, scopes, created_at, absolute_expires_at,
  revoked_at, revoke_reason

refresh_tokens
  id, family_id, token_hash, generation, issued_at, expires_at, consumed_at
```

关键约束：

- `token_hash` 32 bytes unique；`(family_id, generation)` unique；
- family Scope sorted/unique、包含 `openid offline_access`、最多四项；单一 family 是 Refresh
  Scope 真值，避免 generation 与 family 维护两份可能漂移的数据；
- rolling expiry ≤ configured hard schema maximum，且不超过 family absolute expiry；
- revoke reason 固定枚举；时间单调；
- nullable `origin_authorization_code_id` 使用普通 FK `ON DELETE SET NULL`，并用只覆盖 non-null
  值的 partial unique index 保证一个 Code 至多创建一个 family，避免 90 天 family 阻塞 Phase 3
  Code 的 24 小时清理；Code 尚存在时的一致性由 transaction/必要 trigger 保护，其后缺失不改变
  lineage 或 authority；
- origin Session 同样是 nullable FK `ON DELETE SET NULL`；authoritative cascade 使用 stable
  `session_binding_id`，不能因 Session rotation/cleanup 断开，也不能因旧行缺失恢复 authority。

扩展 `authorization_codes`：两列在 schema 上为 nullable 以保留 schema-11 active Code；Phase-4
新签发 Code 必须写当前 `origin_session_id`（FK `ON DELETE SET NULL`）与 non-null
`session_binding_id`，且任何含 `offline_access` 的行由 CHECK 强制 binding 非空。扩展
`access_tokens`：

- 增加 non-null fixed `issuance_source=authorization_code|refresh_token`，schema-11 行安全回填为
  `authorization_code`；该 discriminator 在 origin 行清理后仍保留来源语义；
- `authorization_code_id` 改为 nullable FK `ON DELETE SET NULL` + non-null partial unique index；
- 增加 nullable unique `source_refresh_token_id`；
- 增加 `refresh_family_id`、`origin_session_id`、`session_binding_id`、`revoked_at/revoke_reason`；
- Access `origin_session_id` 同样使用 nullable FK `ON DELETE SET NULL`；所有 cascade 只依赖 stable
  `session_binding_id`，不能让 Session cleanup 破坏 CHECK 或恢复 authority；
- source 约束：`refresh_token` 必须有 non-null `source_refresh_token_id`/family 且 Code 为 NULL；
  `authorization_code` 必须让 Refresh source 为 NULL，但 Code FK 可在后续清理后变为 NULL。Repository
  insert 时仍强制提供 Code；不能使用会被 `ON DELETE SET NULL` 破坏的永久 Code XOR Refresh CHECK；
- phase-three 现有 Code/Access 行保持 legacy Code source、family/session binding NULL，不 fabricate
  Refresh Token；Phase-4 repository inserts 必须携带 binding，即使本次 Code 未申请 offline Scope；
- UserInfo 对历史行继续原规则，对新行增加 revoke/family/Grant 检查。

### 16.3 Migration 00014：Logout transaction 与 cleanup indexes

新增短期 `logout_transactions`：

- opaque token hash、nullable User/Session binding、verified Client/URI 与只绑定到该 pair 的 opaque
  State；所有 end-session request 都先形成 zero-authority pre-confirm context，随后只能一次性
  same-origin bind 当前 Session；
- clear lookup value 只经 Path-scoped transient HttpOnly cookie 传递，不进入 Location、query、
  Hosted hidden form、日志或 Audit；terminal/invalid/expiry response 负责清同属性 cookie；
- stage、transaction-bound CSRF proof digest、created/expires/bound/consumed、bounded attempt count
  与合法时间单调约束；
- lookup/proof hash 各 32 bytes，lookup hash unique，digest domain 与所有现有 token/session 分离；
- 每 Session 的 live transaction cap/replace-or-reject 所需约束或锁策略；
- verified URI 与其 bound opaque State 不进入普通 read/Audit；
- consumed/expiry cleanup index；
- Refresh family/token/Access revoke/expiry retention index；
- reuse event partial unique index；
- FK-aware 250-row `SKIP LOCKED` cleanup 顺序。

### 16.4 升级与回滚

- schema-11 populated upgrade test 必须包含 active/expired Code、Access、Grant、Session；
- Code cleanup `ON DELETE SET NULL` 后 Access 的 immutable `issuance_source`/authority CHECK 仍合法；
- 不给旧 Grant 自动添加 `offline_access`，不创建 family；
- migration 前签发、升级时仍 active 的 legacy Code 可按原 Scope 交换，但不能产生 Refresh，所得
  Access 保持 binding NULL 并进入最长 30 分钟兼容窗口；
- 升级时尚未过期的 phase-three Access 按原 TTL 工作，最长 30 分钟后自然退出兼容窗口；
- schema 14 不保证旧 binary 兼容；回滚必须恢复 migration 前备份，不能跑生产 Down；
- migration 在大表上必须评估锁时长、index build 和空间，禁止不受控 rewrite；
- 版本/校验脚本、sqlc generation 与 migration docs 同 PR 更新。

## 17. 锁顺序与事务边界

Refresh/Grant/Client/User family 操作建议使用：

```text
User → Client → Consent Grant → Refresh family → Refresh Token → Access metadata
```

Presented digest 可先查 candidate ID，但加锁后必须再次验证 digest、owner 和全部 authority。
更新多个 family/Access 时按 UUID 固定排序并使用 set-based SQL，不能按用户可控输入顺序循环。

Code exchange 保留 `Code → User → Client → Grant`，只在 Grant lock 后创建新的 family，不等待
已有 family，避免与 Grant revoke 形成锁环。Session revoke 先确定并锁定目标 Session/binding，
再以固定顺序级联 family；同 Principal 的防固定 rotation 在同一登录事务内继承 binding，不走
revoke cascade；跨 Principal 不能继承，并按冻结的账号切换 cascade 处理。
Refresh 不要求或锁定 active browser Session，因为 offline access 可跨 passive Session expiry。

Logout clean-bind/confirm 使用 `Logout transaction → Session/binding → ordered family → Access`
顺序；普通 Session revoke 从 Session 开始且绝不反向锁 logout transaction。P4-00 已冻结
per-Session cap 采用 reject-current；Phase 4 不实现 replace，避免在持有当前 transaction 时等待
另一个先持有 transaction 的请求形成锁环。

至少为以下 pair 做真实 PostgreSQL 并发/死锁测试：Refresh↔Refresh、Refresh↔Grant revoke、
Refresh↔Session revoke、Refresh↔User/Client disable、Code issue↔Grant revoke、cleanup↔reuse。
只对明确分类的 serialization/deadlock failure 做 bounded transaction retry；重试不得重复生成或
输出两组 clear Token。

## 18. 配置提案

| 环境变量 | 默认 | 建议边界/说明 |
| --- | --- | --- |
| `ONEISSUER_REFRESH_TOKEN_TTL` | `720h` | 1h–720h |
| `ONEISSUER_REFRESH_TOKEN_ABSOLUTE_TTL` | `2160h` | 24h–8760h，且 ≥ rolling TTL |
| `ONEISSUER_LOGOUT_TRANSACTION_TTL` | `5m` | 1–15m |
| `ONEISSUER_LOGOUT_MAX_ACTIVE_PER_SESSION` | `3` | 1–5；默认 reject 当前 bind，replace 需 P4-00 锁序证据 |
| `ONEISSUER_LOGOUT_ID_TOKEN_HINT_MAX_AGE` | `24h` | 5m–720h；旧验证公钥至少保留该值 + clock skew |
| `ONEISSUER_OAUTH_RATE_PER_MINUTE` | `120` | 每 IP/认证后 Client 的 token lifecycle bucket |
| `ONEISSUER_OAUTH_RATE_BURST` | `30` | bounded burst |
| `ONEISSUER_OAUTH_GLOBAL_RATE_PER_SECOND` | `100` | process-wide pre-sign/DB guard |
| `ONEISSUER_OAUTH_GLOBAL_BURST` | `200` | process-wide burst |

配置必须进入 `SafeMap` 但不包含任何 Token/Secret。Production 需要部署容量评审，不允许通过
超大 TTL 绕过 family absolute limit。Schema CHECK 使用硬上限，不把运行时默认写死成唯一值。

## 19. HTTP、错误与限流

- Token/Revoke/Introspect：POST、form、无 query、Body ≤ 8 KiB、单一 Content-Type；
- clear Token 长度在 hash/DB 前严格限制；Basic/Header 保持现有上限；
- duplicate、NUL、invalid UTF-8/percent、multiple credential channels 一律固定错误；
- global + per-IP bucket 在昂贵 DB/signing 前；认证成功后再进入 bounded per-Client bucket；
- bucket table 有固定上限/idle sweep，不能由随机 `client_id` 制造无界 Map；
- Logout request GET/POST 在 Hint 验签和事务插入前同样进入 global/per-IP bucket；zero-authority
  rows 受 rate × TTL capacity budget，per-Session live cap 只在 clean GET bind 时执行；
- Token refresh unknown/expired/reused authority → `invalid_grant`；Access Scope expansion、当前
  无效值或缺少 `openid` → `invalid_scope` 且不消费；invalid Client → 401/Basic challenge；
- Revocation authenticated unknown → 200；Introspection authenticated inactive → 200 active=false；
- internal DB/sign/Audit → `server_error`，不降级成成功；
- 所有协议响应 `no-store`/`no-cache`，不启用 CORS；
- end-session GET/POST 的 clean 303 使用 route-specific `Referrer-Policy: no-referrer`；clean Hosted
  logout 页面沿用严格 CSP、`Referrer-Policy: same-origin`、frame deny、无外部资源和 HTML escaping。

## 20. Audit、隐私与 Metrics

### 20.1 固定 Audit 提案

- `refresh_token_issued`
- `refresh_token_rotated`
- `refresh_token_exchange_rejected`
- `refresh_token_reuse_detected`
- `refresh_token_family_revoked`
- `access_token_revoked`
- `consent_grant_revoked`
- `consent_grant_reactivated`
- `rp_logout_completed`
- `logout_transaction_rejected`

Targets 可增加 `refresh_token`、`refresh_token_family`、`logout_transaction`。Changed fields 只允许
`issued`、`rotated`、`consumed`、`reused`、`revoked`、`reactivated` 等固定字段名。

现有受限 Audit `target_id` 可以保存被影响实体的随机内部 UUID，除此之外禁止记录 clear/digest、
JWT `jti`、generation、family/Session linkage、Scope 原串、Hint、State、URI、Header、Client
Secret 或 Session cookie。该 UUID 不得复制到 changed fields、日志、Metrics、协议或 current-user
response 的新增 phase-four 字段；已接受的 phase-two owner/admin User/Client/Session resource ID
字段保持兼容，但不能借此暴露 family/binding/Token/Grant/logout-transaction ID。
`refresh_token_exchange_rejected` 只允许对已解析的内部 target 做每 generation 至多一条的
partial-unique bounded evidence；未知/畸形 Revoke、Introspection、Refresh 流量不逐条进入 Audit，
重复 `invalid_scope` 也不能放大行数。

### 20.2 Metrics 提案

- `oneissuer_token_operations_total{operation,result}` 增加固定 `refresh/revoke/introspect`；
- `oneissuer_refresh_reuse_total{result}` 或合并到 fixed operation；
- `oneissuer_token_families_revoked_total{reason}`，reason 固定枚举；
- `oneissuer_rp_logout_total{result}`；
- cleanup 继续复用 operation/result/rows/duration，新增固定 operation；
- 可选 Gauge 只统计 aggregate active families，不按 Client/User 分标签。

所有 label 在代码中枚举，禁止 token type hint 原值、Client ID、User、Scope、URI、reason error。

## 21. Retention 与 Cleanup

- Access metadata：expiry/revoke 后至少 24h，再按 250 行 batch 删除；
- Logout transaction：active 到 TTL；terminal 保留 24h 后删除；
- Refresh Token digest：至少保留到 family absolute expiry，确保旧代 reuse 可识别；
- terminal family/Token：不早于 `max(absolute_expires_at, terminal_at) + 30d` 删除；提前 revoke
  不能缩短 digest reuse-detection 或安全证据窗口；
- Consent Grant：不自动删除；revoked 行可重新 Consent；
- Audit：仍不由应用删除；
- 任何 cleanup 延迟都不延长 Token/Grant/Session validity；
- FK 删除顺序：Access → Refresh Token → Family；Code/Grant/Session 按关联策略后处理；
- 每个 cleanup operation 使用新 5s context，并报告已提交 partial progress。

容量评审至少估算每日 Code exchange、平均 refresh 频率、90 天 family、30 天 evidence 与 index
空间；上线前必须给出监控阈值和 vacuum/backup 影响。

## 22. 测试策略

### 22.1 单元/属性测试

- Refresh prefix/entropy/hash domain/invalid grammar；
- TTL min/max/absolute cap 与 replacement expiry；
- Access Scope inherit/per-request narrowing/no expansion；replacement Refresh Scope identity；
- family active/revoke/reuse state machine；
- Revocation hint/ownership/uniform response；
- Introspection active/inactive minimal schema/forbidden fields；
- logout hint JWS/Issuer/Audience/Subject/approved stale-time window、exact URI、stage 与
  transaction-bound CSRF state machine；
- logout lookup/proof entropy、domain-separated digest、cookie grammar/attribute；
- Discovery arrays/paths/auth methods snapshot；
- current-user Grant cursor/owner/public-client selector/forbidden-field property tests；
- Audit enums、Metric labels、config bounds；
- retention cutoff 和 lock ordering helpers。

### 22.2 真实 PostgreSQL 与并发

- schema 11 populated → 14，无 authority fabrication/data loss；
- initial offline Code exchange 全原子，签名/Audit/commit fault 全回滚；
- refresh success/expiry/per-request Access narrowing/replacement Scope identity/Client auth/current state；
- consumed generation rolling-expired 但 family absolute-live 时仍触发 reuse；owning old Refresh 的
  Revocation 仍撤销 live family；
- 同一 Token 并发：最多一个 response，family 最终 revoked；
- reuse event 唯一且 repeated replay 不放大；
- Grant version、Session binding rotation、User/Client cascade 与 refresh 双向竞态；
- Access revoke 不撤 family，Refresh revoke 必须撤 linked Access；
- idempotent revoke 和 concurrent revoke；
- Introspection consistent snapshot；
- logout zero-authority live-row budget、one-time bind、transaction-bound CSRF、cookie overwrite、
  confirm/replay/cancel、Client/URI 中途变更与 commit failure；
- cleanup first-batch rollback/later-batch partial progress/retention boundary；
- restart persistence、outage/recovery、deadlock/serialization bounded retry。

### 22.3 HTTP、Fuzz 与浏览器

- form content type/body/query/duplicate/NUL/UTF-8/percent/header/channel matrix；
- malformed/cross-type/oversized clear Token Fuzz；
- Revoke unknown/wrong/expired response byte equality；
- Introspection cross-Client and Public Client rejection；
- Logout URI encoding/query/fragment/CRLF/duplicate/既有 `state` key/State append privacy Fuzz；
- real browser request GET/POST 都不退出、GET history/log warning、303 clean URL/no-referrer、
  SameSite continuation/storage cap、cookie-only transaction、cookie overwrite/two-tab/stale form、
  cookie loss/terminal cleanup、
  transaction-bound confirm CSRF、cross-site logout attempt、same-origin form；
- CSP/referrer/security headers、HTML escape、no external asset；
- rate limiter refill/cap/idle/global budget；
- full logs/Audit/Metrics/error/response sensitive canary scan；只允许 post-logout `state` 在
  confirmed logout commit 后进入仍已登记的精确 verified Redirect boundary。

### 22.4 Conformance

- 固定 Suite/镜像/版本/配置 digest；
- 运行适用 Refresh、offline access、RP-Initiated Logout 模块；
- Revocation/Introspection 若 Suite 覆盖则记录适用 profile；
- 明确 Front-/Back-Channel、dynamic/PAR/JAR/FAPI 等非适用；
- 只提交 secret-free matrix/result summary，不提交 raw Token/Client Secret；
- 不把通过子集写成 OpenID Foundation Certification。

## 23. 示例 Client、Compose 与 CI

### 23.1 示例 RP

- A（Public）和 B（Confidential）均可请求 `offline_access`；
- Refresh 与 logout 所需 ID Token Hint 只保存在 server-side bounded Session；cookie 仍只有 opaque
  RP Session ID；
- 替换 old/new Refresh 必须原子，旧 clear value 立即从内存丢弃；
- `invalid_grant` 清除 family 并引导重新授权；不后台无限重试；
- B 展示 owning Introspection；A 明确不能 Introspect；
- logout 默认用 form POST 提交受限保存的 initial ID Token Hint 与新 state；验证返回 state 后才销毁
  RP local Session，Hint/State 不进入 RP URL/access log；
- 示例继续校验 Issuer/Audience/signature/actual Scope/UserInfo subject；
- 1024 Session cap/CAS 保护继续存在。

### 23.2 `make phase-4-smoke`

在 Phase 3 smoke 基础上增加：

1. schema 11 upgrade fixture 与空库迁移；
2. A/B offline Consent、初始 Refresh；
3. rotation、restart、per-request Access Scope narrowing，以及后代 Refresh Scope 保持不变；
4. concurrent reuse 最终 family revoke；
5. Access/Refresh Revoke 与 Introspection；
6. Grant revoke、login rotation binding、explicit Session revoke、passive Session expiry 差异；
7. RP logout exact URI/state/CSRF/cancel/replay；
8. DB outage、Audit/commit injection、graceful shutdown；
9. secret exposure scan、non-root/read-only、container restart persistence。

### 23.3 CI 门禁

保持全部 Phase 3 gate，并新增 migration 12–14 checksum、sqlc、OpenAPI、phase-4 smoke、更新后的
Conformance record。Container SBOM/Trivy、Go/npm audit、govulncheck、race、lint、Fuzz、文档链接
和 private-key/secret scan 仍是阻断项。

## 24. 工作项拆分

| ID | 工作项 | 输出 | 前置 |
| --- | --- | --- | --- |
| P4-00 | ADR/Threat/Spike | accepted profile、锁/依赖、Hint time/key、Session binding 证据 | **完成** |
| P4-01 | Grant/Session/Audit migration | 00012、Grant version、Session binding、domain/sqlc、upgrade tests | P4-00 |
| P4-02 | Family/Access schema | 00013、token domain/repository | P4-01 |
| P4-03 | Initial offline issue | Authorize/Consent/Code response | P4-02 |
| P4-04 | Refresh rotation/reuse | parser、service、atomic exchange | P4-03 |
| P4-05 | Revocation | endpoint、uniform semantics、cascade | P4-04 |
| P4-06 | Introspection | restricted caller、minimal response | P4-04 |
| P4-07 | Grant self-service | OpenAPI、list/revoke + interactive Consent reactivation | P4-04 |
| P4-08 | RP logout | 00014、transaction、Hosted page | P4-02 |
| P4-09 | Cross-authority cascade | Session/User/Client atomic updates | P4-04/P4-08 |
| P4-10 | Rate/Cleanup/Observability | bounded limiter、retention、metrics | P4-05–09 |
| P4-11 | Example/Compose | strict RP、phase-4-smoke | P4-10 |
| P4-12 | Conformance/docs/release | guides、record、Release Notes | P4-11 |

核心依赖：

```text
P4-00 → P4-01 → P4-02 → P4-03 → P4-04
P4-04 → P4-05 / P4-06 / P4-07 / P4-09
P4-02 → P4-08 → P4-09
P4-05..09 → P4-10 → P4-11 → P4-12
```

## 25. 建议 PR 顺序

1. **PR1 文档与 Spike**：ADR、Threat Model、wire/schema/lock/conformance fixture；
2. **PR2 Migration 12**：Grant offline/revoke/version、Session binding、Audit enums、sqlc/tests；
3. **PR3 Migration 13**：family/Refresh/Access source/revoke model、cleanup queries；
4. **PR4 Initial offline issue**：Authorize/Consent/Code exchange/Discovery 暂不公开新 fields；
5. **PR5 Refresh Grant**：rotation/reuse/concurrency/failure，随后开放 grant metadata；
6. **PR6 Revoke + Introspect**：各自 route/auth/error/live Metadata cross-test；
7. **PR7 Grant API + cascades**：OpenAPI、Session/User/Client interleavings；
8. **PR8 Migration 14 + RP logout**：Hosted flow、URI/CSRF/browser tests；
9. **PR9 hardening**：limits、cleanup、metrics、capacity/incident docs；
10. **PR10 example/smoke/conformance/release**：完整验收与最终文档。

任何中间 PR 的 Discovery 都不能声明尚未 live 的能力。若需分支部署，Feature 必须整体不可见，
而不是 endpoint 返回伪成功。

## 26. Definition of Done

- [x] ADR 0003 与 Phase 4 Threat Model accepted，无 ownerless blocker；
- [ ] 00001–00011 checksum 不变，schema 11 populated → target upgrade 通过；
- [ ] `offline_access` 只在 Code + explicit live Grant 下签发；
- [ ] Refresh clear value CSPRNG/digest-only，rolling/absolute TTL 生效；
- [ ] refresh request Scope 只控制本次 Access 且不扩大；replacement Refresh Scope 与 presented
      Token 相同；
- [ ] consumed reuse 无 grace，family/linked Access 最终 revoked；
- [ ] consumed old generation 在 rolling expiry 后、family absolute expiry 前仍检测 reuse；任一 owning
      Refresh generation 的 Revocation 撤销 otherwise-live family；
- [ ] Code/Refresh mint、revoke、logout、Grant cascade 与 Audit 均原子；
- [ ] Revocation 对 unknown/wrong/inactive 不形成 oracle；
- [ ] Introspection 仅 Confidential owning Client，inactive body/active fields 固定；
- [ ] RP logout request GET/POST 无 authority mutation 且 zero-authority transaction 有界；clean GET
      不泄漏原始 Hint/State 且独占 bind；cookie-only confirm POST 有精确 Session/transaction-bound
      CSRF，提交前重检 Client/精确 Redirect；cookie overwrite/stale form 不能 retarget；SameSite
      continuation、cookie cleanup 与 Hint stale-time/key policy 已冻结；
- [ ] Hint-required Redirect 的窄化已通过 ADR/Conformance 明确记录，不把 `client_id`-only 限制误报
      为无条件完整 profile；
- [ ] Grant list/revoke owner-bound，cursor/model 不含 Grant UUID，reconsent 不恢复旧 revoked
      Scope/Code version；
- [ ] existing local `/logout` 与 owner/admin Session revoke 复用 binding cascade，但不混用 RP schema；
- [ ] login rotation 继承 stable binding；passive Session expiry 与 explicit revoke 的 offline
      语义有测试/文档；
- [ ] UserInfo/Introspection 立即观察 revoke/disable/Grant/family state；
- [ ] JWT offline revocation 延迟限制明确，不宣称 instant global revocation；
- [ ] cleanup retention 足以 reuse detection，250-row partial progress 正确；
- [ ] endpoint limiter 有 bounded map/global budget，无随机 Client ID 内存放大；
- [ ] 日志/Audit/Metrics/error/镜像不含 Token/Secret/Hint/State；response 仅在 verified
      post-logout Redirect boundary 原样返回对应 `state`；
- [ ] race、真实 PG 并发/故障、Fuzz、lint、vuln、SBOM、Trivy 全绿；
- [ ] 示例 A/B、restart/outage、phase-4-smoke 全绿；
- [ ] Discovery、OpenAPI、配置、迁移、Client、运维、排障、Key Runbook 同实现；
- [ ] 适用 Conformance 通过并保留 secret-free evidence，不作认证声明；
- [ ] Release Notes 明确 delivery/replay/Introspection/Logout 与残余限制。

## 27. 验收脚本草案

自动验收至少执行：

1. 构建固定镜像，生成临时 JWK，空库迁移并 Bootstrap；
2. 装载 schema-11 fixture，升级并核对旧 authority；
3. 创建 Public A、Confidential B，登记 Redirect/Logout URI 和 offline Scope；
4. 无 Consent 的 `prompt=none offline_access` 安全失败；
5. interactive Consent 后初始 response 有 Refresh，普通请求无 Refresh；
6. A/B 各自 refresh，旧 Token 失效、actual Scope 正确；
7. restart 后 latest generation 可用；
8. concurrent old generation 导致 family 最终 revoke；
9. Revoke Access/Refresh 的 cascade 差异正确；
10. B Introspect own active/inactive；A/other Client 不可探测；
11. Grant revoke 使旧 Code version/family/Access fail closed；Client 移除 offline Scope 不复活 family；
12. login rotation 保留同一 binding，explicit Session revoke 级联，而 passive expiry 不意外撤销
    仍批准的 offline family；
13. RP logout request GET/POST no-op/cap、303 no-referrer clean continuation、cookie-only transaction、
    one-time bind/transaction-bound CSRF、cookie overwrite/stale form、SameSite/cookie-loss/cleanup、
    Hint 时间窗口、cancel/confirm、Client/URI 中途变更、State、exact URI、CSRF/replay 全矩阵；
14. 签名/Audit/commit/DB outage 不留下半 consume/半 revoke；
15. cleanup retention/reuse evidence 与指标正确；
16. 敏感 canary 不出现在 argv、文件、日志、Audit、Metrics、镜像或非预期响应；唯一 allowlist 是
    exact verified post-logout Redirect 的对应 `state`；
17. 所有 Phase 1–3 Bootstrap、login、Consent、Code、UserInfo、Admin 回归通过。

脚本不能把管理员密码、Client Secret、private JWK、Code、Refresh/Access/ID Token、Hint、State
写入命令行、固定文件或 CI 输出。临时受限文件/pipe/内存必须在退出时清理，失败日志也只打印
固定分类。

## 28. 主要风险与待评审问题

| 风险/问题 | 当前提案 | 阻断条件 |
| --- | --- | --- |
| 并发 benign retry 被判 reuse | fail closed、whole-family revoke | 若产品要求 grace，必须重开 ADR |
| 90 天 family 容量 | 30d rolling/90d absolute + 30d evidence | 无容量/索引/backup 数据则不上线 |
| Introspection 实用性有限 | Confidential self-introspection only | 若要 Resource Server，移出本阶段或新 ADR |
| Logout `client_id`-only interoperability | 更严格的 Hint-required external redirect；bare `client_id` 仅可 local logout | ADR 已接受该窄化；Conformance/Release 必须明确记录，否则阻断 |
| Logout hint 过期/Key overlap 与 refresh 不发新 ID Token | 24h 默认、5m–720h bounded hint age + verified ring；无效则 local logout，不静默改发 ID Token | P4-00 已冻结；实现与 key-overlap 测试不符则阻断 |
| Session rotation/revoke 与 offline 语义 | rotation 继承 binding；explicit revoke cascade；passive expiry 不级联 | P4-00 已冻结 lineage；无真实 PG 竞态证据则不上线 |
| Logout request storage/SameSite/Referer | GET/POST limiter + rate×TTL live-row budget + bind-time per-Session cap + no-referrer 303 + cookie-only clean continuation | 无有界跨站 POST、无 Hint/State Referer 泄漏及 cookie cleanup 浏览器证据则不上线 |
| Logout cookie overwrite/多标签页 | clean GET 独占 bind + transaction-bound one-time CSRF；POST 不升级 pre-confirm | 旧页面可确认另一 transaction 则阻断上线 |
| Refresh signing 仍在 DB transaction | local RSA bounded transaction | remote KMS 必须重做事务，不在本阶段 |
| 跨表 lock/deadlock | 固定顺序 + real PG interleaving tests | 任一无界 retry/双 response 阻断 |
| JWT offline revoke 延迟 | UserInfo/Introspection 即时，offline 到 exp | 不能宣称 global instant revoke |

## 29. 进入第五阶段的交接条件

Phase 4 验收后，向最小真实 Account/Admin UI 与 `v0.1` 收口交接时必须冻结：

1. Refresh family/generation、rolling/absolute TTL、reuse 与 delivery 语义；
2. Access/Refresh revoke 和 Introspection caller/response profile；
3. RP logout transaction、Hint、exact URI、State 与 Session cascade；
4. Grant list/revoke API、interactive Consent reactivation 与 owner visibility；
5. User/Client/Session/Grant/family/Access 级联矩阵；
6. schema target、retention/cleanup/容量和升级/恢复边界；
7. Discovery/错误/Audit/Metrics/隐私枚举；
8. 示例 RP 与 Conformance evidence。

第五阶段可以把 `web/` 原型逐页接入已经冻结的 current-user/Admin API，但不得让浏览器脚本
持有 Refresh Token、Client Secret 或协议 authority，也不得通过 UI 需要反向放宽 Phase 4 的
CSRF、同源、recent-auth、分页、字段可见性和 one-time Secret 规则。
