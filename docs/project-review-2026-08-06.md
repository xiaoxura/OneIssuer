# OneIssuer 当前项目全面审查与测试报告

> 日期：2026-08-06  
> 审查对象：`main` 分支当前工作树，包括尚未提交的 Phase 4 变更  
> 审查方式：架构与安全基线核对、分模块静态审查、宿主机质量门禁、真实 PostgreSQL、Compose 端到端、容器供应链检查及真实 Chrome 验证  
> 结论：核心流程已有较完整实现和测试基础，但当前工作树仍存在高风险 authority 级联与示例 RP 并发缺陷，完整发布门禁尚未全绿

## 1. 审查范围与基线

本轮审查以以下已接受或当前适用的设计输入为基线：

- [`go-backend-design.md`](./go-backend-design.md)：单 Issuer、PostgreSQL 权威状态、模块边界与安全目标；
- [`ui-design.md`](./ui-design.md)：独立 Web Mock、响应式和可访问性要求；
- [`phase-3-handoff.md`](./phase-3-handoff.md)：Phase 2/3 冻结的身份、Client、Session、事务和隐私边界；
- [`adr/0002-phase-three-oidc-security-profile.md`](./adr/0002-phase-three-oidc-security-profile.md)：Authorization Code、S256、Issuer、JWT、UserInfo 与错误契约；
- [`adr/0003-phase-four-token-lifecycle.md`](./adr/0003-phase-four-token-lifecycle.md)：Refresh rotation/reuse、Revocation、Introspection、Grant 与 RP Logout 决策；
- [`phase-4-threat-model.md`](./phase-4-threat-model.md)：Phase 4 authority、并发、隐私与残余风险；
- [`phase-4-dependency-concurrency-spike.md`](./phase-4-dependency-concurrency-spike.md)：Schema 12-14、锁顺序、Session binding、Hint/Key 和浏览器 continuation 决策；
- [`phase-4-development-plan.md`](./phase-4-development-plan.md)：实现范围和 Definition of Done。

当前工作树相对 `main` 涉及 107 个已跟踪文件，约 7,797 行新增、1,047 行删除，并包含一批未跟踪的 Phase 4 源码、迁移、测试和文档。审查结论针对该完整工作树，不仅针对已提交的 `HEAD`。

## 2. 总体结论

项目的 Phase 4 主流程已经能够通过 race-enabled Go 测试、真实 PostgreSQL 集成测试和完整 Compose smoke。协议和存储实现总体遵循既定的 digest-only、单次消费、原子提交、owner-bound 查询和精确 URI 原则。

当前不能视为发布就绪，主要原因如下：

1. 账号切换与本地登出的服务端 authority 级联存在确定缺陷；
2. 示例 RP 的 Refresh Token 并发和 Session 更新方式会破坏 fail-closed family；
3. RP Logout 的基础设施错误分类会错误终结事务；
4. Migration 13 的 Code detach 约束自相矛盾；
5. `make check` 尚未全绿，Trivy 本轮扫描未完成，Phase 4 Conformance 仍为 `NOT_RUN`；
6. 若干并发、迁移、浏览器 Logout 和示例 RP 路径缺少直接测试证据。

## 3. 审查发现

### 3.1 高风险

#### H-01 账号切换未撤销旧 Session binding 的 Token authority

证据：[`internal/storage/postgres/authn.go:174`](../internal/storage/postgres/authn.go#L174)、[`internal/httpserver/auth_handlers.go:135`](../internal/httpserver/auth_handlers.go#L135)、[`internal/authn/authn.go:69`](../internal/authn/authn.go#L69)

登录事务检测到现有活跃 Session 属于另一用户时，只以 `account_switch` 撤销旧 Session，没有调用 Session binding 的 Refresh family/Access metadata 级联。注册流程没有传递现有 Session，因此账号 A 的浏览器会话中注册账号 B 时，连 A 的旧 Session 都不会被撤销。

影响：账号切换后，旧用户的 Refresh Token 仍可继续刷新，关联 Access Token 也继续有效，违反已冻结的 account-switch fail-closed 级联矩阵。

建议：登录和注册都应把现有 Session token 传入同一 PostgreSQL 事务；锁定旧活跃 Session 后，以 `account_switch` 原因撤销其 binding 下按固定顺序锁定的 family 和 live Access，再创建新用户的 fresh binding。

#### H-02 本地登出在认证存储故障时产生假登出

证据：[`internal/httpserver/auth_handlers.go:188`](../internal/httpserver/auth_handlers.go#L188)、[`internal/session/service.go:54`](../internal/session/service.go#L54)

`POST /logout` 将 `Authenticate` 返回的所有错误都当作未认证，清除主 Cookie 并跳回登录页。但 `Authenticate` 会透传数据库查询和 Session touch 错误。

影响：数据库故障期间，用户看到类似成功退出的结果，浏览器丢失 Session Cookie，但服务端 Session、Refresh family 和 Access metadata 均未撤销。

建议：只有 `session.ErrUnauthenticated` 可以清除陈旧 Cookie；基础设施错误必须保留 Cookie 并返回 5xx。主 Cookie 只能在 Session binding 级联与 Audit 成功提交后清除。

#### H-03 示例 RP 并发刷新会触发 Refresh family reuse

证据：[`examples/oidc-client/server.go:479`](../examples/oidc-client/server.go#L479)、[`examples/oidc-client/server.go:495`](../examples/oidc-client/server.go#L495)、[`examples/oidc-client/server.go:499`](../examples/oidc-client/server.go#L499)

两个并发 `/refresh` 请求可以在本地 CAS 之前读取并提交同一代 Refresh Token。Provider 正确地把第二次提交视为 reuse 并撤销整个 family；失败请求随后按 Session ID 清除 Refresh，又可能覆盖成功请求保存的 replacement。

该端点还是 GET，并由普通链接触发。`SameSite=Lax` Cookie 会随跨站顶层 GET 发送，浏览器预取、重复导航或诱导式导航均可触发状态变更。

建议：改为带 CSRF 和 Origin/Referer 校验的 POST；在请求 Provider 前，按 Session/version 原子声明 refresh in-flight，重复请求不得到达 Provider；提交和清值都必须校验同一 attempt/version。

#### H-04 示例 RP 的旧 Session 快照可覆盖新 Token

证据：[`examples/oidc-client/server.go:105`](../examples/oidc-client/server.go#L105)、[`examples/oidc-client/server.go:357`](../examples/oidc-client/server.go#L357)、[`examples/oidc-client/server.go:384`](../examples/oidc-client/server.go#L384)

`memorySessions.save` 只检查 Session ID 和有效期，然后整份覆盖当前记录。`beginLogin` 在锁外读取旧快照后，与 refresh/logout 并发时可恢复已消费的 Refresh Token、擦除 replacement 或覆盖新的 logout state。

建议：使用锁内字段级更新，或给完整 Session 增加版本并执行 CAS；禁止把任意旧快照直接保存为当前状态。

### 3.2 中风险

#### M-01 移除 `offline_access` 会误撤销全部在线 Access Token

证据：[`internal/storage/postgres/client.go:121`](../internal/storage/postgres/client.go#L121)、[`queries/token.sql:249`](../queries/token.sql#L249)

Client disable 与移除 `offline_access` 共用 `RevokeLiveAccessTokensByClient`。该查询没有限制 `refresh_family_id IS NOT NULL`，因此普通 Authorization Code Flow 签发的在线 Access Token 也会被撤销。

建议：拆分两种级联。Client disable 可撤销全部 live Access；移除 offline Scope 只撤销 family 及 family-linked Access。

#### M-02 RP Logout 将基础设施错误错误映射为终态

证据：[`internal/httpserver/logout_handlers.go:67`](../internal/httpserver/logout_handlers.go#L67)、[`internal/httpserver/logout_handlers.go:73`](../internal/httpserver/logout_handlers.go#L73)、[`internal/httpserver/logout_handlers.go:112`](../internal/httpserver/logout_handlers.go#L112)

认证查询、Bind、Complete 的数据库/Audit/锁错误被统一映射为 `already_signed_out` 或 4xx，并清除 transient Cookie。

影响：用户可能收到错误的退出状态，主 Session 仍有效，同时原 logout transaction 被销毁而无法重试。

建议：区分未认证、not found、CSRF、capacity 和基础设施错误。未分类基础设施错误应返回 5xx，并保留可安全重试的 transient Cookie。

#### M-03 Migration 13 的 Code detach 契约不可执行

证据：[`migrations/00013_refresh_families_and_access_lifecycle.sql:149`](../migrations/00013_refresh_families_and_access_lifecycle.sql#L149)、[`migrations/00013_refresh_families_and_access_lifecycle.sql:161`](../migrations/00013_refresh_families_and_access_lifecycle.sql#L161)、[`migrations/00013_refresh_families_and_access_lifecycle.sql:211`](../migrations/00013_refresh_families_and_access_lifecycle.sql#L211)

FK 对 `authorization_code_id` 声明 `ON DELETE SET NULL`，但 `access_tokens_source_valid` 和 authority trigger 又要求 Code-sourced Access 永远有非空 Code ID。删除 Code 时会触发约束失败。

影响：文档声明的 Code 独立清理和 detached source 表示无法成立；当前清理只能通过保留 Code 来绕开冲突。

建议：允许 FK 驱动的受控 detach，并把完整 authority 校验限定到 INSERT/非 detach 更新；否则取消 `SET NULL` 并同步修正迁移、清理和文档契约。

#### M-04 Refresh introspection 返回了禁止字段

证据：[`internal/token/lifecycle.go:190`](../internal/token/lifecycle.go#L190)

active Refresh introspection 返回 `token_type: "refresh_token"`，而冻结的 ADR 字段矩阵要求 Refresh 响应省略 `token_type` 和 `aud`。

建议：删除该字段，并为 Access/Refresh active response 增加精确 JSON 快照和字段 allowlist 测试。

#### M-05 Refresh Token 未纳入最终隐私过滤

证据：[`internal/observability/logger.go:17`](../internal/observability/logger.go#L17)、[`scripts/check-sensitive-examples.sh:56`](../scripts/check-sensitive-examples.sh#L56)、[`scripts/check-conformance-record.py:75`](../scripts/check-conformance-record.py#L75)

logger 和两个静态提交门禁只匹配 `ois_sec_v1_` 与 `[spct]1_`，遗漏 Phase 4 的 `r1_`。当 clear Refresh Token 出现在非敏感键的字符串、错误文本、文档或 Conformance 模板中时，这些最后防线会放行。

建议：统一维护 opaque credential pattern，并增加非结构化日志、Markdown 和 Phase 4 JSON 模板回归测试。

#### M-06 panic recovery 会把完整栈写入常规日志

证据：[`internal/httpserver/middleware.go:108`](../internal/httpserver/middleware.go#L108)

恢复中间件记录 `debug.Stack()`，与 Phase 4 固定隐私边界中“普通日志不含 stack trace”直接冲突。

建议：只记录固定 panic 分类和 request ID；测试应断言日志不含 panic 值、栈和敏感 canary。

#### M-07 Basic Client 认证缺少端点级长度和控制字符边界

证据：[`internal/oidc/token_request.go:177`](../internal/oidc/token_request.go#L177)

Basic Header 在长度检查前直接 Base64 解码，解码和 percent-unescape 后也没有拒绝 NUL/控制字符。服务允许的 Header 上限最高为 16 MiB。

建议：解码前设置紧限制；解码和 unescape 后拒绝 NUL/控制字符；补超长、原始 NUL 和 `%00` 测试。

#### M-08 生命周期与 Logout 操作没有服务端执行 deadline

证据：[`internal/httpserver/token_handlers.go:53`](../internal/httpserver/token_handlers.go#L53)、[`internal/httpserver/lifecycle_handlers.go:31`](../internal/httpserver/lifecycle_handlers.go#L31)、[`internal/httpserver/logout_handlers.go:29`](../internal/httpserver/logout_handlers.go#L29)

这些路径直接传递 `request.Context()`。HTTP `WriteTimeout` 只约束响应写入，不能保证取消卡在 PostgreSQL 锁等待中的事务。

建议：增加有界 operation timeout 或数据库 statement/lock timeout，并验证阻塞事务被取消且不提交半状态。

#### M-09 管理 OpenAPI 的 Audit 契约落后于实现

证据：[`api/openapi.yaml:1342`](../api/openapi.yaml#L1342)、[`internal/audit/audit.go:93`](../internal/audit/audit.go#L93)、[`scripts/check-openapi.sh:13`](../scripts/check-openapi.sh#L13)

OpenAPI 缺少 Phase 3/4 的 Authorization、Code、Consent、Token、Signing Key 事件，多种 target 和 changed field。路径门禁也没有检查两个 Grant API。

影响：服务器可返回合法事件，但生成客户端和响应校验器会认为其违反 schema；删除 Grant API 规范路径也可能继续通过静态 gate。

建议：让 OpenAPI、Go 白名单和数据库 CHECK 由自动集合一致性测试约束，并补充 Grant API 必需路径。

#### M-10 示例 RP 的默认登出回调不可用

证据：[`examples/oidc-client/config.go:49`](../examples/oidc-client/config.go#L49)、[`examples/oidc-client/server.go:555`](../examples/oidc-client/server.go#L555)

未设置 `EXAMPLE_POST_LOGOUT_REDIRECT_URI` 时，默认复用授权回调 `/callback`；但 logout state 只由 `/logged-out` 处理。按 README 的 native 示例启动时，Provider 返回 `/callback?state=...`，RP 会拒绝且无法销毁本地 Session。

建议：将该变量设为必填，或从同源 URL 可靠派生 `/logged-out`，并补配置和文档测试。

#### M-11 示例 RP 未按实际 granted Scope 判断 Refresh Token

证据：[`examples/oidc-client/provider.go:135`](../examples/oidc-client/provider.go#L135)

Refresh Token 是否必须出现取决于配置请求 Scope，而不是 Token response 的实际 granted Scope。Provider 合法缩减 `offline_access` 时会被拒绝；响应 Scope 未包含 offline access 但携带 Refresh Token 时又会被保存。

建议：先解析和验证 response Scope，再依据实际 granted Scope 决定 Refresh Token 的必须/禁止关系。

### 3.3 中低与低风险

#### L-01 活跃 Refresh family Gauge 永远为零

证据：[`internal/observability/metrics.go:236`](../internal/observability/metrics.go#L236)、[`internal/app/app.go:220`](../internal/app/app.go#L220)

Gauge 已注册并公开，但 `SetActiveRefreshFamilies` 没有生产调用，形成监控假阴性。应实现有界计数更新，或在不能可靠维护前移除该指标。

#### L-02 Revocation/Introspection HTTP 指标归入 `unmatched`

证据：[`internal/httpserver/middleware.go:77`](../internal/httpserver/middleware.go#L77)

固定 route label 列表遗漏 `/oauth2/revoke` 与 `/oauth2/introspect`。这不会造成高基数，但会掩盖关键生命周期端点的请求量、状态和延迟。

#### L-03 本地 `/logout` 接受并忽略 query 参数

证据：[`internal/httpserver/auth_handlers.go:280`](../internal/httpserver/auth_handlers.go#L280)

`ParseForm` 会合并 query，但校验只遍历 `PostForm`。携带有效 CSRF body 的 `/logout?post_logout_redirect_uri=...` 仍会退出。当前不会外跳，但违反本地 Logout 与 RP Logout 的严格独立 schema。

#### L-04 启动末尾的管理员状态查询没有 deadline

证据：[`internal/app/app.go:142`](../internal/app/app.go#L142)

Key、迁移和启动 Audit 都有 10 秒上下文，但 `store.HasAdmin(ctx)` 直接使用进程生命周期 context。数据库在该阶段黑洞或锁等待时，进程可能在监听前无限挂起。

#### L-05 Web 管理页移动端横向溢出

证据：[`web/src/index.css:5255`](../web/src/index.css#L5255)、[`web/src/components/AdminShell.tsx:194`](../web/src/components/AdminShell.tsx#L194)

真实 Chrome 在 `390x844` 下测得 `/admin` 的 `scrollWidth=624`、`/admin/users` 的 `scrollWidth=725`，均超过 390px 视口。桌面和其他已测移动路由未发现同类溢出。

#### L-06 Modal 与 User Drawer 缺少完整焦点管理

证据：[`web/src/components/ui.tsx:105`](../web/src/components/ui.tsx#L105)、[`web/src/pages/admin/UsersPage.tsx:42`](../web/src/pages/admin/UsersPage.tsx#L42)

Modal 虽声明 `aria-modal=true`，但没有初始焦点、Focus Trap、Escape 关闭或关闭后恢复焦点；User Drawer 还缺少 dialog 语义。键盘用户可继续操作被遮挡的背景内容。

## 4. 完整测试结果

### 4.1 宿主机门禁

| 门禁 | 结果 | 说明 |
| --- | --- | --- |
| `make contract-check` | PASS | migrations、敏感示例、Conformance scaffold、文档链接、actionlint、OpenAPI 均通过 |
| Go format/generated/migration checks | PASS | gofmt、sqlc generation、迁移校验和通过 |
| `go vet ./...` | PASS | 无失败 |
| golangci-lint | PASS | 0 issues |
| `go test -race ./...` | PASS | 全部 Go 单元、race 和 Testcontainers PostgreSQL 测试通过 |
| `make integration-test` | PASS | PostgreSQL integration 及相关 app/httpserver 包通过 |
| Fuzz smoke | FAIL | `FuzzParseAuthorizationRequest` 在 1 秒 smoke 中返回 `context deadline exceeded` |
| `make vuln` | PASS | 可达代码漏洞为 0；依赖图存在未被当前代码调用的 advisory |
| `make build` | PASS | 成功生成静态 `bin/oneissuer` |
| `make web-check` | PASS | oxlint、`tsc -b`、Vite build、npm audit 全部通过；npm 报告 0 vulnerabilities |
| `git diff --check` | PASS | 无空白错误 |

由于 Fuzz smoke 失败，顶层 `make check` 整体结果仍是 **FAIL**。其后置的 vulnerability、build 和 Web gate 已单独各补跑一次并通过，没有重跑已经通过的测试。

失败入口：[`internal/oidc/authorize_fuzz_test.go:8`](../internal/oidc/authorize_fuzz_test.go#L8)、[`scripts/fuzz-smoke.sh:20`](../scripts/fuzz-smoke.sh#L20)。本轮没有通过重复执行来掩盖该失败，需要后续判断是 1 秒预算抖动还是 parser/resolver 存在阻塞路径。

### 4.2 Compose 与供应链

| 门禁 | 结果 | 说明 |
| --- | --- | --- |
| `make phase-4-smoke` | PASS | Schema 14、Bootstrap、Public/Confidential A/B、Consent、Refresh、Revocation、Introspection、Grant、RP Logout、PKCE、禁用、重启、故障恢复、隐私和优雅关闭通过 |
| CycloneDX SBOM | PASS | 162 个组件，SBOM 校验成功 |
| Trivy High/Critical scan | BLOCKED | 漏洞数据库下载约 29.6% 后，在 5 分钟处 `context deadline exceeded`；没有生成本轮报告 |
| `make container-check` | FAIL | SBOM 通过，但因 Trivy 外部数据库下载超时整体失败 |

本轮没有发现容器扫描结果中的漏洞，因为扫描根本没有开始完成。`.artifacts/supply-chain/trivy-high-critical.json` 是旧报告，不能作为当前工作树证据。

测试结束后没有残留 `oneissuer-*` 容器或 PostgreSQL volume。项目镜像、Trivy 镜像和 `oneissuer-trivy-cache` 下载缓存卷仍保留；未做破坏性清理。

### 4.3 真实 Chrome

测试使用现有可见 Chrome 的 DevTools auto-connect，并在独立 browser context 中执行；用户原有页面未关闭。

覆盖视口：

- Desktop：`1440x900`；
- Mobile：`390x844`。

覆盖路由：

- `/login`、`/register`、`/consent`；
- `/account`、`/account/applications`；
- `/admin`、`/admin/users`、`/admin/applications/new`。

验证结果：

- 路由导航和 accessibility snapshot 均成功；
- 语言切换、移动菜单抽屉、应用撤销状态更新和创建应用表单填写成功；
- 控制台无 error/warn；
- 135 个本地 Vite 网络请求均为 200/304，无失败请求；
- `/admin` 与 `/admin/users` 在移动视口存在横向溢出；
- 测试页面和本轮启动的 Vite 进程已安全关闭，用户基线页面和已有其他 Vite 进程未受影响。

### 4.4 Conformance 状态

Phase 4 Conformance 仍是仓库中明确标记的 `NOT_RUN` scaffold。`make contract-check` 通过仅证明 matrix/result 模板、适用模块和非认证声明没有漂移，不代表官方 OpenID/OAuth Conformance 模块已经执行或通过。

## 5. 关键测试缺口

1. 缺少 populated schema 11 → 14 的迁移样本。现有升级测试从 schema 5 开始，没有 schema-11 active/expired Grant、Code、Access 和 Session authority；
2. 缺少账号 A → B 登录、A → 注册 B、同主体 rotation、被动 expiry 的真实 PostgreSQL lineage 测试；
3. 缺少移除 `offline_access` 时保留普通在线 Access Token 的对照测试；
4. 缺少 Logout repository 的 bind cap、并发 confirm/cancel、stale CSRF、cookie overwrite、Audit/commit rollback 和 Session/family cascade 集成测试；
5. 并发矩阵仍缺 Refresh↔User disable、Code issue↔Grant revoke、cleanup↔reuse 的强制锁区间交错；
6. Refresh、Grant cascade、Client/User cascade 和 Logout 缺 signer/Audit/insert/deferred-commit 故障注入；
7. 示例 RP 测试没有直接调用 refresh handler，也没有 login/refresh/logout 的受控并发交错；Compose smoke 的 Refresh 测试主要直接调用 Provider Token endpoint；
8. 缺少真实浏览器 two-tab、cookie overwrite、stale form、cookie loss、SameSite continuation、cancel 和 terminal replay 自动化矩阵；
9. Web 没有自动化交互或可访问性测试；
10. Phase 4 官方 Conformance 尚未执行。

## 6. 建议修复顺序

### 第一优先级：authority 正确性

1. 修复账号切换/注册对旧 Session binding 的原子级联；
2. 修复本地 Logout 的基础设施错误分类和 Cookie 清理顺序；
3. 修复 RP Logout 的错误分类、事务保留和 5xx 行为；
4. 补相应真实 PostgreSQL、故障注入和双向竞态测试。

### 第二优先级：示例 RP 与协议契约

1. 重做示例 RP 的 refresh 串行化、版本 CAS、POST+CSRF；
2. 修复 Session 旧快照覆盖、默认 logout redirect 和 actual granted Scope 判断；
3. 修复 Refresh introspection 字段；
4. 拆分 Client disable 与 offline Scope removal 的 Access cascade。

### 第三优先级：迁移、隐私和可观测性

1. 统一 Migration 13 的 Code detach、CHECK、trigger、cleanup 和文档语义；
2. 将 `r1_` 纳入所有隐私扫描并移除常规 panic stack；
3. 同步 OpenAPI、Audit 白名单和路径门禁；
4. 修复 active family Gauge、生命周期 route label、操作 deadline 和 Basic Header 上限。

### 第四优先级：发布门禁

1. 定位并稳定 Fuzz smoke 超时；
2. 使用可用的 Trivy DB mirror/cache 重新完成当前镜像扫描；
3. 完成真实浏览器 Logout 边缘矩阵；
4. 执行并记录 Phase 4 适用 Conformance 模块；
5. 在发布前统一将 Phase 4 artifact/version 从 `v0.1.0-dev.3` 切换到目标 `v0.1.0-dev.4`。

## 7. 本轮变更与产物

本轮审查没有修改应用源码、配置、迁移或测试。测试过程生成或更新了以下忽略产物：

- `bin/oneissuer`；
- `web/dist/`；
- `.artifacts/supply-chain/oneissuer.cdx.json` 及其校验文件；
- Docker 项目镜像和 Trivy 数据库缓存卷。

测试脚本已清理 Compose 容器和项目数据库卷。由于本轮任务是审查与测试，没有对上述发现实施修复。
