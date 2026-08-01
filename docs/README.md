# OneIssuer 文档索引

| 文档 | 状态 | 说明 |
| --- | --- | --- |
| [`go-backend-design.md`](./go-backend-design.md) | Draft | Go 后端总体架构、协议、安全和 `v0.1` 范围 |
| [`ui-design.md`](./ui-design.md) | Draft | 认证页、个人中心和管理控制台的 UI 原型说明 |
| [`phase-1-development-plan.md`](./phase-1-development-plan.md) | Implemented and verified | 第一阶段工程基础的任务、测试与验收计划 |
| [`phase-2-development-plan.md`](./phase-2-development-plan.md) | Implemented and verified | 第二阶段身份、凭证、Session、Client、管理员与审计计划 |
| [`phase-2-threat-model.md`](./phase-2-threat-model.md) | Implemented | 第二阶段资产、信任边界、威胁、控制和残余风险 |
| [`adr/0001-phase-two-identity-and-client-security.md`](./adr/0001-phase-two-identity-and-client-security.md) | Accepted | 身份规范化、密码、Session、Client、审计与协议边界决策 |
| [`development.md`](./development.md) | Implemented | 阶段三本地开发、完整门禁、Conformance 与供应链流程 |
| [`configuration.md`](./configuration.md) | Implemented | 环境变量、Canonical Issuer、签名 Key、TTL、安全校验与代理信任 |
| [`migrations.md`](./migrations.md) | Implemented | 版本 1–10 显式 Goose 迁移、升级、清理与 sqlc 规则 |
| [`troubleshooting.md`](./troubleshooting.md) | Implemented | Key、Discovery/JWKS、Authorize/Token/UserInfo、数据库与容器排障 |
| [`operations.md`](./operations.md) | Implemented | 发布、Bootstrap、备份/恢复、at-most-once、清理和事故处置 |
| [`key-rotation-runbook.md`](./key-rotation-runbook.md) | Implemented | RS256 Key 生成、预发布、重启式 overlap、移除与紧急撤销 |
| [`oidc-client-integration.md`](./oidc-client-integration.md) | Implemented | Public/Confidential RP 的 S256、Token 校验、UserInfo 与错误处理 |
| [`phase-1-release-notes.md`](./phase-1-release-notes.md) | Verified | 第一阶段交付与验收证据记录 |
| [`phase-2-release-notes.md`](./phase-2-release-notes.md) | Verified | 第二阶段迁移、能力、安全边界与执行证据 |
| [`phase-3-handoff.md`](./phase-3-handoff.md) | Accepted freeze | 第三阶段协议适配必须复用的领域接口和禁用捷径 |
| [`phase-3-development-plan.md`](./phase-3-development-plan.md) | Implemented and verified | 第三阶段 OIDC 主流程的范围、安全剖面、任务和验收计划 |
| [`phase-3-threat-model.md`](./phase-3-threat-model.md) | Accepted | 第三阶段协议、签名密钥、Code、Token、Consent 和 UserInfo 威胁与控制 |
| [`phase-3-dependency-spike.md`](./phase-3-dependency-spike.md) | Accepted | Fosite/go-jose 版本、适配边界、漏洞与 Conformance Spike 记录 |
| [`adr/0002-phase-three-oidc-security-profile.md`](./adr/0002-phase-three-oidc-security-profile.md) | Accepted | 第三阶段协议剖面、依赖、密钥、Token、原子性与延期能力决策 |
| [`phase-3-conformance.md`](./phase-3-conformance.md) | Applicable subset passed | 固定 Suite/镜像、适用模块、结果证据、限制与非认证声明 |
| [`phase-3-release-notes.md`](./phase-3-release-notes.md) | Verified | 阶段三能力、迁移、安全边界、升级与最终验收记录 |

## 推荐阅读顺序

1. 先阅读 Go 总体方案，理解单 Issuer、非多租户和 OIDC 协议边界；
2. 再阅读 UI 设计，了解用户流程、页面路由和前后端接口映射；
3. 查阅第一阶段开发计划与 Release Notes，了解已交付的稳定边界；
4. 阅读第二阶段威胁模型、ADR 与 Release Notes，核对已实现安全边界；
5. 阅读已接受的第三阶段交接文档，确认协议层不可绕过的领域契约；
6. 阅读第三阶段 ADR、威胁模型和依赖 Spike，确认协议与依赖边界；
7. 阅读 OIDC Client 接入指南、Key Runbook 与 Conformance 限制；
8. 查阅第三阶段开发计划和 Release Notes 的最终门禁与验收记录。

第一阶段是工程基础，第二阶段实现身份与 Client 基础；第三阶段已实现并验证 Discovery、JWKS、
Authorize、Token、UserInfo 及强制 S256 Code Flow。它仍不包含 Refresh、Revoke、
Introspection 或 RP Logout，也不代表生产就绪或 OpenID Foundation 认证。
