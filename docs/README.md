# OneIssuer 文档索引

| 文档 | 状态 | 说明 |
| --- | --- | --- |
| [`go-backend-design.md`](./go-backend-design.md) | Draft | Go 后端总体架构、协议、安全和 `v0.1` 范围 |
| [`ui-design.md`](./ui-design.md) | Draft | 认证页、个人中心和管理控制台的 UI 原型说明 |
| [`phase-1-development-plan.md`](./phase-1-development-plan.md) | Implemented and verified | 第一阶段工程基础的任务、测试与验收计划 |
| [`phase-2-development-plan.md`](./phase-2-development-plan.md) | Implemented and verified | 第二阶段身份、凭证、Session、Client、管理员与审计计划 |
| [`phase-2-threat-model.md`](./phase-2-threat-model.md) | Implemented | 第二阶段资产、信任边界、威胁、控制和残余风险 |
| [`adr/0001-phase-two-identity-and-client-security.md`](./adr/0001-phase-two-identity-and-client-security.md) | Accepted | 身份规范化、密码、Session、Client、审计与协议边界决策 |
| [`development.md`](./development.md) | Implemented | 本地开发、工具、测试和构建流程 |
| [`configuration.md`](./configuration.md) | Implemented | 环境变量、安全校验、脱敏与代理信任 |
| [`migrations.md`](./migrations.md) | Implemented | 显式 Goose 迁移与 sqlc 生成规则 |
| [`troubleshooting.md`](./troubleshooting.md) | Implemented | 启动、数据库、迁移、就绪和关闭排障 |
| [`operations.md`](./operations.md) | Implemented | Bootstrap、发布、备份/恢复、清理和审计保留策略 |
| [`phase-1-release-notes.md`](./phase-1-release-notes.md) | Verified | 第一阶段交付与验收证据记录 |
| [`phase-2-release-notes.md`](./phase-2-release-notes.md) | Verified | 第二阶段迁移、能力、安全边界与执行证据 |
| [`phase-3-handoff.md`](./phase-3-handoff.md) | Accepted freeze | 第三阶段协议适配必须复用的领域接口和禁用捷径 |
| [`phase-3-development-plan.md`](./phase-3-development-plan.md) | Planned | 第三阶段 OIDC 主流程的范围、安全剖面、任务和验收计划 |

## 推荐阅读顺序

1. 先阅读 Go 总体方案，理解单 Issuer、非多租户和 OIDC 协议边界；
2. 再阅读 UI 设计，了解用户流程、页面路由和前后端接口映射；
3. 查阅第一阶段开发计划与 Release Notes，了解已交付的稳定边界；
4. 阅读第二阶段威胁模型、ADR 与 Release Notes，核对已实现安全边界；
5. 阅读已接受的第三阶段交接文档，确认协议层不可绕过的领域契约；
6. 按第三阶段开发计划先完成 ADR、威胁模型和依赖 Spike，再开始 OIDC 协议实现。

第一阶段只是工程基础；第二阶段实现了身份与 Client 基础，但仍不等于可供业务系统接入的
完整 OIDC Provider。Discovery、JWKS、Authorize、Token 和 UserInfo 从第三阶段开始。
