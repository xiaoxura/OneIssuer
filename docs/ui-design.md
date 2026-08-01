# OneIssuer UI 设计与原型说明

> 状态：Draft  
> 原型目录：`web/`  
> 目标：在 Go 后端开发前确定认证流程、个人中心、管理控制台的信息架构和视觉语言

## 1. 设计目标

OneIssuer 的界面分为三类：

1. **Hosted Authentication UI**：面向最终用户的登录、注册、授权确认页面；
2. **Account Center**：面向当前登录用户的资料、安全、授权应用和设备管理页面；
3. **Admin Console**：面向平台管理员的用户、应用、会话、审计和系统配置页面。

界面需要传达以下产品感受：

- **可信**：用户能清楚看到当前由谁认证、将进入哪个应用、将共享哪些信息；
- **克制**：避免使用夸张插画和大量渐变，不让视觉效果干扰安全操作；
- **开发者友好**：Client ID、Issuer、Redirect URI 和 Token 配置容易查找和复制；
- **一致**：认证页面与管理控制台共享品牌、颜色、间距和交互反馈；
- **可扩展**：后续可加入 MFA、Passkey、上游身份源和主题定制，而无需重做布局。

## 2. 产品定位与视觉方向

视觉关键词：

```text
Pure white · Quiet confidence · Secure infrastructure · Developer first
```

当前主题采用纯白与中性黑灰体系：

- 页面、侧栏、顶栏和主要面板均使用纯白背景，以浅灰边框建立层级；
- 主要按钮、当前导航和品牌标记使用接近黑色的中性色，不使用大面积深色背景；
- 认证页左侧仅保留极浅网格和单色身份轨道，不使用彩色渐变；
- 成功、警告、危险和信息状态保留克制的绿、琥珀、红、蓝色，因为这些颜色承担语义；
- 彩色头像和应用标记仅用于区分实体，不参与主要页面配色；
- 不使用颜色作为状态的唯一表达，同时保留文字、图标和形状。

Logo 原型将字母 `O` 的圆环和 Issuer 的签发/钥匙概念组合，形成圆环加钥匙柄的标记。
当前 Logo 以 React 内联 SVG 和 `favicon.svg` 实现，后续可独立输出正式矢量文件。

## 3. 信息架构

### 3.1 认证页面

| 路由 | 页面 | 目标 |
| --- | --- | --- |
| `/login` | 登录 | 使用 OneIssuer 账号继续进入来源应用 |
| `/register` | 注册 | 从来源应用发起全局账号创建 |
| `/consent` | 授权确认 | 清楚展示 Client 请求的 Scope/Claim |
| `/complete` | 完成状态 | 原型中展示授权完成和身份连接结果 |

真实接入后，`/complete` 通常会被 Client 的 Redirect URI 替代，不属于 OIDC 标准端点。

### 3.2 个人中心

| 路由 | 页面 | 目标 |
| --- | --- | --- |
| `/account` | Overview | 展示当前用户资料、账号摘要和最近身份活动 |
| `/account/security` | Security | 管理密码、Passkey、TOTP、恢复代码与安全建议 |
| `/account/applications` | Applications | 查看 Scope、最近使用情况并逐个撤销应用授权 |
| `/account/sessions` | Sessions | 查看当前用户自己的设备会话并单独或批量退出 |

个人中心只允许操作当前登录主体自己的资源，不提供用户目录、Client 配置、全局审计或 Issuer 设置。
管理员也可以进入自己的个人中心，但管理权限与个人账号能力必须在后端授权层严格分离。

### 3.3 管理控制台

| 路由 | 页面 | 目标 |
| --- | --- | --- |
| `/admin` | Overview | 登录数据、系统健康和最近活动 |
| `/admin/users` | Users | 搜索、筛选、创建和查看用户身份 |
| `/admin/applications` | Applications | 查看所有 OIDC Client |
| `/admin/applications/new` | New Application | 创建 Client、配置类型和 Redirect URI |
| `/admin/sessions` | Sessions | 查看和撤销登录会话 |
| `/admin/audit` | Audit Log | 查询安全与管理事件 |
| `/admin/settings` | Issuer Settings | 配置规范 Issuer URL 与发现地址 |
| `/admin/settings/registration` | Registration Settings | 配置自助注册、邮箱验证与默认应用策略 |
| `/admin/settings/authentication` | Authentication Settings | 配置密码、上游身份源与 Passkey 登录方式 |
| `/admin/settings/tokens` | Token Settings | 配置 ID、Access 与 Refresh Token 有效期 |
| `/admin/settings/keys` | Signing Key Settings | 查看和轮换当前签名密钥 |

原型不展示 Organization、Tenant 或 Realm，因为 OneIssuer 当前明确为单 Issuer、非多租户产品。

## 4. 页面布局

### 4.1 认证体验

桌面端采用左右分栏：

```text
┌──────────────────────────┬────────────────────────────────┐
│ OneIssuer 品牌与价值信息 │ 来源 Client 上下文             │
│ 身份连接视觉             │ 登录/注册/Consent 主操作       │
│ 安全说明                 │ 原型页面导航和法律链接         │
└──────────────────────────┴────────────────────────────────┘
```

设计约束：

- 表单始终由 OneIssuer Origin 托管；
- 页面明确显示 `Continue to <Client Name>`；
- 密码字段附近解释密码不会提供给 Client；
- Consent 页面同时显示应用、当前账号和每一项授权内容；
- 取消与同意操作必须有清晰层级，不能使用诱导式设计；
- 移动端隐藏左侧品牌面板，将 Logo 移至表单顶部；
- 原型底部的 `Prototype` 导航仅用于设计评审，生产模式必须移除。
- 登录、注册和授权确认属于阅读与决策任务，表单工作区继续限制在约 `500px`，不会为了“全宽”而拉伸输入框。

### 4.2 个人中心

个人中心在桌面端采用品牌顶栏、左侧菜单栏和路由级内容区，不再把资料、安全、应用与会话的全部数据堆放在同一页面：

```text
┌─────────────────────────────────────────────────────────────┐
│ Brand                                      Language · Account│
├──────────────┬──────────────────────────────────────────────┤
│ Account      │ Current route header · route-specific action │
│ Overview     │ Overview / Security / Application cards      │
│ Security     │ Session cards and focused management content │
│ Applications │                                              │
│ Sessions     │                                              │
└──────────────┴──────────────────────────────────────────────┘
```

- 桌面端左侧菜单宽度为 `240px`，固定展示概览、安全、应用和会话入口，并高亮当前路由；
- 左侧菜单粘在 `72px` 品牌顶栏下方，底部展示当前账号保护状态；
- 主工作区使用全部可用宽度，仅保留 `24–48px` 的响应式页面边距，不设置窄版最大宽度；
- `/account` 概览使用约 `340px` 的资料栏和可伸缩摘要区，其他三个路由只呈现各自主题；
- 安全页桌面端使用“主要安全方式 + `340px` 建议栏”，应用页和会话页使用三列卡片网格；
- 个人资料、安全方式、授权应用和会话操作均限制在当前主体范围；
- 应用授权明确展示 Scope，并允许用户逐个撤销；
- 当前设备不可被误操作撤销，其他会话可单独或批量退出；
- `901–1180px` 时仍保留左侧菜单，概览资料卡改为横向布局，安全建议栏下移，应用与会话卡片改为两列；
- 小于 `900px` 时左侧菜单转换成顶栏下方可横向滚动的粘性菜单，避免占用手机内容宽度；
- 小于 `780px` 后概览改为单列；
- 小于 `560px` 时应用与会话卡片改为单列并占满容器宽度；
- 横向菜单会自动将当前路由滚动到可见区域，不压缩品牌和账号操作。

### 4.3 管理控制台

桌面端采用固定侧栏、粘性顶栏和内容工作区：

```text
┌──────────────┬───────────────────────────────────────────┐
│ Brand        │ Breadcrumb · Search · Account            │
│ Workspace    ├───────────────────────────────────────────┤
│ Navigation   │ Page title · Description · Actions        │
│              │ Metrics / Panels / Tables / Forms         │
│ System health│                                           │
└──────────────┴───────────────────────────────────────────┘
```

- 侧栏宽度：`250px`；
- 顶栏高度：`68px`；
- 内容工作区使用侧栏之外的全部可用宽度，仅保留响应式页面边距；
- 面板默认圆角：`12px`；
- 管理页使用紧凑信息密度，但交互目标不小于约 `36px`；
- 设置区通过五个独立路由承载 Issuer、注册、认证、令牌和签名密钥配置，左侧二级菜单保持一致；
- 设置页不使用人为撑高的空面板，内容较少时保持自然高度；
- 小于 `1020px` 时侧栏变为抽屉；
- 小于 `780px` 时表格允许横向滚动，页面操作自动换行。

## 5. Design Tokens

Token 当前定义在 `web/src/index.css` 的 `:root` 中。

### 5.1 核心颜色

| Token | 值 | 用途 |
| --- | --- | --- |
| `--ink-950` | `#111113` | 最高层级标题、品牌标记 |
| `--ink-800` | `#27272a` | 主要正文和图标 |
| `--ink-500` | `#62626b` | 次要正文 |
| `--ink-200` | `#e4e4e7` | 边框和分隔线 |
| `--canvas` | `#ffffff` | 页面与管理后台背景 |
| `--paper` | `#ffffff` | 面板、表单背景 |
| `--mint-700` | `#18181b` | 主要按钮、链接、选中状态 |
| `--mint-500` | `#52525b` | 图表和焦点状态 |
| `--mint-100` | `#f1f1f3` | 图标及选中项浅背景 |
| `--amber-500` | `#d99639` | 警告 |
| `--rose-500` | `#d95862` | 错误和危险操作 |

### 5.2 字体

原型不依赖在线字体资源，避免自托管部署时出现第三方请求：

```css
Inter, "Avenir Next", "PingFang SC", "Microsoft YaHei", "Segoe UI", Roboto, Helvetica, Arial, sans-serif
```

代码、Issuer、Client ID 和 URI 使用系统等宽字体。

文字层级：

- 认证主标题：`42–64px`，仅位于桌面端品牌面板；
- 管理页标题：`26–34px`；
- 面板标题：`14–16px`；
- 表格正文：`12–13px`；
- 常规辅助说明：`11–12px`；
- 仅键盘提示、代码摘要等非关键技术元数据可使用 `10–10.5px`，界面文字不低于 `10px`；
- 移动端 SVG 图表文字需补偿 `viewBox` 缩放，确保最终视觉字号不低于约 `10px`。

### 5.3 圆角与阴影

```text
Input / Button       8–9px
Panel                12px
Authentication Card 18px
Modal                16px
```

阴影保持克制。常规面板使用边框和极轻阴影，仅 Modal、Drawer 和浮动保存栏使用明显层级。

## 6. 核心组件

### Brand

- `Brand` 支持默认与深色背景两种模式；
- 可使用 `compact` 只展示标记；
- 文字显示名固定为 `OneIssuer`。

### Button

- `primary`：创建、继续、允许、保存；
- `secondary`：取消、导出、日期筛选；
- `danger-soft`：撤销 Session、暂停用户；
- 禁用状态降低透明度，但仍保留可识别文本。

### Form Field

- Label 永远位于输入框上方；
- 图标用于辅助识别，不替代 Label；
- `focus-within` 使用中性深灰边框和低透明度焦点环；
- 错误信息后续应显示在字段下方，并通过 `aria-describedby` 关联。

### Status Pill

支持：

```text
success · warning · danger · info · neutral
```

每个状态同时包含颜色、圆点和文字。

### Table

- 表头使用大写元数据样式；
- 行 Hover 只表示可交互，不替代选择状态；
- 窄屏允许横向滚动，不强制压缩所有列；
- 用户列表点击行打开右侧详情 Drawer。

### Modal / Drawer

- 点击背景可以关闭原型 Modal/Drawer；
- 生产实现还需加入 Escape 关闭、Focus Trap、打开后自动聚焦和关闭后恢复焦点；
- 危险确认应使用独立确认 Modal，不能只依赖 Toast。

## 7. 关键交互流程

### 7.1 A 网站发起注册

```text
A 注册按钮
→ /oauth2/authorize?...&prompt=create
→ OneIssuer /register
→ 创建全局用户和登录会话
→ 恢复 Authorization Request
→ /consent
→ Redirect URI
→ A 使用 (iss, sub) JIT 创建本地用户
```

原型中通过 `/register → /consent → /complete` 表达该流程。

### 7.2 已有用户登录

```text
/login
→ 用户提交凭证
→ 恢复 Authorization Request
→ 按 Consent 策略决定是否展示 /consent
→ Redirect URI
```

### 7.3 B 网站复用账号

B 必须发起自己的 OIDC Authorization Request，不能复用 A 的 ID Token。OneIssuer 根据已有
SSO Session 省略密码输入，再为 B 产生独立的 Code 和 Token。

### 7.4 管理员创建应用

```text
Applications
→ New application
→ 选择 Web / SPA / Native
→ 设置展示信息
→ 添加精确 Redirect URI
→ 后端生成 Client ID/Secret
→ 只显示一次 Client Secret
```

## 8. 后端接口映射

原型目前全部使用 Mock Data，不会发送真实认证信息。接入 Go 后端时建议映射：

| UI 操作 | 后端能力 |
| --- | --- |
| 登录 | 服务端登录事务，不返回 Token 给页面脚本 |
| 注册 | 绑定 `authorization_request_id` 的注册事务 |
| Consent | Fosite Authorize Request 的 Grant Scope |
| 当前用户资料 | `/api/v1/me` |
| 当前用户认证方式 | `/api/v1/me/authenticators`、WebAuthn 注册事务 |
| 当前用户授权应用 | `/api/v1/me/grants`，撤销时同步失效相关授权与令牌 |
| 当前用户会话 | `/api/v1/me/sessions`，只允许撤销自己的 Session |
| 个人数据归档 | 异步导出任务，下载链接短期有效并要求重新认证 |
| 用户列表 | `/api/admin/v1/users` |
| 应用列表/创建 | `/api/admin/v1/clients` |
| Session 撤销 | `/api/admin/v1/sessions/{id}/revoke` |
| Audit 查询 | `/api/admin/v1/audit-events` |
| 设置 | `/api/admin/v1/settings` |
| Signing Key 轮换 | 高风险管理员操作，需要重新认证 |

认证页面不要把原始 Redirect URI 当作任意 `return_to` 使用。页面只提交服务端生成的短期
事务 ID，后端从数据库恢复已经验证过的 Client、Redirect URI、PKCE、Scope、State 和 Nonce。

## 9. 响应式策略

| Breakpoint | 行为 |
| --- | --- |
| `> 1180px` | 完整桌面布局，四列指标卡片 |
| `1020–1180px` | 指标两列，认证品牌面板收窄；个人中心保留左侧菜单并使用紧凑概览布局 |
| `< 1020px` | 管理侧栏抽屉化；认证页面切换为单栏 |
| `< 960px` | 个人中心应用和会话卡片保持两列 |
| `< 900px` | 个人中心左侧菜单切换为独立横向滚动行；概览摘要卡改为单列 |
| `< 780px` | 操作换行、表格横向滚动、设置二级菜单横向滚动；个人中心概览改为单列 |
| `< 560px` | 指标、表单、个人中心应用与会话卡片改为单列；Consent 按钮纵向排列 |

设计评审至少覆盖以下视口：

```text
1440 × 900  Desktop
1920 × 1080 Wide desktop
1024 × 768  Tablet landscape
390 × 844   Mobile
```

## 10. 可访问性要求

原型已包含语义 Label、按钮类型、基础 ARIA、键盘 Focus 样式和 Reduced Motion 支持。
接入后端并进入正式开发时还需完成：

- 使用自动化工具检查 WCAG 2.2 AA 对比度；
- Modal 和 Drawer 实现 Focus Trap；
- 表单错误使用 `aria-invalid` 和 `aria-describedby`；
- 登录失败信息使用 `aria-live`，但避免泄露账号是否存在；
- 图表提供等价文字摘要或数据表；
- 所有图标按钮提供可本地化的 `aria-label`；
- 确保 200% 浏览器缩放下不会丢失操作；
- 不把 Session 地理位置当作精确事实，应显示其为 IP 推测结果。

## 11. 国际化与主题

原型现已完整支持英文与简体中文，不再在页面 JSX 中硬编码用户可见文案：

- 支持 Locale：`en`、`zh-CN`；
- Locale 解析顺序：用户上次选择（`localStorage`）→ 浏览器语言 → `en`；
- 认证页面、个人中心和管理控制台均提供语言切换入口，切换后立即更新整个界面；
- 翻译资源位于 `web/src/i18n/messages.en.ts` 和
  `web/src/i18n/messages.zh-CN.ts`，中文资源通过 TypeScript 校验，不能遗漏英文基准资源中的 Key；
- 日期、数字和相对时间统一使用 `Intl.DateTimeFormat`、`Intl.NumberFormat` 和
  `Intl.RelativeTimeFormat`，Mock Data 保存语义值而不是已经格式化的英文；
- 页面切换语言时同步更新 `<html lang>`、页面标题、Meta Description 和可访问性文案；
- 产品名、协议术语、Client 展示名、用户名、URL、ID 和算法名称不做强制翻译；
- 后端错误码应继续与用户文案分离，不直接把服务端英文错误显示给最终用户；
- Client 只允许从管理员保存的可信元数据中提供 Logo 和展示名；
- 后续主题功能只开放受限 Token，不允许注入任意 CSS/HTML。

## 12. 原型边界

当前原型用于 UI 和流程评审，不代表功能已经完成：

- 所有用户、应用、Session 和 Audit Event 均为本地 Mock Data；
- 登录和注册表单不会提交密码；
- 创建应用不会生成真实 Client；
- 撤销 Session 只修改当前浏览器中的 React State；
- 个人中心的资料保存、Passkey 添加、Grant 撤销和会话退出只修改本地 React State；
- Settings 保存只展示临时 Toast；
- 原型导航和 `/complete` 页面不应进入最终 Hosted Authentication UI；
- 正式发布前必须重新进行威胁建模、可访问性和 OIDC Conformance 检查。
