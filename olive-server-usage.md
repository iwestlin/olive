# Olive Server 使用指南

`olive server` 是 Olive 直播录制工具的 API 服务模式，提供 HTTP RESTful API 来管理和控制直播录制功能。通过这个服务，你可以程序化地管理多个直播监控任务，适合构建 Web 管理界面或集成到其他系统中。

## 目录

- [快速开始](#快速开始)
- [命令参数详解](#命令参数详解)
- [API 接口文档](#api-接口文档)
- [调试端点](#调试端点)
- [数据库配置](#数据库配置)
- [使用示例](#使用示例)
- [部署建议](#部署建议)
- [常见问题](#常见问题)
- [安全模型与加固](#安全模型与加固)

## 快速开始

### 基本启动

```bash
# 使用默认配置启动服务。
# 自 v0.7.0 起 API/Debug 默认绑定到 127.0.0.1，不对外暴露。
olive server

# 指定日志和视频保存目录
olive server -l /path/to/logs -s /path/to/videos

# 把 API 暴露到所有网卡（请配合 --web-tls-cert/--web-tls-key 使用）
olive server --web-api-host 0.0.0.0:3000 \
            --web-tls-cert /etc/olive/tls.crt \
            --web-tls-key  /etc/olive/tls.key
```

### 查看帮助

```bash
olive server --help
```

## 命令参数详解

### Web 服务器配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--web-api-host` | `127.0.0.1:3000` | API 服务监听地址。默认绑回环，避免管理员凭据裸奔公网；如需对外请配合 TLS 参数 |
| `--web-debug-host` | `127.0.0.1:4000` | 调试服务监听地址。若要绑非回环地址，必须同时配置 `--web-debug-user/--web-debug-pass`，否则启动会被拒绝 |
| `--web-read-timeout` | `5s` | HTTP 请求读取超时时间 |
| `--web-write-timeout` | `10s` | HTTP 响应写入超时时间 |
| `--web-idle-timeout` | `2m0s` | HTTP 连接空闲超时时间 |
| `--web-shutdown-timeout` | `20s` | 服务优雅关闭超时时间 |
| `--web-tls-cert` | 空 | TLS 证书（PEM）路径。**v0.7.0 新增**。与 `--web-tls-key` 同时设置后 API 服务以 HTTPS 启动 |
| `--web-tls-key` | 空 | TLS 私钥（PEM）路径。**v0.7.0 新增**。与 `--web-tls-cert` 同时设置后 API 服务以 HTTPS 启动 |
| `--web-debug-user` | 空 | 调试端点 HTTP Basic-Auth 用户名。**v0.7.0 新增**。为空且 DebugHost 绑回环时不启用 Basic-Auth；为空且 DebugHost 绑非回环时启动被拒绝 |
| `--web-debug-pass` | 空 | 调试端点 HTTP Basic-Auth 密码（在启动日志中被脱敏）。**v0.7.0 新增** |

> 历史 Bug 修复：v0.7.0 之前 `--web-write-timeout`、`--web-idle-timeout`、`--web-shutdown-timeout` 三个 flag 因都绑到 `ReadTimeout` 字段而**同时失效**，现已分别绑到各自对应字段生效

### 数据库配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--db-host` | `localhost` | PostgreSQL 数据库主机地址 |
| `--db-user` | `postgres` | 数据库用户名 |
| `--db-password` | `postgres` | 数据库密码 |
| `--db-name` | `postgres` | 数据库名称 |
| `--db-max-idle-conns` | `0` | 最大空闲连接数（0 表示无限制） |
| `--db-max-open-conns` | `0` | 最大打开连接数（0 表示无限制） |
| `--db-disable-tls` | `true` | 是否禁用 TLS 连接 |

### 目录配置

| 参数 | 短选项 | 说明 |
|------|--------|------|
| `--logdir` | `-l` | 日志文件保存目录 |
| `--savedir` | `-s` | 视频文件保存目录 |

## API 接口文档

所有 API 接口都位于 `/v1/` 路径下，默认监听在 `http://127.0.0.1:3000`。

### 鉴权说明（v0.7.0 新增）

自 v0.7.0 起，olive server 引入了基于 HMAC-SHA256 签名的会话凭据：

- `/v1/user/login`（公开）：校验 `core_config` 中的 `PortalUsername/PortalPassword`，校验通过会 `Set-Cookie: olive_session=...; HttpOnly; SameSite=Lax`，TTL 12 小时。
- `/v1/user/logout`（公开）：清空会话 Cookie。
- `/v1/shows/*`、`/v1/configs/*`（**需鉴权**）：必须携带会话 Cookie 或 `X-Olive-Session` 头；缺失/无效/过期返回 **HTTP 401 Unauthorized**。
- `/v1/test`：保持公开，用于健康探活。
- 登录失败按 (RemoteAddr, Username) 维度计数，连续失败超过 5 次后启用指数退避锁定窗口（500ms → 10min 封顶）。成功登录或 30 分钟无失败记录将清空计数。
- 凭据比较使用 `crypto/subtle.ConstantTimeCompare`，避免时序旁路。
- 默认 `olive/olive` 凭据首次启动时引擎日志会打印一次 WARNING 提示更换。
- 会话密钥在进程内存生成（32 字节随机），**不写入数据库**，进程重启后旧会话全部失效。

> 兼容性提示：与 olive-portal 同源部署时，前端 `axios` 请求会自动带上会话 Cookie，无前端改动；跨域部署需在 `olive-portal/src/config/axios/service.ts` 中加 `withCredentials: true`。

### 直播管理 (`/shows`)（需鉴权）

#### 获取直播列表（分页）
- **URL**: `GET /v1/shows/{pageIndex}/{pageSize}`
- **参数**:
  - `pageIndex`: 页码（从1开始）
  - `pageSize`: 每页数量
- **响应**: 返回分页的直播列表

#### 获取单个直播信息
- **URL**: `GET /v1/shows/{id}`
- **参数**:
  - `id`: 直播记录 ID
- **响应**: 返回指定直播的详细信息

#### 创建直播监控任务（需鉴权）
- **URL**: `POST /v1/shows`
- **请求体**:
  ```json
  {
    "url": "https://www.huya.com/518512",
    "enabled": true,
    "name": "主播名称",
    "platform": "huya"
  }
  ```
- **路径安全（v0.7.0 新增）**：`save_dir`、`out_tmpl` 字段会走 `validate.CheckSafePath` 校验，禁止：
  - 包含 `..` 路径段（跨 OS 的 `/`、`\` 分隔符均识别）
  - 绝对路径（以 `/` 或 `\` 起头）
  - 包含 NUL 字节
  - 校验失败会返回 `HTTP 400`,错误标识 `SaveDir/OutTmpl contains an unsafe path`
- **PostCmds 白名单（v0.7.0 新增）**：`post_cmds` 字段必须是一个 JSON 数组，每个元素的 `path` 仅允许下列值：
  - `olivetrash`：删除录制文件
  - `olivearchive`：归档到录制目录下 `archive/` 子目录
  - `olivebiliup`：调用内置 biliup 上传
  - `oliveshell`：运行 `args` 数组中指定的二进制（要求 `args` 非空，引擎会注入 `FILE_PATH=<录制文件路径>` 到子进程环境）
  - 任何其它 `path`（例如 `/bin/sh`、`local-script.sh`）会被 `validate.CheckPostCmds` 拒绝，并且在引擎运行时 `Uploader.DefaultHandlerFunc` 会兜底返回 "refusing to execute unknown post cmd"，关闭历史 RCE。
- **请求体大小限制（v0.7.0 新增）**：所有 JSON 请求体在 `web.Decode` 包裹一层 `http.MaxBytesReader(1 MiB)`，超过会返回 400。
- **响应**: 返回创建的直播记录

#### 更新直播配置
- **URL**: `PUT /v1/shows/{id}`
- **参数**:
  - `id`: 直播记录 ID
- **请求体**: 更新字段的 JSON 对象
- **响应**: 返回更新后的直播记录

#### 删除直播监控任务
- **URL**: `DELETE /v1/shows/{id}`
- **参数**:
  - `id`: 直播记录 ID（支持逗号分隔的批量删除）
- **响应**: 成功删除返回 200 状态码

### 配置管理 (`/configs`)（需鉴权）

#### 获取配置项
- **URL**: `GET /v1/configs/{key}`
- **参数**:
  - `key`: 配置键名
- **响应**: 返回配置值

#### 创建配置项
- **URL**: `POST /v1/configs`
- **请求体**:
  ```json
  {
    "key": "config_key",
    "value": "config_value"
  }
  ```

#### 更新配置项
- **URL**: `PUT /v1/configs/{key}`
- **参数**:
  - `key`: 配置键名
- **请求体**:
  ```json
  {
    "value": "new_config_value"
  }
  ```

#### 删除配置项
- **URL**: `DELETE /v1/configs/{key}`
- **参数**:
  - `key`: 配置键名

### 用户认证 (`/user`)（公开路由，但此处的登录是后续鉴权的入口）

#### 用户登录
- **URL**: `POST /v1/user/login`
- **请求体**:
  ```json
  { "username": "olive", "password": "olive" }
  ```
- **响应**（成功，HTTP 200）:
  ```json
  { "code": "0000", "data": { "permissions": ["*.*.*"] } }
  ```
  同时 `Set-Cookie: olive_session=<HMAC-signed token>; HttpOnly; SameSite=Lax; Max-Age=43200`
- **失败响应**:
  - 用户名/密码错误：`HTTP 400` `{"message":"invalid Username or Password"}`
  - 触发锁定窗口：`HTTP 429` `{"message":"too many failed login attempts; try again later"}`
- **凭据加密比较**：登录校验使用 `crypto/subtle.ConstantTimeCompare`，避免时序旁路泄露用户名/密码字符
- **失败锁定**：按 (RemoteAddr, Username) 维度计数，超过 5 次后启用指数退避锁定，500ms 起指数翻倍，10min 封顶；成功登录或 30 分钟无失败记录清空计数
- **默认凭据告警**：首次启动且 `core_config` 中仍是默认 `olive/olive` 时，引擎日志会打印一次 WARNING

#### 用户登出
- **URL**: `GET /v1/user/logout`
- **说明**: 通过 `Set-Cookie: olive_session=; Max-Age=-1` 在客户端清空会话 Cookie，服务端为无状态设计

### 测试接口 (`/test`)

#### 健康检查
- **URL**: `GET /v1/test`
- **响应**: 返回服务状态信息

## 调试端点

调试服务默认运行在 `http://127.0.0.1:4000/debug/` 路径下（v0.7.0 起默认绑回环地址）：

### 安全说明（v0.7.0 新增）
- 默认 `--web-debug-host=127.0.0.1:4000`，仅本机可访问。
- 若改绑非回环地址（`0.0.0.0:4000` 等），**必须**同时配置 `--web-debug-user` 与 `--web-debug-pass`;否则服务启动将被拒绝，主要原因：
  - `/debug/pprof/*` 会暴露 goroutine 调用栈与堆数据，可泄露 Cookie/Token 等内存中的敏感数据
  - pprof 既是远程内存取证入口也是 CPU DoS 放大器
- 已配置 Basic-Auth 时使用 `crypto/subtle.ConstantTimeCompare` 进行常量时间比较，避免账号爆破时序泄露

### 健康检查
- `/debug/readiness` - 就绪状态检查（返回 200 表示服务已准备好处理请求）
- `/debug/liveness` - 存活状态检查（返回 200 表示服务正在运行）

### 性能分析
- `/debug/pprof/` - Go 标准性能分析工具
  - `/debug/pprof/profile` - CPU profile
  - `/debug/pprof/heap` - 内存 heap profile
  - `/debug/pprof/goroutine` - goroutine stack dump
  - `/debug/pprof/block` - contended mutexes
  - `/debug/pprof/mutex` - mutex contention

### 应用变量
- `/debug/vars` - 显示应用的 expvar 变量，包括构建版本等信息

## 数据库配置

`olive server` 依赖 PostgreSQL 数据库来存储以下信息：

### 数据表结构
- **shows 表**: 存储直播监控任务配置
  - `id`: 主键
  - `url`: 直播地址
  - `enabled`: 是否启用
  - `name`: 主播名称
  - `platform`: 平台类型
  - 其他元数据字段

- **configs 表**: 存储全局配置项
  - `key`: 配置键
  - `value`: 配置值

### 自动初始化
服务启动时会自动执行以下操作：
1. 创建必要的数据库表（如果不存在）
2. 执行数据库迁移
3. 初始化默认配置

### 数据库准备
在启动服务前，确保 PostgreSQL 已正确安装和配置：

```bash
# 使用 Docker 启动 PostgreSQL
docker run -d --name postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres

# 或使用本地安装的 PostgreSQL
# 确保 postgres 用户和数据库存在
```

## 使用示例

### 1. 启动服务

```bash
# 启动 PostgreSQL（如果使用 Docker）
docker run -d --name postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres

# 启动 olive server（v0.7.0 默认绑回环，仅本机访问）
olive server \
  --db-host localhost \
  --db-user olive \
  --db-password letmein \
  --db-name olivedb \
  --web-api-host 127.0.0.1:3000 \
  --logdir ./task \
  --savedir ./task
```

### 2. 登录获取会话凭据（v0.7.0 起所有写操作都需要鉴权）

```bash
# 登录并保存 Cookie 到 cookie.txt
curl -c cookie.txt -X POST http://127.0.0.1:3000/v1/user/login \
  -H "Content-Type: application/json" \
  -d '{"username":"olive","password":"olive"}'

# 后续所有写操作请求都要带 cookie.txt
```

### 3. 管理直播任务

```bash
# 添加抖音直播监控（必须带会话凭证）
curl -b cookie.txt -X POST http://127.0.0.1:3000/v1/shows \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "douyin",
    "room_id": "32548597",
    "enable": true,
    "streamer_name": "叶南秋"
  }'

# 查询所有直播任务
curl -b cookie.txt http://127.0.0.1:3000/v1/shows/1/10

# 获取特定直播信息
curl -b cookie.txt http://127.0.0.1:3000/v1/shows/1

# 更新直播配置
curl -b cookie.txt -X PUT http://127.0.0.1:3000/v1/shows/1 \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# 删除直播任务
curl -b cookie.txt -X DELETE http://127.0.0.1:3000/v1/shows/1
```

> `curl` 默认会保存并复用 Cookie。对其它不支持 Cookie 的客户端，可以把登录响应里的 `X-Olive-Session` 等同值字符串作为 `X-Olive-Session` 请求头附带。

### 4. 健康检查

```bash
# 检查服务就绪状态（调试端口默认 127.0.0.1:4000，仅本机访问）
curl http://127.0.0.1:4000/debug/readiness

# 检查服务存活状态
curl http://127.0.0.1:4000/debug/liveness

# 获取应用变量（若配置了 --web-debug-user，需加 -u user:pass）
curl -u debuguser:debugpass http://127.0.0.1:4000/debug/vars
```

## 部署建议

### 开发环境
```bash
# 简单启动，使用默认配置
olive server -l ./logs -s ./videos
```

### 生产环境
```bash
# 推荐做法：API 通过反代终结 TLS 后暴露，olive server 自己绑回环
olive server \
  --db-host your-postgres-host \
  --db-user your-db-user \
  --db-password your-db-password \
  --web-api-host 127.0.0.1:3000 \
  --web-read-timeout 10s \
  --web-write-timeout 30s \
  --logdir /var/log/olive \
  --savedir /data/videos

# 或者不做反代，让 olive server 自己终结 TLS
olive server \
  --web-api-host 0.0.0.0:3000 \
  --web-tls-cert /etc/olive/tls.crt \
  --web-tls-key  /etc/olive/tls.key \
  --logdir /var/log/olive \
  --savedir /data/videos

# 需要远程访问 pprof 时必须给 debug 端口加 Basic-Auth
olive server \
  --web-debug-host 0.0.0.0:4000 \
  --web-debug-user admin \
  --web-debug-pass "$(openssl rand -base64 24)"
```

### Docker 部署
```yaml
# Docker Compose 示例
version: '3'
services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data

  olive:
    image: luxcgo/olive:latest
    # v0.7.0 起默认绑回环，容器内若要让宿主机访问需显式改绑 0.0.0.0
    # 推荐前置 nginx/caddy 做 TLS 终结
    command: server --db-host postgres --web-api-host 0.0.0.0:3000
    ports:
      - "127.0.0.1:3000:3000"   # 仅本机暴露 API
      - "127.0.0.1:4000:4000"   # 仅本机暴露 pprof
    volumes:
      - ./videos:/videos
      - ./logs:/logs
    depends_on:
      - postgres

volumes:
  postgres_data:
```

## 常见问题

### 1. 数据库连接失败
**问题**: 启动时出现数据库连接错误
**解决方案**:
- 确保 PostgreSQL 服务正在运行
- 检查数据库连接参数是否正确
- 确认数据库用户有足够权限

### 2. 端口冲突
**问题**: API 端口已被占用
**解决方案**:
- 使用不同的端口：`--web-api-host 127.0.0.1:3001`
- 检查并关闭占用端口的进程

### 3. 权限问题
**问题**: 无法写入日志或视频目录
**解决方案**:
- 确保指定目录存在且有写入权限
- 使用绝对路径而不是相对路径

### 4. 内存不足
**问题**: 处理大量并发录制时内存不足
**解决方案**:
- 调整数据库连接池大小
- 限制同时录制的直播数量
- 增加系统内存或使用更强大的服务器

### 5. 启动被拒绝：debug listener bound to a non-loopback address
**问题**（v0.7.0 新增）: 启动日志出现
```
debug listener bound to a non-loopback address without --web-debug-user/--web-debug-pass; refusing to start
```
**原因**: 你把 `--web-debug-host` 改成 `0.0.0.0:4000` 等非回环地址，但没配 Basic-Auth；pprof/expvar 直接暴露到公网是非常危险的远程内存取证与 DoS 放大入口。
**解决方案**:
- 推荐：保持 `--web-debug-host 127.0.0.1:4000`，仅本机访问
- 若必须远程调试：同时提供 `--web-debug-user` 和 `--web-debug-pass`

### 6. 调用 API 返回 401 Unauthorized
**问题**（v0.7.0 新增）: `GET /v1/shows/1/10` 或 `POST /v1/shows` 返回
```json
{"error":"missing session credentials"}
```
或
```json
{"error":"invalid or expired session"}
```
**原因**: 自 v0.7.0 起 `/v1/shows/*` 与 `/v1/configs/*` 必须携带会话凭据，缺失/过期/无效都会被 `Authenticate` 中间件拒绝。
**解决方案**:
1. 先调用 `POST /v1/user/login`，把响应里的 `olive_session` Cookie 保存下来
2. 后续请求带 Cookie（`curl -b cookie.txt`）或 `X-Olive-Session: <token>` 头
3. 会话有效期 12 小时，过期后需要重新登录

### 7. 调用 API 返回 400 "SaveDir/OutTmpl contains an unsafe path"
**问题**（v0.7.0 新增）: `POST /v1/shows` 或 `PUT /v1/shows/:id` 返回
```json
{"error":"SaveDir/OutTmpl contains an unsafe path"}
```
**原因**: `save_dir` 或 `out_tmpl` 字段里出现了 `..`、绝对路径前缀（`/xxx` 或 `\xxx`）或 NUL 字节。
**解决方案**:
- 使用相对路径（如 `recordings/clips`）
- 模板字段（`{{ .StreamerName }}` 之类）可以出现,但不要在 `save_dir` 里塞 `/etc/cron.d` 这类系统目录
- 直接留空让引擎使用 `core_config` 中的默认目录

### 8. 调用 API 返回 400 "PostCmds is not valid"
**问题**（v0.7.0 新增）: 写入 show 时返回
```json
{"error":"PostCmds is not valid"}
```
**原因**: `post_cmds` JSON 数组中某条 `path` 不在白名单内（`olivetrash`/`olivearchive`/`olivebiliup`/`oliveshell`），或 `oliveshell` 缺少 `args`，或者格式不是合法 JSON。
**解决方案**:
- 仅使用四种白名单 task type
- 用 `oliveshell` 时至少提供 1 个 `args`（要执行的二进制及参数）
- 引擎不接受直接传入 `/bin/sh`、`./local.sh` 等任意二进制路径

### 9. 登录返回 429 Too Many Requests
**问题**（v0.7.0 新增）: `/v1/user/login` 返回
```json
{"error":"too many failed login attempts; try again later"}
```
**原因**: 同一 `(IP, username)` 连续失败超过 5 次，已进入指数退避锁定窗口（起始 500ms，每次翻倍，10min 封顶）。
**解决方案**: 等待窗口结束后再尝试；或确认用户名/密码无误；成功登录或 30 分钟无失败记录会自动清空计数。

### 10. 升级到 v0.7.0 后默认监听地址变成回环
**问题**: 升级前可以用 `curl http://<对内IP>:3000` 访问，升级后变成 `connection refused`。
**原因**: 安全加固后 API 默认绑 `127.0.0.1:3000`，不再对非本机暴露。
**解决方案**:
- 仅本机访问 → 不需要改动
- 容器内需要被宿主机访问 → `--web-api-host 0.0.0.0:3000`,并务必配合 TLS（直接终结 TLS 或前置反代）

## 注意事项

1. **自动录制**: 服务启动后会自动开始录制所有 `enabled=true` 的直播任务
2. **优雅关闭**: 使用 `SIGINT` 或 `SIGTERM` 信号可以优雅关闭服务，确保当前录制完成
3. **配置热重载**: 通过 API 修改的配置会立即生效（自 v0.7.0 起该调用本身需要鉴权）
4. **安全考虑**:
   - v0.7.0 起 API 默认仅监听 `127.0.0.1:3000`
   - 对外暴露时务必启用 TLS（`--web-tls-cert/--web-tls-key` 或前置反代）
   - `/v1/shows/*`、`/v1/configs/*` 已强制要求会话凭据
   - 推荐在 `core_config` 中把默认 `PortalUsername/PortalPassword` (`olive/olive`) 改为强随机值（升级后首次启动会打 WARNING 提醒）
5. **资源监控**: 监控磁盘空间，确保有足够的存储空间保存录制的视频

## 安全模型与加固

v0.7.0 对 `olive server` 进行了一次安全加固，闭合了之前公开的 RCE、未授权管理 API、跨目录写入等多类风险。下表汇总了风险项、原状以及 v0.7.0 的整改措施：

| 风险项 | 原状 | v0.7.0 整改 |
|---|---|---|
| API 未授权 CRUD | `/v1/shows/*`、`/v1/configs/*` 没有任何鉴权，匿名即可全权管理 | 新增 `mid.Authenticate` 中间件，缺失/无效/过期会话返回 401 |
| 登录弱比较/无锁定 | 登录走 `==` 字符串比较，无失败锁定 | 改用 `crypto/subtle.ConstantTimeCompare`;新增 `LoginLockout` 按 (IP, Username) 指数退避锁定 |
| Login 后无会话签发 | 登录只返回 `permissions`,无 cookie/token,后续路由也不读 | 登录成功 `Set-Cookie: olive_session=<HMAC-SHA256>; HttpOnly; SameSite=Lax`;`X-Olive-Session` 头作为非浏览器客户端备用通道 |
| PostCmds RCE | `path` 字段任意字符串都喂给 `exec.Command`,可执行任意二进制 | `validate.PostCmdWhitelist` 限定 4 种 task type;`Uploader.DefaultHandlerFunc` 兜底拒绝未知 path |
| SaveDir/OutTmpl 跨目录 | 任意路径可写,可写到 `/etc/cron.d` 等系统目录 | 新增 `validate.CheckSafePath/CheckSafeFilename`,create/update 双端校验 |
| 默认监听公网 | `--web-api-host`、`--web-debug-host` 默认 `0.0.0.0` | 改为默认 `127.0.0.1`,显式暴露需要 TLS 或反代 |
| Debug pprof 裸奔 | 端口即可访问 `/debug/pprof/*`、`/debug/vars` | 默认回环;绑非回环必须 Basic-Auth,否则启动拒绝 |
| 请求体大小无上限 | `json.NewDecoder(r.Body)`,可被 1GB JSON 内存 DoS | `http.MaxBytesReader(1 MiB)` 包住解码器 |
| 写超时等 flag 失效 | `--web-write-timeout/--web-idle-timeout/--web-shutdown-timeout` 都绑到 `ReadTimeout` 字段 | 各自绑到对应字段,真正生效 |
| 默认凭据 `olive/olive` | 静默使用 | 首次启动引擎日志一次性 WARNING |
| `core_config` 含密码等敏感字段 | 任何登录(以及未授权时)可热替换任意字段 | 写入仍走已鉴权 API;`SessionStore` 密钥脱离 `core_config`,无法被热替换盗取 |
| Show 类型转换用 unsafe | `(*Show)(unsafe.Pointer(&dbShow))` 依赖布局稳定 | 改为显式字段拷贝,杜绝潜在内存破坏 |

### 升级检查清单

从 v0.6.x 升级到 v0.7.0+ 时建议执行以下检查：

1. **修改默认口令**：通过 `PUT /v1/configs/core_config` 把 `PortalUsername/PortalPassword` 从 `olive/olive` 改为强随机值（建议 `openssl rand -base64 24`）
2. **决定 API 暴露面**：
   - 仅本机/同容器：保持 `--web-api-host 127.0.0.1:3000` 默认
   - 对外：提供 `--web-tls-cert/--web-tls-key` 或前置 nginx/caddy 反代终结 TLS
3. **决定 Debug 暴露面**：
   - 保持 `127.0.0.1:4000` 默认最简单
   - 远程调试：必须 `--web-debug-user` + `--web-debug-pass`
4. **客户端适配**：现有调用 `/v1/shows/*`、`/v1/configs/*` 的脚本/前端都需要先调 `/v1/user/login` 拿到会话凭据后再发起写操作
5. **PostCmds 体检**：检查数据库 `shows.post_cmds` 列里是否有非白名单的 `path` 值，升级前应清理掉，否则引擎会拒绝执行该 show 的录制后任务
6. **Database TLS**：`--db-disable-tls` 默认仍为 `true`,生产环境建议显式设置为 `false` 以便加密数据库连接

## 版本信息

本文档随 Olive 仓库同步更新；最新版本对应的安全加固于 commit `4cf2a8d` 引入。如需最新信息，请参考源码或 PR 历史。