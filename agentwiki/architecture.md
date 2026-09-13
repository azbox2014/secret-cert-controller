# Architecture

[← Quickstart](quickstart.md)

<!-- agentwiki:prose slot="design-overview" status="fresh" facts-hash="16613fa62f2b" hint="Explain the high-level architecture: the main runtime pieces, how data/control flows between the modules shown in the dependency graph, and the role of each entrypoint." -->
程序结构很简单：一个入口 `main.go:17` 加单包 `controllers`（5 个文件）。它不监听 K8s 资源事件，而是把一个定时同步器注册为 controller-runtime manager 的 `Runnable`（`main.go:38` 用 `mgr.Add(&controllers.Syncer{...})`），复用 manager 的 client / APIReader / 信号处理，但自身不建 controller、不 watch Secret。

数据流（一轮同步，见 `controllers/syncer.go:29` 的 `Start`）：

1. **配置**：每个周期 `LoadConfig(CONFIG_PATH)`（`controllers/config.go:53`）读取并校验挂载的 YAML（`sync: [{namespace, domains}]`，同命名空间域名不可重复）。解析失败沿用上一份有效配置。
2. **命名空间检查**：`reconcile`（`controllers/syncer.go:78`）对每个目标 `Get Namespace`，不存在则告警跳过，不创建。
3. **逐域名调谐** `syncDomain`（`:102`）：用 `SecretName(domain)`（点→横杠加 `-tls`）得到 Secret 名；不存在走 `createSecret`（`:152`，拉 fullchain+privkey 后 `Create`）；已存在则先只拉 fullchain、算 sha256 指纹（`controllers/cert.go:43`）与 Secret 中现有 `tls.crt` 比对，一致跳过，不一致才再拉 privkey 并 `Update`。
4. **HTTP**：`controllers/cert.go` 用单一 `http.Client`（超时 `HTTP_TIMEOUT`，可选 `HTTPPROXY_URL`，`init` 于 `:24`），从 `{CERT_SERVER}/{domain}/{fullchain,privkey}.pem` 拉取并做 PEM/证书校验。

控制流完全由 60s ticker 与启动时立即执行一次驱动；单副本运行（chart `replicaCount: 1`），没有选主。写入的 Secret 类型固定 `kubernetes.io/tls`，只有 `tls.crt`/`tls.key` 两个数据键、无注解无标签。
<!-- /agentwiki:prose -->

## Repository layout

<!-- agentwiki:facts id="layout" hash="16613fa62f2b" -->
- `chart/` — 7 files (0 source)
- `controllers/` — 5 files (5 source)
- `.github/` — 2 files (0 source)
<!-- /agentwiki:facts -->

## Entrypoints

<!-- agentwiki:facts id="entrypoints" hash="16613fa62f2b" -->
- `main.go`
<!-- /agentwiki:facts -->

## Module dependency graph

<!-- agentwiki:facts id="module-graph" hash="16613fa62f2b" -->
_No cross-module imports detected (single module or unsupported language)._
<!-- /agentwiki:facts -->

## Design decisions

<!-- agentwiki:prose slot="key-decisions" status="fresh" facts-hash="16613fa62f2b" hint="Document notable design decisions and trade-offs visible in the code and git history (frameworks chosen, patterns used, things deliberately avoided)." -->
从代码与 git 历史（0.0.6 起配置驱动的大改）可见的关键取舍：

- **放弃注解 watch，改为配置文件轮询**：旧版 `secret_controller.go`（已删除）watch 带注解的 Secret、靠事件触发，并维护一个 `sync.Map` 证书缓存 + 后台 refresher。新版只保留一个 manager `Runnable` 定时全量调谐。代价是最多有一个 `SYNC_INTERVAL`（60s）的延迟、且每轮对每个域名拉一次 fullchain；换来期望态集中在 Git（Helm values/ConfigMap）可见、无需给业务 Secret 打注解、也没有缓存一致性问题。
- **Secret 名由域名确定，而非注解任意指定**：`SecretName`（`controllers/config.go:117`）固定为 `strings.ReplaceAll(domain,".","-")+"-tls"`。好处是配置与产物一一对应、不会重复创建；约束是必须按规则命名（如 `example.com` → `example-com-tls`），因此从旧版注解模式迁移时，历史上非规则命名的 Secret 需要改名才能对应上。
- **最小权限、最小副作用**：目标命名空间不存在只告警跳过、不自动建 ns；配置删掉域名不 prune 已有 Secret（避免业务中断）；更新走"先比 fullchain 指纹、变了才拉私钥"以减少私钥传输；Secret 上不写注解标签，已存在的同名 Secret（含历史遗留注解）只更新数据。
- **读走 APIReader、写走 client**：`main.go:38-40` 同时注入 `mgr.GetClient()` 与 `mgr.GetAPIReader()`，只读的 Get 走直连 API，不依赖 informer 缓存对所有 namespace Secret/Namespace 的 list-watch 权限与缓存填充。
- **发布即多目标 OCI**：tag 触发的 workflow 同时推 GHCR/DockerHub/ACR/Hi 镜像并把 chart 推多个 OCI registry；CI 内用 sed 把 chart version/image.tag 强制对齐 git tag，避免三处版本漂移。这也是 build.yml 高频改动（hot files 9 次提交）的原因——期间踩过 ACR 不接受 buildx provenance 空清单（`provenance: false`）、QCR 权限不足等问题。
<!-- /agentwiki:prose -->
