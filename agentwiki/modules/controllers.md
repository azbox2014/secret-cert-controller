# Module: `controllers`

[← Quickstart](../quickstart.md) · [Architecture](../architecture.md)

<!-- agentwiki:prose slot="purpose" status="fresh" facts-hash="11aa23dad181" hint="Explain the purpose and responsibilities of the controllers module: what it owns, its key abstractions, and how the rest of the codebase uses it." -->
`controllers` 是唯一的业务包，承载证书同步的全部逻辑，`main.go` 只负责建 manager 并把它注册为 Runnable。包内三个源文件按职责拆分：

- **`config.go`（配置与规则）**：定义 `Config{Sync []SyncTarget}`（`SyncTarget{Namespace, Domains}`，见 `:42`、`:48`）、`LoadConfig`（`:53`，用 `sigs.k8s.io/yaml` 读文件）和 `Validate`（`:72`，校验非空、namespace/domain 合法、同命名空间域名不重复）；`SecretName`（`:117`）实现域名到 Secret 名的固定映射。运行参数（`CERT_SERVER`、`CONFIG_PATH`、`SYNC_INTERVAL`）也在这里以包级变量读取。
- **`cert.go`（证书来源）**：`Fingerprint`（`:43`，对 PEM 首张证书 DER 算 sha256）、PEM 校验、`FetchFullchain`/`FetchPrivkey`（`:72`/`:85`）与带代理的 `http.Client`。
- **`syncer.go`（调谐循环）**：`Syncer`（`:17`）实现 manager `Runnable`，`Start`（`:29`）做启动即跑 + ticker 循环，`reconcile`（`:78`）逐命名空间、`syncDomain`（`:102`）逐 Secret 做 create/update，`createSecret`（`:152`）处理首次创建。

对外暴露的关键抽象就是"配置（期望的 namespace→domains）+ 无状态周期调谐"；`main.go` 仅通过实例化 `controllers.Syncer{Client, Reader, ConfigPath, Interval}` 使用本包，包不反向依赖 main。
<!-- /agentwiki:prose -->

## Files and exports

<!-- agentwiki:facts id="files" hash="11aa23dad181" -->
| File | Exports |
| --- | --- |
| `controllers/cert.go` | `FetchFullchain`, `FetchPrivkey`, `Fingerprint` |
| `controllers/cert_test.go` | `TestFetchFullchainAndPrivkey`, `TestFingerprint` |
| `controllers/config.go` | `Config`, `LoadConfig`, `SecretName`, `SyncTarget`, `Validate` |
| `controllers/config_test.go` | `TestDuplicateDomainAcrossNamespacesAllowed`, `TestLoadConfigErrors`, `TestLoadConfigOK`, `TestSecretName` |
| `controllers/syncer.go` | `Start`, `Syncer` |
<!-- /agentwiki:facts -->

## Dependencies

<!-- agentwiki:facts id="dependencies" hash="11aa23dad181" -->
- **Imports from:** nothing internal
- **Imported by:** nothing internal
<!-- /agentwiki:facts -->

## Recent activity

<!-- agentwiki:facts id="activity" hash="11aa23dad181" volatile="true" -->
- No commits touched this module in the last 90 days.
<!-- /agentwiki:facts -->

## Notes for contributors

<!-- agentwiki:prose slot="notes" status="fresh" facts-hash="11aa23dad181" hint="Practical guidance for changing code in controllers: invariants to respect, gotchas, and where tests live." -->
改动时需要守住的不变量与坑：

- **命名规则是对外契约**：`SecretName`（`config.go:117`）决定的名字会被下游 Ingress/TLSStore 直接引用，改规则或分隔符会导致生成全新 Secret（旧的不删除、新的无数据）。域名合法性校验走 `IsDNS1123Label`/`IsDNS1123Subdomain`，新增配置形态要同步更新 `Validate`（`config.go:72`）。
- **调谐副作用边界**：只允许 create/update Secret 与只读 Get Namespace；不要在 namespace 缺失时自动建 ns，不要 prune 配置中已删除域名对应的 Secret（这是刻意的"保留不动、停止同步"语义）。Secret 必须是 `corev1.SecretTypeTLS` 且只写 `tls.crt`/`tls.key`；遇到已存在但类型非 TLS 的同名 Secret 当前只告警跳过（`syncer.go` 的 `syncDomain`）。
- **更新判定靠 fullchain 指纹**：先拉证书算 sha256 与现有 `tls.crt` 比对，相同即返回，不同才拉私钥。改 HTTP/缓存逻辑时保持"尽量少传私钥"，并保留对非 200、非法 PEM 的错误处理（`cert.go` 的 `httpGet`）。
- **配置容错**：`LoadConfig` 失败时 `Start` 里的循环沿用上一份有效配置；若从未成功加载则跳过本轮。新增必填配置时注意 `sync: []` 是能通过 YAML 解析但被 `Validate` 拒绝的。

测试在 `config_test.go`（命名规则、加载/各类非法配置、跨命名空间允许同名）与 `cert_test.go`（指纹稳定性、用 `httptest` 起本地服务器验证 `FetchFullchain`/`FetchPrivkey` 及 404 路径），跑 `go test ./...`。目前没有针对 `syncer.go` 的 fake-client 测试，改动调谐分支时建议用 `sigs.k8s.io/controller-runtime/pkg/client/fake` 补上。
<!-- /agentwiki:prose -->
