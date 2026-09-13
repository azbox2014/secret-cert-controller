# Recent activity

[← Quickstart](quickstart.md)

<!-- agentwiki:facts id="summary" hash="0dcf422ec0ea" -->
- **Branch:** `main` at `1b92276`
- **Commits (last 90 days):** 11
- **Active contributors (last 90 days):** 1
<!-- /agentwiki:facts -->

## Current focus

<!-- agentwiki:prose slot="current-focus" status="fresh" facts-hash="0dcf422ec0ea" hint="Summarize what the team is currently working on, based on the hot files and recent commit messages below." -->
近 90 天 11 个提交、1 名贡献者，工作几乎全部集中在 **2026-09-12 的一次大版本（v0.0.7）**，主线是把控制器从"Secret 注解被动触发"重写为"配置文件主动同步"，并打通多 registry 的镜像/chart 发布：

- **核心重构**（0.0.6 起的配置驱动改造）：删除旧的 `controllers/secret_controller.go`（watch + sync.Map 缓存），新增 `controllers/config.go`（YAML 配置与域名→Secret 命名规则）、`cert.go`（拉取/指纹）、`syncer.go`（定时 Runnable），并补齐单元测试；chart 升到 0.0.6/0.0.7，新增 ConfigMap 与 `/etc/cert-sync` 挂载。
- **发布链路密集调试**（build.yml 是最热文件，9 次提交）：chart 随 tag 自动 `helm push` 到多个公共 OCI 仓库；期间依次修了兼容 OCI 的 registry 拒绝 buildx provenance 空清单（加 `provenance: false`）、Helm 升 v4.3.0、手动触发产生非法 tag（给 build job 加 tag 条件）、以及个别 registry 的推送权限/路径问题。

v0.0.7 镜像与 OCI chart 均已发布成功，使用方已把实例 pin 到 0.0.7 并改为 values 配置驱动。后续若再动，主要热点预计仍在 chart 版本对齐与证书配置，而非 Go 逻辑本身。
<!-- /agentwiki:prose -->

## Hot files

<!-- agentwiki:facts id="hot-files" hash="0dcf422ec0ea" -->
| File | Commits (90d) |
| --- | --- |
| `.github/workflows/build.yml` | 9 |
| `chart/Chart.yaml` | 3 |
| `chart/values.yaml` | 3 |
| `chart/templates/deployment.yaml` | 2 |
| `controllers/secret_controller.go` | 2 |
| `README.md` | 1 |
| `chart/templates/configmap.yaml` | 1 |
| `chart/templates/rbac.yaml` | 1 |
| `controllers/cert.go` | 1 |
| `controllers/cert_test.go` | 1 |
| `controllers/config.go` | 1 |
| `controllers/config_test.go` | 1 |
<!-- /agentwiki:facts -->

## Recent commits

<!-- agentwiki:facts id="recent-commits" hash="0dcf422ec0ea" -->
- `1b92276` 2026-09-12 — ci: QCR 切换为 Hi Registry（镜像 + Helm chart），移除诊断 job _(Liqiang Zhang)_
- `ca272ac` 2026-09-12 — ci: 暂时移除 QCR 镜像推送目标 _(Liqiang Zhang)_
- `e9d9124` 2026-09-12 — ci: QCR 镜像推送路径改为 osc-org 命名空间 _(Liqiang Zhang)_
- `55928c7` 2026-09-12 — release v0.0.7 _(Liqiang Zhang)_
- `7e9034d` 2026-09-12 — ci: Helm 升级到 v4.3.0 _(Liqiang Zhang)_
- `60d8763` 2026-09-12 — ci: 增加 QCR OCI 推送诊断（workflow_dispatch） _(Liqiang Zhang)_
- `016ea40` 2026-09-12 — fix(ci): 关闭 buildx provenance 以兼容 ACR 推送 _(Liqiang Zhang)_
- `4d58fbf` 2026-09-12 — 发版时 Helm chart 同时推送到 QCR 和 GHCR OCI _(Liqiang Zhang)_
- `2af52c7` 2026-09-12 — 改为配置文件驱动证书同步并自动发布 OCI chart _(Liqiang Zhang)_
- `d365f1d` 2026-08-28 — update ignore _(Liqiang Zhang)_
<!-- /agentwiki:facts -->
