# Recent activity

[← Quickstart](quickstart.md)

<!-- agentwiki:facts id="summary" hash="45306063ca7c" -->
- **Branch:** `main` at `4d38795`
- **Commits (last 90 days):** 13
- **Active contributors (last 90 days):** 1
<!-- /agentwiki:facts -->

## Current focus

<!-- agentwiki:prose slot="current-focus" status="fresh" facts-hash="45306063ca7c" hint="Summarize what the team is currently working on, based on the hot files and recent commit messages below." -->
近 90 天 11 个提交、1 名贡献者，工作几乎全部集中在 **2026-09-12 的一次大版本（v0.0.7）**，主线是把控制器从"Secret 注解被动触发"重写为"配置文件主动同步"，并打通多 registry 的镜像/chart 发布：

- **核心重构**（0.0.6 起的配置驱动改造）：删除旧的 `controllers/secret_controller.go`（watch + sync.Map 缓存），新增 `controllers/config.go`（YAML 配置与域名→Secret 命名规则）、`cert.go`（拉取/指纹）、`syncer.go`（定时 Runnable），并补齐单元测试；chart 升到 0.0.6/0.0.7，新增 ConfigMap 与 `/etc/cert-sync` 挂载。
- **发布链路密集调试**（build.yml 是最热文件，9 次提交）：chart 随 tag 自动 `helm push` 到多个公共 OCI 仓库；期间依次修了兼容 OCI 的 registry 拒绝 buildx provenance 空清单（加 `provenance: false`）、Helm 升 v4.3.0、手动触发产生非法 tag（给 build job 加 tag 条件）、以及个别 registry 的推送权限/路径问题。

v0.0.7 镜像与 OCI chart 均已发布成功，使用方已把实例 pin 到 0.0.7 并改为 values 配置驱动。后续若再动，主要热点预计仍在 chart 版本对齐与证书配置，而非 Go 逻辑本身。
<!-- /agentwiki:prose -->

## Hot files

<!-- agentwiki:facts id="hot-files" hash="45306063ca7c" -->
| File | Commits (90d) |
| --- | --- |
| `.github/workflows/build.yml` | 9 |
| `chart/Chart.yaml` | 3 |
| `chart/values.yaml` | 3 |
| `agentwiki/activity.md` | 2 |
| `agentwiki/architecture.md` | 2 |
| `agentwiki/quickstart.md` | 2 |
| `chart/templates/deployment.yaml` | 2 |
| `controllers/secret_controller.go` | 2 |
| `.claude/settings.json` | 1 |
| `.cursor/hooks.json` | 1 |
| `.cursor/rules/agentwiki.mdc` | 1 |
| `AGENTS.md` | 1 |
<!-- /agentwiki:facts -->

## Recent commits

<!-- agentwiki:facts id="recent-commits" hash="45306063ca7c" -->
- `4d38795` 2026-09-13 — wiki: 精修 prose，去除内部部署细节与失效提交引用 _(Liqiang Zhang)_
- `e9a8953` 2026-09-13 — docs: 接入 agentwiki，初始化项目 wiki 与 agent 配置 _(Liqiang Zhang)_
- `e06f05a` 2026-09-12 — ci: QCR 切换为 Hi Registry（镜像 + Helm chart），移除诊断 job _(Liqiang Zhang)_
- `4e67c87` 2026-09-12 — ci: 暂时移除 QCR 镜像推送目标 _(Liqiang Zhang)_
- `032f820` 2026-09-12 — ci: QCR 镜像推送路径改为 osc-org 命名空间 _(Liqiang Zhang)_
- `dcdd0e9` 2026-09-12 — release v0.0.7 _(Liqiang Zhang)_
- `c1615af` 2026-09-12 — ci: Helm 升级到 v4.3.0 _(Liqiang Zhang)_
- `fff3f24` 2026-09-12 — ci: 增加 QCR OCI 推送诊断（workflow_dispatch） _(Liqiang Zhang)_
- `bd1f5fe` 2026-09-12 — fix(ci): 关闭 buildx provenance 以兼容 ACR 推送 _(Liqiang Zhang)_
- `3e219df` 2026-09-12 — 发版时 Helm chart 同时推送到 QCR 和 GHCR OCI _(Liqiang Zhang)_
<!-- /agentwiki:facts -->
