# Secret Cert Controller

读取配置文件，在指定的 Kubernetes 命名空间下自动同步 TLS 证书到 Secret。

## 功能特性

- **配置文件驱动**：在配置文件中按命名空间列出域名，控制器定时读取（ConfigMap 挂载，改配置无需重启）
- **自动创建/更新**：目标 Secret 不存在则创建；已存在则比对证书指纹，过期才更新
- **命名规则固定**：域名中的 `.` 替换为 `-` 再追加 `-tls`
  - `example.com` → `example-com-tls`
  - `www.example.com` → `www-example-com-tls`
- **命名空间保护**：目标命名空间不存在时跳过并告警，不会自动创建命名空间
- **删除不回收**：从配置中移除域名后，已创建的 Secret 保留不动，仅停止同步

## 工作原理

控制器每 `SYNC_INTERVAL`（默认 60 秒）执行一轮：

1. 重新读取并解析配置文件（解析失败时沿用上一份有效配置）
2. 对每个目标命名空间检查是否存在，不存在则告警跳过
3. 对每个域名按规则计算 Secret 名：
   - Secret 不存在：拉取 `fullchain.pem` + `privkey.pem`，创建 `kubernetes.io/tls` 类型的 Secret
   - Secret 已存在：拉取 fullchain，与 Secret 中现有证书比对 sha256 指纹，一致则跳过，不一致才拉取私钥并更新

创建/更新的 Secret 只包含 `tls.crt`、`tls.key` 两个数据键，不添加任何注解或标签。

## 配置文件

配置文件为 YAML，默认路径 `/etc/cert-sync/config.yaml`：

```yaml
sync:
  - namespace: default
    domains:
      - example.com
      - www.example.com
  - namespace: kube-system
    domains:
      - app.example.com
```

校验规则：`sync` 不能为空；每项必须有 `namespace` 和非空 `domains`；同一命名空间下域名不可重复（不同命名空间可重复）。

## Helm 部署

通过 values 内联配置（chart 会创建 ConfigMap 并挂载）：

```yaml
controller:
  certServer: "https://cert.example.com/live"
  configSync:
    syncInterval: 60
    config: |
      sync:
        - namespace: default
          domains:
            - example.com
            - www.example.com
```

```bash
helm install secret-cert-controller ./chart -f values.yaml
```

也可以引用预先创建好的 ConfigMap（需包含 `config.yaml` 键）：

```yaml
controller:
  configSync:
    existingConfigMap: my-cert-sync-config
```

### Chart 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `controller.certServer` | `http://cert-server` | 证书服务器地址 |
| `controller.httpTimeout` | `5` | HTTP 请求超时（秒） |
| `controller.httpProxyUrl` | `""` | 出站代理地址（对应环境变量 `HTTPPROXY_URL`） |
| `controller.configSync.syncInterval` | `60` | 同步周期（秒），同时也是配置重读周期 |
| `controller.configSync.mountPath` | `/etc/cert-sync` | 配置文件挂载目录 |
| `controller.configSync.config` | `sync: []` | 内联同步配置（YAML） |
| `controller.configSync.existingConfigMap` | `""` | 使用已有 ConfigMap，设置后不再创建 |
| `replicaCount` | `1` | 副本数 |
| `image.repository` / `image.tag` | - | 镜像地址与标签 |

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CERT_SERVER` | `http://cert-server` | 证书服务器地址 |
| `HTTP_TIMEOUT` | `5` | HTTP 请求超时（秒） |
| `HTTPPROXY_URL` | （空） | 出站代理 |
| `CONFIG_PATH` | `/etc/cert-sync/config.yaml` | 配置文件路径 |
| `SYNC_INTERVAL` | `60` | 同步/配置重读周期（秒） |

## RBAC

- `secrets`：get/list/watch/create/update/patch
- `namespaces`：get/list/watch（用于判断目标命名空间是否存在）

## 证书服务器 API

控制器期望证书服务器提供以下接口（域名直接拼在路径中）：

```
GET {CERT_SERVER}/{domain}/fullchain.pem  -> 返回完整证书链 (PEM)
GET {CERT_SERVER}/{domain}/privkey.pem    -> 返回私钥 (PEM)
```

## 开发

```bash
go build ./...          # 构建
go vet ./...            # 静态检查
go test ./...           # 单元测试
go run .                # 本地运行（需要有效的 kubeconfig 与配置文件）
helm template ./chart   # 校验 chart
```

## 项目结构

```
secret-cert-controller/
├── chart/
│   ├── Chart.yaml            # Helm Chart 定义
│   ├── values.yaml           # 默认配置
│   └── templates/            # Deployment / ConfigMap / RBAC 等
├── controllers/
│   ├── config.go             # 配置文件结构、加载校验、Secret 命名规则
│   ├── cert.go               # 证书拉取、校验与指纹计算
│   └── syncer.go             # 定时同步循环（manager Runnable）
├── main.go                   # 程序入口
├── Dockerfile                # Docker 镜像构建
└── go.mod                    # Go 依赖
```

## License

MIT
