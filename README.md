# gate
VPN Gate SSTP 家宽节点 (edgetunnel 链式)

## 流程

1. 抓取 VPN Gate 原始节点，只保留带 TCP 入口的 SSTP 节点并去重
2. 调用检测 Worker 做第一轮可用性检测
3. **端到端拨测**：按真实客户端路径 (VLESS over WS -> Worker -> SSTP -> generate_204) 逐节点拨测，
   只保留真正拿得到 204 的节点；拨测全挂则本次运行失败，不发布空列表
4. 生成 public/data.json / public/index.html / public/nodes.txt

## 端到端拨测环境变量

- `PROBE_ENABLE` — 是否启用拨测 (默认 1)
- `PROBE_HOST` — Worker 域名，作为 TLS SNI 与 Host 头
- `PROBE_UUID` — Worker 的 VLESS UUID (仓库 Secret，用于生成链式代理路径)
- `PROBE_CONCURRENCY` — 拨测并发 (默认 10)
- `PROBE_TIMEOUT` — 单次连接超时秒数 (默认 8)
- `PROBE_TARGET_HOST` / `PROBE_TARGET_PORT` / `PROBE_TARGET_PATH` — 拨测目标 (默认 cp.cloudflare.com:80/generate_204)

`PROBE_UUID` 未配置时自动跳过拨测，退回仅 Worker 检测。

