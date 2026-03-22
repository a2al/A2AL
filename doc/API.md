# A2AL Go 库 — 调用说明（Phase 1）

## 库与验证程序

- **库**：仓库根目录 `go.mod`（`module github.com/a2al/a2al`），各子包供应用 `import`。
- **验证程序**：`examples/phase1-node/`（独立 `go.mod`），单一 DHT 节点：启动即发布，交互式按 Address 查询。

## 快速上手

```bash
cd examples/phase1-node

# 终端1：第一个节点
go run . -listen :5001 -debug :2634

# 终端2：第二个节点，bootstrap 到第一个
go run . -listen :5002 -bootstrap 127.0.0.1:5001 -debug :2635

# 终端3：第三个节点
go run . -listen :5003 -bootstrap 127.0.0.1:5001 -debug :2636
```

每个节点启动后打印自己的 Address。在任一终端输入另一个节点的 Address，按回车，即可解析出对方的端点信息。

## 浏览器看状态

默认 Debug HTTP 地址由 `-debug` 参数指定（库常量 `dht.DebugHTTPAddr` = `127.0.0.1:2634`）。

| URL | 内容 |
|-----|------|
| `http://127.0.0.1:2634/debug/identity` | 本节点 Address、NodeID、监听地址 |
| `http://127.0.0.1:2634/debug/routing` | 路由表快照 |
| `http://127.0.0.1:2634/debug/store` | 本地存储记录 |
| `http://127.0.0.1:2634/debug/stats` | 收发包 / RPC 计数 |

多节点时每个用不同端口（如 `:2634`、`:2635`、`:2636`）。

## Bootstrap：只需要 ip:port

调用 **`node.BootstrapAddrs(ctx, []net.Addr{udpAddr})`** 即可。库会自动向裸地址发 PING，从 PONG 中提取对方 Address / NodeID，注册拨号地址并加入路由表。**应用无需提前知道种子的密码学身份。**

旧接口 `Bootstrap(ctx, []BootstrapSeed)` 仍可用（需预知对方 NodeInfo），但推荐使用 `BootstrapAddrs`。

## 包职责

| 包 | 作用 |
|----|------|
| `github.com/a2al/a2al` | `Address` / `NodeID`、`Storage`、`MemStorage` |
| `github.com/a2al/a2al/crypto` | `KeyStore` 接口、`EncryptedKeyStore` |
| `github.com/a2al/a2al/protocol` | 消息、编解码、`SignEndpointRecord` |
| `github.com/a2al/a2al/transport` | `Transport` 接口、`MemTransport`、`UDPTransport` |
| `github.com/a2al/a2al/dht` | `Node`、`Query`、bootstrap、Debug HTTP |
| `github.com/a2al/a2al/routing` | K-bucket 路由表 |

## `dht.Node` 生命周期

1. `NewNode(Config{Transport, Keystore})`
2. `Start()` — 收包循环
3. `BootstrapAddrs(ctx, addrs)` — 只需 ip:port
4. `PublishEndpointRecord(ctx, rec)` — 发布自己
5. `NewQuery(node).Resolve(ctx, targetNodeID)` — 按 Address 查询
6. `Close()`

## 常用 API

| 方法 | 说明 |
|------|------|
| `BootstrapAddrs(ctx, []net.Addr)` | **推荐**：只需 ip:port，自动握手入表 |
| `PingIdentity(ctx, addr)` | Ping 并返回对方 `PeerIdentity{Address, NodeID}` |
| `PublishEndpointRecord(ctx, rec)` | 向 DHT 近邻 STORE |
| `NewQuery(n).Resolve(ctx, nodeID)` | 迭代 FIND_VALUE |
| `NewQuery(n).FindNode(ctx, nodeID)` | 迭代 FIND_NODE |
| `StartDebugHTTP(addr)` / `DebugHTTPHandler()` | 只读 JSON |
| `Ping` / `FindNode` / `FindValue` / `StoreAt` | 单跳 RPC |

## 端点记录

```go
rec, err := protocol.SignEndpointRecord(priv, addr, EndpointPayload{...}, seq, timestampUnix, ttlSec)
```

`timestamp + TTL` 需覆盖当前时间，否则验证 / 存储会失败。

## 库测试

```bash
go test -vet=off -count=1 ./...
```
