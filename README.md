# 双方链下状态通道（State Channel）

一个简化的双方链下记账/支付通道实现：双方在链下通过交换**签名状态**更新账本，
只有发生争议时才需要"链上"仲裁。仅使用 Go 标准库（`crypto/ed25519`），
回放页为单一静态 HTML 文件，原生 HTML/CSS/JavaScript，无任何第三方依赖。

## 快速开始

```bash
go test ./...                                  # 运行全部测试
go run ./cmd/statechannel -out channel.html    # 生成交互回放页
open channel.html                              # 浏览器中逐步回放
```

## 协议设计

### 账本状态与签名

每个账本状态为：

```
State { ChannelID, Version, BalanceA, BalanceB }
```

签名内容是该结构的**确定性 32 字节大端编码**（`State.Bytes()`），双方各自用
ed25519 私钥签名。一个状态只有集齐**双方签名**（`SignedState`）才有效：

- `ChannelID` 防止跨通道重放；
- `Version` 从 0 开始，每次更新**严格 +1**；
- `BalanceA + BalanceB` 总额必须守恒（不允许凭空增发）。

### 链下更新流程

1. 提案方基于自己持有的最新双签状态构造 `v+1` 的新状态，签上自己的签名（半签提案）；
2. 接收方校验：版本号严格 `+1`、总额守恒、对方签名有效 —— 全部通过才会签并各自存档；
3. 任何一方收到**旧版本**状态（重放攻击，例如对方想撤回一笔对自己不利的付款）
   都会因版本号不满足单调递增而拒绝会签。

### 链上仲裁（Adjudicator）

当一方不再响应链下更新时，另一方可以把手中**最新的双签状态**提交给仲裁器：

- `StartDispute(state)`：校验双签，版本必须高于已结算版本；受理后开启**争议期**，
  该状态成为候选结算状态。签名无效（伪造）直接拒绝。
- `Challenge(state)`（欺诈证明）：争议期内，任何一方可提交**版本号更高**的双签状态，
  候选立即被替换 —— 即使先提交的是真实但过期的旧状态，也会被更新的证据推翻。
  **争议期过后**提交的反驳一律拒绝（`ErrChallengeExpired`）。
- `Settle()`：争议期结束后，当前候选状态成为最终账本并结算。

仲裁器本身不分辨"谁诚实"，只认两条密码学规则：**双签有效** + **版本号更高**。

### 争议期的设计依据

争议期（challenge period）是状态通道安全模型的核心参数：

- **为什么需要**：链上合约无法观测链下发生了多少次更新。若允许单方提交状态
  立即结算，作弊者总会挑选历史上对自己最有利的旧状态。争议期给对方留出
  提交欺诈证明（更高版本双签状态）的时间窗口。
- **为什么过期反驳无效**：若反驳窗口无限延长，结算永远无法确定，资金无法终局
  分配。争议期截止后候选状态即终局 —— 这要求诚实方在期内至少上线一次
  （liveness 假设），也是演示中"Bob 持有 v4 却过期未提交，最终按 v3 结算"
  这一结果的原因：规则不采信迟到的证据。
- **取值权衡**：真实系统（如 Lightning Network、乐观 Rollup）把争议期设为
  数小时到数天，权衡点是"诚实方上链交易的最低成本时间"与"资金锁定时长"。
  本实现将其参数化（`NewAdjudicator(pubA, pubB, period)`），演示场景用 2 个
  时间单位以便在一屏内展示"期内反驳有效 / 过期反驳无效"两种结果。

## 演示场景（`scenario.Run`）

| # | 事件 | 说明 |
|---|------|------|
| 1 | 开通通道 | 创世状态 v0 (50/50)，双方签名 |
| 2–5 | 链下更新 | 正常推进到 v4 (50/50) |
| 6 | 重放被拒 | Bob 试图让 Alice 重新接受旧状态 v2，版本号不递增被拒 |
| 7 | 伪造被拒 | Bob 捏造 v9 (0/100) 并伪造 Alice 签名，仲裁器验签失败 |
| 8 | 链上争议 | Bob 改用真实但过期的 v2 (35/65) 发起争议，进入争议期 |
| 9 | 欺诈证明 | Alice 在期内用 v3 (55/45) 反驳，候选被替换 |
| 10 | 过期反驳被拒 | Bob 在争议期后提交 v4 (50/50)，不再被接受 |
| 11 | 结算 | 按候选 v3 结算：Alice 55 / Bob 45 |

## 测试覆盖（`channel/`、`scenario/`）

- **版本单调性**：正常 +1 更新被接受；重放旧版本、跳号均被拒绝
  （`TestMonotonicVersionAccepted` / `TestReplayRejected` / `TestSkippedVersionRejected`）；
- **资金守恒**：总额膨胀的更新被拒绝（`TestBalanceConservation`）；
- **仲裁采信高版本**：双方持有不同版本时结算更高版本
  （`TestAdjudicatorPrefersHigherVersion` / `TestSettleWithoutChallenge`）；
- **欺诈证明**：争议期内反驳替换候选、截止前一刻仍有效、过期后无效且旧状态照常结算
  （`TestChallengeJustBeforeDeadline` / `TestChallengeAfterExpiryRejected`）；
- **伪造签名**：链下会签与链上争议/反驳两条路径都拒绝伪造状态
  （`TestForgedSignatureRejected` / `TestForgedStateRejectedOnChain`）；
- **仲裁器守卫**：重复争议、提前结算、已结算版本重放等
  （`TestSettleAndChallengeGuards` / `TestSettledVersionCannotBeRedispputed` 等）；
- **场景与 HTML**：脚本覆盖全部事件类型、按预期版本结算、HTML 自包含无外部引用
  （`TestScenarioFlow` / `TestRenderHTMLSelfContained`）。

## 目录结构

```
channel/            核心库：状态编码、签名、链下交互、链上仲裁器
scenario/           脚本化交互序列 + 单文件 HTML 回放页生成
cmd/statechannel/   入口：运行场景并输出 channel.html
```
