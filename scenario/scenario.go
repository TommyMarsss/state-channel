// Package scenario 运行一组脚本化的通道交互（正常更新、重放、伪造、
// 争议、反驳、过期反驳、结算），把每一步记录为事件，供 HTML 回放使用。
package scenario

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/TommyMarsss/state-channel/channel"
)

// HeldView 是某一方在某一时刻持有的账本快照。
type HeldView struct {
	Version  uint64 `json:"version"`
	BalanceA uint64 `json:"balanceA"`
	BalanceB uint64 `json:"balanceB"`
}

// ChainView 是链上仲裁器在某一时刻的状态快照。
type ChainView struct {
	Status           string `json:"status"`           // "无争议" / "争议中" / "已结算"
	CandidateVersion int64  `json:"candidateVersion"` // 无候选时为 -1
	CandidateBalA    uint64 `json:"candidateBalA"`
	CandidateBalB    uint64 `json:"candidateBalB"`
	Deadline         string `json:"deadline"`
	FinalVersion     int64  `json:"finalVersion"` // 未结算时为 -1
}

// Event 是回放时间线上的一个步骤。
type Event struct {
	Seq      int       `json:"seq"`
	Kind     string    `json:"kind"` // open/update/replay-rejected/forgery-rejected/dispute/challenge/challenge-rejected/settle
	Actor    string    `json:"actor"`
	Title    string    `json:"title"`
	Note     string    `json:"note"`
	Clock    string    `json:"clock"`
	Version  int64     `json:"version"` // 事件涉及的状态版本，无则 -1
	BalanceA uint64    `json:"balanceA"`
	BalanceB uint64    `json:"balanceB"`
	SigAOK   bool      `json:"sigAOK"` // 事件涉及状态的签名校验结果
	SigBOK   bool      `json:"sigBOK"`
	Alice    HeldView  `json:"alice"`
	Bob      HeldView  `json:"bob"`
	Chain    ChainView `json:"chain"`
}

// 演示参数：争议期取 2 个时间步，便于在一屏内展示"期内反驳有效、过期反驳无效"。
const challengePeriod = 2 * time.Minute

// Run 执行脚本并返回完整事件序列。密钥由固定种子派生，结果可复现。
func Run() []Event {
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	for i := range seedA {
		seedA[i] = byte(i + 1)
		seedB[i] = byte(0xB0 + i)
	}
	alice, _ := channel.NewParticipant("Alice", channel.RoleA, seedA)
	bob, _ := channel.NewParticipant("Bob", channel.RoleB, seedB)

	privA := ed25519.NewKeyFromSeed(seedA)
	privB := ed25519.NewKeyFromSeed(seedB)

	ad := channel.NewAdjudicator(alice.Pub, bob.Pub, challengePeriod)

	epoch := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := epoch
	advance := func(d time.Duration) { clock = clock.Add(d) }
	clockStr := func() string { return "T+" + clock.Sub(epoch).String() }

	var events []Event
	snap := func() (HeldView, HeldView, ChainView) {
		a := alice.Latest.State
		b := bob.Latest.State
		cv := ChainView{Status: "无争议", CandidateVersion: -1, FinalVersion: -1}
		if c, ok := ad.Candidate(); ok {
			cv.Status = "争议中"
			cv.CandidateVersion = int64(c.State.Version)
			cv.CandidateBalA = c.State.BalanceA
			cv.CandidateBalB = c.State.BalanceB
			cv.Deadline = "T+" + ad.Deadline().Sub(epoch).String()
		}
		if f, ok := ad.Final(); ok {
			cv.Status = "已结算"
			cv.FinalVersion = int64(f.Version)
		}
		return HeldView{a.Version, a.BalanceA, a.BalanceB},
			HeldView{b.Version, b.BalanceA, b.BalanceB}, cv
	}
	emit := func(kind, actor, title, note string, st *channel.SignedState) {
		av, bv, cv := snap()
		ev := Event{
			Seq: len(events) + 1, Kind: kind, Actor: actor,
			Title: title, Note: note, Clock: clockStr(),
			Version: -1, Alice: av, Bob: bv, Chain: cv,
		}
		if st != nil {
			ev.Version = int64(st.State.Version)
			ev.BalanceA = st.State.BalanceA
			ev.BalanceB = st.State.BalanceB
			ev.SigAOK = ed25519.Verify(alice.Pub, st.State.Bytes(), st.SigA)
			ev.SigBOK = ed25519.Verify(bob.Pub, st.State.Bytes(), st.SigB)
		}
		events = append(events, ev)
	}

	// 1. 开通通道：创世状态 v0 (50/50)，双方签名。
	genesis := channel.Genesis(1, 50, 50, privA, privB)
	alice.Init(genesis)
	bob.Init(genesis)
	emit("open", "双方", "开通通道，创世状态 v0 (50/50)",
		"双方各自在链下保存这份双签状态；此后所有更新都在链下完成，只有争议时才上链。", &genesis)

	// 2-5. 正常链下更新。
	update := func(proposer, counter *channel.Participant, balA, balB uint64, desc string) {
		prop, err := proposer.Propose(balA, balB)
		must(err)
		full, err := counter.CounterSign(prop, proposer.Pub)
		must(err)
		must(proposer.Confirm(full, counter.Pub))
		advance(30 * time.Second)
		emit("update", proposer.Name, desc,
			fmt.Sprintf("提案方构造 v%d 并签名，对方校验版本号严格 +1、总额守恒后会签，双方各自存档。", full.State.Version), &full)
	}
	update(alice, bob, 40, 60, "Alice 向 Bob 支付 10：v1 (40/60)")
	update(alice, bob, 35, 65, "Alice 向 Bob 支付 5：v2 (35/65)")
	update(bob, alice, 55, 45, "Bob 向 Alice 支付 20：v3 (55/45)")
	update(alice, bob, 50, 50, "Alice 向 Bob 支付 5：v4 (50/50)")

	// 6. 重放攻击：Bob 把对自己有利的旧状态 v2 重新发给 Alice 请求会签。
	oldV2 := channel.SignedState{
		State: channel.State{ChannelID: 1, Version: 2, BalanceA: 35, BalanceB: 65},
	}
	oldV2.SigB = channel.Sign(privB, oldV2.State)
	replayErr := error(nil)
	if _, err := alice.CounterSign(oldV2, bob.Pub); err != nil {
		replayErr = err
	}
	advance(30 * time.Second)
	emit("replay-rejected", "Bob", "重放攻击：Bob 试图让 Alice 重新接受旧状态 v2 (35/65)",
		fmt.Sprintf("v2 对 Bob 更有利，但 Alice 的客户端要求版本号严格递增（当前 v4，期望 v5），拒绝会签。错误：%v", replayErr), &oldV2)

	// 7. Bob 失联，Alice 准备上链结算；Bob 抢先伪造状态。
	//    Bob 编造 v9 (0/100)，并用攻击者密钥伪造 Alice 的签名。
	attackerSeed := make([]byte, ed25519.SeedSize)
	for i := range attackerSeed {
		attackerSeed[i] = 0xEE
	}
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	forged := channel.SignedState{
		State: channel.State{ChannelID: 1, Version: 9, BalanceA: 0, BalanceB: 100},
	}
	forged.SigA = channel.Sign(attackerPriv, forged.State) // 伪造的 Alice 签名
	forged.SigB = channel.Sign(privB, forged.State)
	forgeErr := ad.StartDispute(forged, clock)
	advance(30 * time.Second)
	emit("forgery-rejected", "Bob", "伪造状态：Bob 提交凭空捏造的 v9 (0/100)",
		fmt.Sprintf("状态上 Alice 的签名由攻击者密钥生成，仲裁器验签失败，直接拒绝。错误：%v", forgeErr), &forged)

	// 8. Bob 改用真实但过期的 v2 (35/65) 发起争议 —— 签名有效，仲裁器受理并进入争议期。
	stale := channel.SignedState{
		State: channel.State{ChannelID: 1, Version: 2, BalanceA: 35, BalanceB: 65},
	}
	stale.SigA = channel.Sign(privA, stale.State)
	stale.SigB = channel.Sign(privB, stale.State)
	must(ad.StartDispute(stale, clock))
	emit("dispute", "Bob", "Bob 用旧状态 v2 (35/65) 发起链上争议",
		fmt.Sprintf("v2 的双签真实有效，仲裁器无法分辨它是否最新，只能受理并开启争议期（至 T+%s），等待对方拿出更新版本反驳。", ad.Deadline().Sub(epoch)), &stale)

	// 9. Alice 在争议期内提交欺诈证明：v3 (55/45) 版本更高，候选被替换。
	proofV3 := channel.SignedState{
		State: channel.State{ChannelID: 1, Version: 3, BalanceA: 55, BalanceB: 45},
	}
	proofV3.SigA = channel.Sign(privA, proofV3.State)
	proofV3.SigB = channel.Sign(privB, proofV3.State)
	advance(time.Minute) // 争议期内
	must(ad.Challenge(proofV3, clock))
	emit("challenge", "Alice", "欺诈证明：Alice 用更新版本 v3 (55/45) 反驳",
		"v3 版本号更高且双签有效，旧候选 v2 立即失效，候选被替换为 v3。争议期不重置。", &proofV3)

	// 10. 争议期过后，Bob 才想起自己持有 v4 (50/50) —— 过期反驳被拒绝。
	proofV4 := channel.SignedState{
		State: channel.State{ChannelID: 1, Version: 4, BalanceA: 50, BalanceB: 50},
	}
	proofV4.SigA = channel.Sign(privA, proofV4.State)
	proofV4.SigB = channel.Sign(privB, proofV4.State)
	advance(2 * time.Minute) // 越过争议期截止时刻
	lateErr := ad.Challenge(proofV4, clock)
	emit("challenge-rejected", "Bob", "过期反驳：Bob 提交 v4 (50/50)，但争议期已过",
		fmt.Sprintf("尽管 v4 双签有效且版本更高，但提交时刻 %s 已超过争议期截止 T+%s，反驳不再被接受。错误：%v",
			clockStr(), ad.Deadline().Sub(epoch), lateErr), &proofV4)

	// 11. 结算：候选 v3 成为最终账本。
	final, err := ad.Settle(clock)
	must(err)
	emit("settle", "仲裁器", fmt.Sprintf("结算完成：按 v3 执行，Alice 得 %d，Bob 得 %d", final.BalanceA, final.BalanceB),
		"争议期结束，候选状态 v3 成为最终账本。注意最终结算的是 v3 而非链下最新的 v4 —— 过期未提交的反驳证据不被采信，这正是争议期设计的意义。", &proofV3)

	return events
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
