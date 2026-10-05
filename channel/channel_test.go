package channel

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// --- 测试辅助 -------------------------------------------------------------

type testEnv struct {
	log   *EventLog
	clock *Clock
	ch    *Channel
	chain *OnChain
	privA ed25519.PrivateKey
	privB ed25519.PrivateKey
}

func newTestEnv(t *testing.T, period uint64) *testEnv {
	t.Helper()
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	a := NewPartyWithKeys(PartyA, privA, pubB)
	b := NewPartyWithKeys(PartyB, privB, pubA)
	log := &EventLog{}
	clock := NewClock(0)
	ch := NewChannel("ch-1", a, b, 100, clock, log)
	bc := NewOnChain("ch-1", pubA, pubB, 100, period, clock, log)
	return &testEnv{log: log, clock: clock, ch: ch, chain: bc, privA: privA, privB: privB}
}

// cloneSigned 复制一个双签状态，便于篡改后保持原状态不变。
func cloneSigned(ss *SignedState) *SignedState {
	cp := *ss
	cp.SigA = append([]byte(nil), ss.SigA...)
	cp.SigB = append([]byte(nil), ss.SigB...)
	return &cp
}

// --- 一、版本号单调性 ------------------------------------------------------

func TestMonotonicUpdatesAndReplay(t *testing.T) {
	env := newTestEnv(t, 10)
	ch := env.ch

	if _, err := ch.Open(100, 0); err != nil {
		t.Fatalf("open: %v", err)
	}

	v2, err := ch.Transfer(PartyA, 10) // A -> B 10
	if err != nil {
		t.Fatalf("transfer v2: %v", err)
	}
	if v2.Version != 2 || v2.BalanceA != 90 || v2.BalanceB != 10 {
		t.Fatalf("v2 unexpected: %+v", v2.State)
	}

	v3, err := ch.Transfer(PartyB, 5) // B -> A 5
	if err != nil {
		t.Fatalf("transfer v3: %v", err)
	}
	if v3.Version != 3 || v3.BalanceA != 95 || v3.BalanceB != 5 {
		t.Fatalf("v3 unexpected: %+v", v3.State)
	}
	if ch.A.LastVersion() != 3 || ch.B.LastVersion() != 3 {
		t.Fatalf("both parties should be at v3, got A=%d B=%d", ch.A.LastVersion(), ch.B.LastVersion())
	}

	// 重放攻击 1：把旧的 v2 双签状态重新提交给当前在 v3 的一方 → 拒绝。
	if err := ch.Resubmit(PartyA, v2); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("replay of v2 should be ErrStaleVersion, got %v", err)
	}

	// 重放攻击 2：重新广播当前版本本身（版本号相等而非严格更大）→ 同样拒绝。
	if err := ch.Resubmit(PartyB, v3); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("resubmit of current v3 should be ErrStaleVersion, got %v", err)
	}

	// 重放攻击 3：伪造一个"旧版本号新签名"的提案（v2，由 A 用当前私钥签名）。
	stale := State{ChannelID: "ch-1", Version: 2, BalanceA: 90, BalanceB: 10}
	pr := Proposal{State: stale, SigProposer: ch.A.sign(stale), From: PartyA}
	if _, err := ch.Accept(PartyB, pr); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("stale proposal v2 should be ErrStaleVersion, got %v", err)
	}

	// 非法账态也必须在签名检查之外被拒绝（透支 → 负余额）。
	if _, err := ch.Transfer(PartyA, 1000); !errors.Is(err, ErrNegativeBalance) {
		t.Fatalf("overdraft should be ErrNegativeBalance, got %v", err)
	}
	// 被拒绝后双方版本不应变化。
	if ch.A.LastVersion() != 3 || ch.B.LastVersion() != 3 {
		t.Fatalf("versions changed after rejected updates: A=%d B=%d", ch.A.LastVersion(), ch.B.LastVersion())
	}
}

// TestDivergentVersions 构造双方持有不同版本的情形：
// A 发出 v3 提案，B 会签保存，但回送消息丢失，A 仍停在 v2。
func makeDivergent(t *testing.T, env *testEnv) (v2, v3 *SignedState) {
	t.Helper()
	ch := env.ch
	v1, err := ch.Open(100, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v2, err = ch.Transfer(PartyA, 10)
	if err != nil {
		t.Fatalf("transfer v2: %v", err)
	}
	// 手工走三阶段协议的前两步，故意不调用 DeliverFinal。
	pr, err := ch.Propose(PartyA, 80, 20) // A -> B 再转 10
	if err != nil {
		t.Fatalf("propose v3: %v", err)
	}
	v3, err = ch.Accept(PartyB, pr)
	if err != nil {
		t.Fatalf("accept v3: %v", err)
	}
	if ch.A.LastVersion() != v1.Version+1 || ch.B.LastVersion() != 3 {
		t.Fatalf("expected divergent A=v2 B=v3, got A=%d B=%d", ch.A.LastVersion(), ch.B.LastVersion())
	}
	return v2, v3
}

// --- 二、链上仲裁：双方版本不一致时采信更高版本 -----------------------------

func TestArbitrationHigherVersionWins(t *testing.T) {
	env := newTestEnv(t, 10)
	v2, v3 := makeDivergent(t, env)

	// A 链下请求超时（它不知道 v3），持 v2 上链发起争议。
	if err := env.chain.Dispute(PartyA, v2); err != nil {
		t.Fatalf("dispute: %v", err)
	}
	if env.chain.Status() != StatusDisputed || env.chain.BestVersion() != 2 {
		t.Fatalf("chain should hold v2 in dispute, got status=%s ver=%d",
			env.chain.Status(), env.chain.BestVersion())
	}

	// 争议期未结束不允许结算。
	if _, err := env.chain.Settle(); !errors.Is(err, ErrDisputeActive) {
		t.Fatalf("early settle should be ErrDisputeActive, got %v", err)
	}

	// B 在争议期内提交自己持有的 v3 双签状态作为证据。
	if err := env.chain.Refute(PartyB, v3); err != nil {
		t.Fatalf("refute v3: %v", err)
	}
	if env.chain.BestVersion() != 3 {
		t.Fatalf("chain should now prefer v3, got %d", env.chain.BestVersion())
	}

	// 争议期结束，按 v3 结算：A=80, B=20。
	env.clock.Advance(11)
	win, err := env.chain.Settle()
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if win.Version != 3 || win.BalanceA != 80 || win.BalanceB != 20 {
		t.Fatalf("settlement should follow v3, got %+v", win.State)
	}
	ver, ba, bb, ok := env.chain.Final()
	if !ok || ver != 3 || ba != 80 || bb != 20 {
		t.Fatalf("final() = %d,%d,%d,%v, want 3,80,20,true", ver, ba, bb, ok)
	}

	// 结算后通道终结，不能再次争议。
	if err := env.chain.Dispute(PartyB, v3); !errors.Is(err, ErrChannelSettled) {
		t.Fatalf("post-settle dispute should be ErrChannelSettled, got %v", err)
	}
}

func TestSettleFollowsSubmittedVersionWithoutRefute(t *testing.T) {
	env := newTestEnv(t, 10)
	v2, _ := makeDivergent(t, env)

	if err := env.chain.Dispute(PartyA, v2); err != nil {
		t.Fatalf("dispute: %v", err)
	}
	env.clock.Advance(11)
	win, err := env.chain.Settle()
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if win.Version != 2 || win.BalanceA != 90 || win.BalanceB != 10 {
		t.Fatalf("without refutation settlement should follow v2, got %+v", win.State)
	}
}

// --- 三、欺诈证明：争议期内有效、过期无效 -----------------------------------

func TestRefuteWithinWindow(t *testing.T) {
	env := newTestEnv(t, 10)
	v2, v3 := makeDivergent(t, env)

	if err := env.chain.Dispute(PartyA, v2); err != nil {
		t.Fatalf("dispute: %v", err)
	}
	deadline := env.chain.Deadline()

	env.clock.Advance(5) // 仍在争议期内
	if err := env.chain.Refute(PartyB, v3); err != nil {
		t.Fatalf("in-window refute should succeed, got %v", err)
	}
	// 争议期不因反驳而延长。
	if env.chain.Deadline() != deadline {
		t.Fatalf("deadline moved: %d -> %d", deadline, env.chain.Deadline())
	}

	// 用更低版本再次"反驳"无效。
	if err := env.chain.Refute(PartyA, v2); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("lower-version refute should be ErrStaleVersion, got %v", err)
	}

	env.clock.Advance(6) // t=11，超过截止 t=10
	win, err := env.chain.Settle()
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if win.Version != 3 {
		t.Fatalf("expected v3 settlement, got v%d", win.Version)
	}
}

func TestRefuteExpired(t *testing.T) {
	env := newTestEnv(t, 10)
	v2, v3 := makeDivergent(t, env)

	if err := env.chain.Dispute(PartyA, v2); err != nil {
		t.Fatalf("dispute: %v", err)
	}
	env.clock.Advance(11) // 争议期已过

	// 过期后提交更高版本证据不再被接受。
	if err := env.chain.Refute(PartyB, v3); !errors.Is(err, ErrExpiredRefute) {
		t.Fatalf("expired refute should be ErrExpiredRefute, got %v", err)
	}
	// 旧状态结算维持有效：按 v2 结算。
	win, err := env.chain.Settle()
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if win.Version != 2 || win.BalanceA != 90 || win.BalanceB != 10 {
		t.Fatalf("expired refutation must leave v2 settlement intact, got %+v", win.State)
	}
}

// --- 四、伪造状态 / 签名不匹配 ---------------------------------------------

func TestForgedStateRejected(t *testing.T) {
	env := newTestEnv(t, 10)
	v2, _ := makeDivergent(t, env)

	// 伪造 1：篡改已双签状态的余额（签名仍对应旧账态）。
	tampered := cloneSigned(v2)
	tampered.BalanceA, tampered.BalanceB = 0, 100
	if err := env.ch.Resubmit(PartyB, tampered); !errors.Is(err, ErrFinalSig) {
		t.Fatalf("tampered off-chain state should be ErrFinalSig, got %v", err)
	}

	// 伪造 2：用第三方密钥给一个状态双签后上链。
	_, privMallory, _ := ed25519.GenerateKey(nil)
	forged := State{ChannelID: "ch-1", Version: 99, BalanceA: 0, BalanceB: 100}
	fake := NewSignedState(forged,
		ed25519.Sign(env.privA, forged.SigningBytes()), // A 的真签名
		ed25519.Sign(privMallory, forged.SigningBytes()),
	) // B 的位置放了攻击者签名
	if err := env.chain.Dispute(PartyB, fake); !errors.Is(err, ErrFinalSig) {
		t.Fatalf("forged dispute should be ErrFinalSig, got %v", err)
	}
	if env.chain.Status() != StatusOpen {
		t.Fatalf("chain must stay open after forged dispute, got %s", env.chain.Status())
	}

	// 合法争议先打开争议期。
	if err := env.chain.Dispute(PartyA, v2); err != nil {
		t.Fatalf("legit dispute: %v", err)
	}

	// 伪造 3：争议期内用伪造签名状态反驳 → 拒绝，已采信版本保持 v2。
	if err := env.chain.Refute(PartyB, fake); !errors.Is(err, ErrFinalSig) {
		t.Fatalf("forged refute should be ErrFinalSig, got %v", err)
	}
	if env.chain.BestVersion() != 2 {
		t.Fatalf("best version must remain 2 after forged refute, got %d", env.chain.BestVersion())
	}

	// 伪造 4：金额守恒但通道 ID 不属于本合约。
	wrongChan := State{ChannelID: "ch-OTHER", Version: 3, BalanceA: 80, BalanceB: 20}
	wc := NewSignedState(wrongChan,
		ed25519.Sign(env.privA, wrongChan.SigningBytes()),
		ed25519.Sign(env.privB, wrongChan.SigningBytes()),
	)
	if err := env.chain.Refute(PartyB, wc); !errors.Is(err, ErrWrongChannel) {
		t.Fatalf("foreign-channel refute should be ErrWrongChannel, got %v", err)
	}
}

// --- 事件日志 -------------------------------------------------------------

func TestEventLogCoversInteractions(t *testing.T) {
	env := newTestEnv(t, 10)
	v2, v3 := makeDivergent(t, env)
	_ = env.ch.Resubmit(PartyA, v2) // 重放拒绝事件
	_ = env.chain.Dispute(PartyA, v2)
	env.clock.Advance(5)
	_ = env.chain.Refute(PartyB, v3)
	env.clock.Advance(6)
	_, _ = env.chain.Settle()

	evs := env.log.Events()
	want := []Kind{KindChannelOpened, KindUpdateOK, KindUpdateReject,
		KindDispute, KindRefute, KindSettled}
	if len(evs) < len(want) {
		t.Fatalf("only %d events logged: %+v", len(evs), evs)
	}
	for i, k := range want {
		if evs[i].Kind != k {
			t.Fatalf("event %d: want %s, got %s", i, k, evs[i].Kind)
		}
	}
	// 回放快照中签名校验结果必须逐方可见。
	if evs[1].State == nil || !evs[1].State.SigAValid || !evs[1].State.SigBValid {
		t.Fatalf("update-ok snapshot should carry both valid sigs: %+v", evs[1].State)
	}
	if evs[2].State == nil {
		t.Fatalf("replay rejection should still snapshot the rejected state")
	}
}
