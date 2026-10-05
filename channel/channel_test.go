package channel

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// 测试用的确定性密钥。
func testKeys() (privA, privB ed25519.PrivateKey) {
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	for i := range seedA {
		seedA[i] = byte(i + 1)
		seedB[i] = byte(i + 101)
	}
	return ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
}

func newPair(t *testing.T) (alice, bob *Participant) {
	t.Helper()
	privA, privB := testKeys()
	seedA := privA.Seed()
	seedB := privB.Seed()
	alice, err := NewParticipant("Alice", RoleA, seedA)
	if err != nil {
		t.Fatal(err)
	}
	bob, err = NewParticipant("Bob", RoleB, seedB)
	if err != nil {
		t.Fatal(err)
	}
	genesis := Genesis(1, 50, 50, privA, privB)
	alice.Init(genesis)
	bob.Init(genesis)
	return alice, bob
}

// doUpdate 完成一次正常的链下更新：proposer 提案，对方会签，提案方确认。
func doUpdate(t *testing.T, proposer, counter *Participant, balA, balB uint64) SignedState {
	t.Helper()
	prop, err := proposer.Propose(balA, balB)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	full, err := counter.CounterSign(prop, proposer.Pub)
	if err != nil {
		t.Fatalf("CounterSign: %v", err)
	}
	if err := proposer.Confirm(full, counter.Pub); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	return full
}

// 正常更新：版本号严格 +1 时被接受。
func TestMonotonicVersionAccepted(t *testing.T) {
	alice, bob := newPair(t)
	st := doUpdate(t, alice, bob, 40, 60)
	if st.State.Version != 1 {
		t.Fatalf("版本号 = %d，期望 1", st.State.Version)
	}
	if alice.Latest.State.Version != 1 || bob.Latest.State.Version != 1 {
		t.Fatal("双方本地账本未推进到 v1")
	}
	st = doUpdate(t, bob, alice, 55, 45)
	if st.State.Version != 2 {
		t.Fatalf("版本号 = %d，期望 2", st.State.Version)
	}
}

// 重放攻击：把旧版本状态重新提交给对方会签，必须被拒绝。
func TestReplayRejected(t *testing.T) {
	alice, bob := newPair(t)
	old := doUpdate(t, alice, bob, 40, 60) // v1: Bob 多得 10
	doUpdate(t, alice, bob, 30, 70)        // v2
	doUpdate(t, alice, bob, 20, 80)        // v3

	// Bob 试图让 Alice 重新接受对自己更有利的旧状态 v1。
	replay := SignedState{State: old.State}
	replay.SigB = Sign(bob.priv, old.State)
	if _, err := alice.CounterSign(replay, bob.Pub); !errors.Is(err, ErrVersionNotMonotonic) {
		t.Fatalf("重放旧版本应返回 ErrVersionNotMonotonic，实际: %v", err)
	}
	if alice.Latest.State.Version != 3 {
		t.Fatalf("Alice 的账本不应被重放污染，当前 v%d", alice.Latest.State.Version)
	}
}

// 总额不守恒的更新（凭空印钞）必须被拒绝。
func TestBalanceConservation(t *testing.T) {
	alice, _ := newPair(t)
	if _, err := alice.Propose(60, 60); !errors.Is(err, ErrBalanceNotConserved) {
		t.Fatalf("总额膨胀应返回 ErrBalanceNotConserved，实际: %v", err)
	}
}

// 伪造签名：用错误的密钥签名，校验必须失败。
func TestForgedSignatureRejected(t *testing.T) {
	alice, bob := newPair(t)
	privA, _ := testKeys()

	prop, err := alice.Propose(40, 60)
	if err != nil {
		t.Fatal(err)
	}
	// Bob 收到提案后篡改余额并伪造 Alice 的签名。
	forged := prop
	forged.State.BalanceA, forged.State.BalanceB = 0, 100
	_, attackerPriv, _ := newAttackerKeys()
	forged.SigA = Sign(attackerPriv, forged.State)
	if _, err := bob.CounterSign(forged, alice.Pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("伪造签名应返回 ErrBadSignature，实际: %v", err)
	}

	// 双签校验同样要识别伪造。
	good := doUpdate(t, alice, bob, 40, 60)
	good.SigA = Sign(attackerPriv, good.State) // 替换为攻击者签名
	if err := VerifyFullySigned(good, privA.Public().(ed25519.PublicKey), bob.Pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("VerifyFullySigned 应拒绝伪造签名，实际: %v", err)
	}
}

// 跳号（v0 直接到 v2）同样违反单调性。
func TestSkippedVersionRejected(t *testing.T) {
	alice, bob := newPair(t)
	prop, err := alice.Propose(40, 60) // v1
	if err != nil {
		t.Fatal(err)
	}
	prop.State.Version = 5 // 篡改为跳号版本，并重新签 Alice 的名
	prop.SigA = Sign(alice.priv, prop.State)
	if _, err := bob.CounterSign(prop, alice.Pub); !errors.Is(err, ErrVersionNotMonotonic) {
		t.Fatalf("跳号应返回 ErrVersionNotMonotonic，实际: %v", err)
	}
}

// newAttackerKeys 生成一对与通道无关的攻击者密钥。
func newAttackerKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0xEE
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv, nil
}
