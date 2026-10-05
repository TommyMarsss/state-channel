package channel

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

var testEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const testChallengePeriod = 24 * time.Hour

// setupAdjudicator 构造仲裁器以及 v0..v3 的合法双签状态。
func setupAdjudicator(t *testing.T) (*Adjudicator, map[uint64]SignedState) {
	t.Helper()
	privA, privB := testKeys()
	pubA := privA.Public().(ed25519.PublicKey)
	pubB := privB.Public().(ed25519.PublicKey)

	states := map[uint64]SignedState{}
	balances := [][2]uint64{{50, 50}, {40, 60}, {35, 65}, {55, 45}}
	for v, b := range balances {
		s := State{ChannelID: 1, Version: uint64(v), BalanceA: b[0], BalanceB: b[1]}
		states[uint64(v)] = SignedState{State: s, SigA: Sign(privA, s), SigB: Sign(privB, s)}
	}
	return NewAdjudicator(pubA, pubB, testChallengePeriod), states
}

// 双方持有不同版本时，仲裁必须采信版本号更高的那个。
func TestAdjudicatorPrefersHigherVersion(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch

	// Bob 用对自己有利的旧状态 v2（35/65）发起争议。
	if err := ad.StartDispute(states[2], now); err != nil {
		t.Fatalf("StartDispute: %v", err)
	}
	// Alice 在争议期内用更新的 v3（55/45）反驳。
	if err := ad.Challenge(states[3], now.Add(time.Hour)); err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	final, err := ad.Settle(now.Add(testChallengePeriod + time.Minute))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if final.Version != 3 || final.BalanceA != 55 || final.BalanceB != 45 {
		t.Fatalf("应结算 v3 (55/45)，实际 v%d (%d/%d)", final.Version, final.BalanceA, final.BalanceB)
	}
}

// 争议期内无人反驳时，按候选状态结算。
func TestSettleWithoutChallenge(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch
	if err := ad.StartDispute(states[3], now); err != nil {
		t.Fatal(err)
	}
	final, err := ad.Settle(now.Add(testChallengePeriod))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if final.Version != 3 {
		t.Fatalf("应结算 v3，实际 v%d", final.Version)
	}
}

// 争议期过后，反驳证据不再有效，旧状态照常结算。
func TestChallengeAfterExpiryRejected(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch

	if err := ad.StartDispute(states[2], now); err != nil {
		t.Fatal(err)
	}
	// 争议期已过，Alice 才拿出 v3 反驳 —— 必须被拒绝。
	err := ad.Challenge(states[3], now.Add(testChallengePeriod))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("过期反驳应返回 ErrChallengeExpired，实际: %v", err)
	}
	final, err := ad.Settle(now.Add(testChallengePeriod + time.Minute))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if final.Version != 2 {
		t.Fatalf("过期反驳无效，应结算 v2，实际 v%d", final.Version)
	}
}

// 争议期结束前的最后一刻反驳仍然有效。
func TestChallengeJustBeforeDeadline(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch
	if err := ad.StartDispute(states[1], now); err != nil {
		t.Fatal(err)
	}
	if err := ad.Challenge(states[3], now.Add(testChallengePeriod-time.Second)); err != nil {
		t.Fatalf("截止前的反驳应被接受: %v", err)
	}
	final, err := ad.Settle(now.Add(testChallengePeriod))
	if err != nil {
		t.Fatal(err)
	}
	if final.Version != 3 {
		t.Fatalf("应结算 v3，实际 v%d", final.Version)
	}
}

// 伪造状态（签名不匹配）不能开启争议，也不能作为反驳证据。
func TestForgedStateRejectedOnChain(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch

	// 攻击者伪造 v9（0/100），Alice 的签名是假的。
	_, attackerPriv, _ := newAttackerKeys()
	forged := states[3]
	forged.State.Version = 9
	forged.State.BalanceA, forged.State.BalanceB = 0, 100
	forged.SigA = Sign(attackerPriv, forged.State)
	forged.SigB = Sign(attackerPriv, forged.State)

	if err := ad.StartDispute(forged, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("伪造状态开启争议应返回 ErrBadSignature，实际: %v", err)
	}

	// 合法争议开启后，伪造的反驳同样被拒绝。
	if err := ad.StartDispute(states[1], now); err != nil {
		t.Fatal(err)
	}
	if err := ad.Challenge(forged, now.Add(time.Hour)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("伪造反驳应返回 ErrBadSignature，实际: %v", err)
	}
	final, err := ad.Settle(now.Add(testChallengePeriod))
	if err != nil {
		t.Fatal(err)
	}
	if final.Version != 1 {
		t.Fatalf("伪造反驳不应生效，应结算 v1，实际 v%d", final.Version)
	}
}

// 反驳版本号必须严格高于候选版本，相同或更低都被拒绝。
func TestChallengeMustBeNewer(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch
	if err := ad.StartDispute(states[2], now); err != nil {
		t.Fatal(err)
	}
	if err := ad.Challenge(states[2], now.Add(time.Hour)); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("同版本反驳应返回 ErrStaleVersion，实际: %v", err)
	}
	if err := ad.Challenge(states[1], now.Add(time.Hour)); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("更低版本反驳应返回 ErrStaleVersion，实际: %v", err)
	}
}

// 已结算的版本不能再次用于开启争议（链上重放）。
func TestSettledVersionCannotBeRedispputed(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch
	if err := ad.StartDispute(states[2], now); err != nil {
		t.Fatal(err)
	}
	if _, err := ad.Settle(now.Add(testChallengePeriod)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(48 * time.Hour)
	if err := ad.StartDispute(states[2], later); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("用已结算版本再次争议应返回 ErrStaleVersion，实际: %v", err)
	}
	if err := ad.StartDispute(states[1], later); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("用更旧版本再次争议应返回 ErrStaleVersion，实际: %v", err)
	}
	// 更高版本仍可开启新一轮争议。
	if err := ad.StartDispute(states[3], later); err != nil {
		t.Fatalf("更高版本应可开启新争议: %v", err)
	}
}

// 争议期未结束时不能结算；没有争议时也不能结算/反驳。
func TestSettleAndChallengeGuards(t *testing.T) {
	ad, states := setupAdjudicator(t)
	now := testEpoch

	if err := ad.Challenge(states[1], now); !errors.Is(err, ErrNoDispute) {
		t.Fatalf("无争议时反驳应返回 ErrNoDispute，实际: %v", err)
	}
	if _, err := ad.Settle(now); !errors.Is(err, ErrNoDispute) {
		t.Fatalf("无争议时结算应返回 ErrNoDispute，实际: %v", err)
	}
	if err := ad.StartDispute(states[1], now); err != nil {
		t.Fatal(err)
	}
	if _, err := ad.Settle(now.Add(time.Hour)); !errors.Is(err, ErrChallengeActive) {
		t.Fatalf("争议期内结算应返回 ErrChallengeActive，实际: %v", err)
	}
	if err := ad.StartDispute(states[2], now.Add(time.Hour)); !errors.Is(err, ErrDisputeActive) {
		t.Fatalf("争议进行中再次开启应返回 ErrDisputeActive，实际: %v", err)
	}
}
