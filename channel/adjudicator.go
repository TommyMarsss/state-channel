package channel

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrDisputeActive 表示已有进行中的争议，不能重复开启。
	ErrDisputeActive = errors.New("adjudicator: 已有进行中的争议")
	// ErrNoDispute 表示当前没有争议可反驳/结算。
	ErrNoDispute = errors.New("adjudicator: 没有进行中的争议")
	// ErrStaleVersion 表示提交的版本号不高于当前候选/已结算版本。
	ErrStaleVersion = errors.New("adjudicator: 版本号不够新")
	// ErrChallengeExpired 表示争议期已过，反驳证据不再被接受。
	ErrChallengeExpired = errors.New("adjudicator: 争议期已过，反驳无效")
	// ErrChallengeActive 表示争议期未结束，还不能结算。
	ErrChallengeActive = errors.New("adjudicator: 争议期未结束，无法结算")
)

// Adjudicator 模拟链上仲裁合约。它只信任密码学证据：
// 双方签名有效且版本号更高的状态永远胜出。
type Adjudicator struct {
	PubA, PubB      ed25519.PublicKey
	ChallengePeriod time.Duration // 争议期长度

	settledVersion uint64       // 已结算的最高版本（初始为 0，即创世状态）
	candidate      *SignedState // 当前争议中的候选结算状态
	deadline       time.Time    // 争议期截止时刻
	disputeOpen    bool
	final          *State // 最终结算结果
}

// NewAdjudicator 创建仲裁器。
func NewAdjudicator(pubA, pubB ed25519.PublicKey, challengePeriod time.Duration) *Adjudicator {
	return &Adjudicator{PubA: pubA, PubB: pubB, ChallengePeriod: challengePeriod}
}

// StartDispute 由任一方发起链上争议：提交自己持有的最新双签状态。
// 签名无效（伪造）或版本不高于已结算版本（重放）都会被拒绝。
// 受理后进入争议期，对方可在期内提交更高版本反驳。
func (ad *Adjudicator) StartDispute(st SignedState, now time.Time) error {
	if ad.disputeOpen {
		return ErrDisputeActive
	}
	if err := VerifyFullySigned(st, ad.PubA, ad.PubB); err != nil {
		return err
	}
	if st.State.Version <= ad.settledVersion {
		return fmt.Errorf("%w: v%d 不高于已结算版本 v%d", ErrStaleVersion, st.State.Version, ad.settledVersion)
	}
	candidate := st
	ad.candidate = &candidate
	ad.deadline = now.Add(ad.ChallengePeriod)
	ad.disputeOpen = true
	return nil
}

// Challenge 是欺诈证明入口：在争议期内，任何一方可提交版本号更高、
// 双签有效的状态，使当前候选（可能是有利于作弊方的旧状态）失效并被替换。
// 争议期过后提交的反驳一律拒绝。
func (ad *Adjudicator) Challenge(st SignedState, now time.Time) error {
	if !ad.disputeOpen {
		return ErrNoDispute
	}
	if !now.Before(ad.deadline) {
		return ErrChallengeExpired
	}
	if err := VerifyFullySigned(st, ad.PubA, ad.PubB); err != nil {
		return err
	}
	if st.State.Version <= ad.candidate.State.Version {
		return fmt.Errorf("%w: v%d 不高于当前候选 v%d", ErrStaleVersion, st.State.Version, ad.candidate.State.Version)
	}
	candidate := st
	ad.candidate = &candidate
	return nil
}

// Settle 在争议期结束后执行结算：候选状态成为最终账本。
func (ad *Adjudicator) Settle(now time.Time) (State, error) {
	if !ad.disputeOpen {
		return State{}, ErrNoDispute
	}
	if now.Before(ad.deadline) {
		return State{}, ErrChallengeActive
	}
	final := ad.candidate.State
	ad.settledVersion = final.Version
	ad.final = &final
	ad.disputeOpen = false
	ad.candidate = nil
	return final, nil
}

// DisputeOpen 报告是否有进行中的争议。
func (ad *Adjudicator) DisputeOpen() bool { return ad.disputeOpen }

// Candidate 返回当前争议候选状态（若有）。
func (ad *Adjudicator) Candidate() (SignedState, bool) {
	if ad.candidate == nil {
		return SignedState{}, false
	}
	return *ad.candidate, true
}

// Deadline 返回争议期截止时刻。
func (ad *Adjudicator) Deadline() time.Time { return ad.deadline }

// SettledVersion 返回已结算的最高版本。
func (ad *Adjudicator) SettledVersion() uint64 { return ad.settledVersion }

// Final 返回最终结算状态（若已结算）。
func (ad *Adjudicator) Final() (State, bool) {
	if ad.final == nil {
		return State{}, false
	}
	return *ad.final, true
}
