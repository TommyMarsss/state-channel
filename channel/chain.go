package channel

import (
	"crypto/ed25519"
	"errors"
)

// 链上仲裁可能返回的错误。
var (
	ErrNoDispute       = errors.New("no dispute has been opened for this channel")
	ErrAlreadyDisputed = errors.New("dispute already open; submit newer evidence instead of opening another")
	ErrDisputeActive   = errors.New("dispute period has not elapsed; the channel cannot be settled yet")
	ErrChannelSettled  = errors.New("channel has already been settled")
	ErrExpiredRefute   = errors.New("dispute period has elapsed; refutation evidence is no longer accepted")
)

// Status 是通道在链上的生命周期状态。
type Status string

const (
	StatusOpen     Status = "open"     // 尚无争议，通道在链上视为开启
	StatusDisputed Status = "disputed" // 争议期进行中，可提交更高版本证据
	StatusSettled  Status = "settled"  // 争议期结束，已按最高版本状态最终结算
)

// validateState 是链上使用的无状态校验器：通道归属、余额非负、
// 存款守恒，并分别核验 Alice/Bob 的签名。
func validateState(id string, total int64, pubA, pubB ed25519.PublicKey, ss *SignedState) (sigAValid, sigBValid bool, err error) {
	if ss.ChannelID != id {
		return false, false, ErrWrongChannel
	}
	if ss.BalanceA < 0 || ss.BalanceB < 0 {
		return false, false, ErrNegativeBalance
	}
	if ss.BalanceA+ss.BalanceB != total {
		return false, false, ErrNotConserved
	}
	sigAValid, sigBValid = ss.Verify(pubA, pubB)
	if !sigAValid || !sigBValid {
		return sigAValid, sigBValid, ErrFinalSig
	}
	return true, true, nil
}

// OnChain 是简化的链上仲裁合约。每个通道一个实例，
// 所有时间读取同一个逻辑时钟。
type OnChain struct {
	id     string
	pubA   ed25519.PublicKey
	pubB   ed25519.PublicKey
	total  int64
	period uint64 // 争议期长度（逻辑时间单位）
	clock  *Clock
	log    *EventLog

	status   Status
	best     *SignedState // 争议期内已采信的最高版本双签状态
	firstBy  Party        // 首个争议的发起方
	deadline uint64       // 争议期截止时间（含该时刻仍可反驳）
	finalA   int64
	finalB   int64
	finalVer uint64
}

// NewOnChain 部署一个通道的仲裁合约。
func NewOnChain(id string, pubA, pubB ed25519.PublicKey, total int64, disputePeriod uint64, clock *Clock, log *EventLog) *OnChain {
	return &OnChain{
		id: id, pubA: pubA, pubB: pubB, total: total,
		period: disputePeriod, clock: clock, log: log,
		status: StatusOpen,
	}
}

// Status 返回链上当前状态。
func (bc *OnChain) Status() Status { return bc.status }

// BestVersion 返回争议期内已采信的最高版本号（无争议时为 0）。
func (bc *OnChain) BestVersion() uint64 {
	if bc.best == nil {
		return 0
	}
	return bc.best.Version
}

// Deadline 返回争议期截止时间。
func (bc *OnChain) Deadline() uint64 { return bc.deadline }

// Final 在结算完成后返回获胜版本与双方最终余额。
func (bc *OnChain) Final() (version uint64, balanceA, balanceB int64, ok bool) {
	if bc.status != StatusSettled {
		return 0, 0, 0, false
	}
	return bc.finalVer, bc.finalA, bc.finalB, true
}

// Dispute 对应"一方链下请求超时后，提交自己持有的最新双签状态上链"。
// 链只接受通道正确、余额守恒且双方签名都有效的状态；
// 伪造状态（任一签名不匹配）在此被拒绝，通道保持开启。
func (bc *OnChain) Dispute(actor Party, ss *SignedState) error {
	switch bc.status {
	case StatusSettled:
		return ErrChannelSettled
	case StatusDisputed:
		return ErrAlreadyDisputed
	}
	aOK, bOK, err := validateState(bc.id, bc.total, bc.pubA, bc.pubB, ss)
	if err != nil {
		bc.log.add(Event{
			Time:    bc.clock.Now(),
			Kind:    KindChainReject,
			Actor:   actor,
			Message: "链上拒绝争议申请：" + ExplainReason(err),
			State:   snapshotOf(ss, bc.pubA, bc.pubB),
			Detail: map[string]any{
				"reason":    ExplainReason(err),
				"sigAValid": aOK,
				"sigBValid": bOK,
			},
		})
		return err
	}

	now := bc.clock.Now()
	bc.status = StatusDisputed
	bc.best = ss
	bc.firstBy = actor
	bc.deadline = now + bc.period
	bc.log.add(Event{
		Time:    bc.clock.Now(),
		Kind:    KindDispute,
		Actor:   actor,
		Message: "链下协商超时，发起链上争议并进入争议期",
		State:   snapshotOf(ss, bc.pubA, bc.pubB),
		Detail: map[string]any{
			"submittedVersion": ss.Version,
			"deadline":         bc.deadline,
			"disputePeriod":    bc.period,
		},
	})
	return nil
}

// Refute 处理争议期内的欺诈证明：提交一个比已采信版本更高的双签状态。
//   - 争议期已过：证据不再被接受（旧结算维持有效）；
//   - 证据伪造（签名不匹配）：拒绝；
//   - 版本号不更高：旧状态仍然有效，拒绝；
//   - 版本号更高且双签有效：旧状态结算失效，链上采信新版本。
func (bc *OnChain) Refute(actor Party, ss *SignedState) error {
	if bc.status != StatusDisputed {
		return ErrNoDispute
	}
	now := bc.clock.Now()
	if now > bc.deadline {
		bc.log.add(Event{
			Time:    now,
			Kind:    KindRefuteReject,
			Actor:   actor,
			Message: "反驳已超过争议期，证据不再有效：旧状态结算维持不变",
			State:   snapshotOf(ss, bc.pubA, bc.pubB),
			Detail: map[string]any{
				"reason":           ExplainReason(ErrExpiredRefute),
				"now":              now,
				"deadline":         bc.deadline,
				"evidenceVersion":  ss.Version,
				"settledAtVersion": bc.best.Version,
			},
		})
		return ErrExpiredRefute
	}

	aOK, bOK, err := validateState(bc.id, bc.total, bc.pubA, bc.pubB, ss)
	if err != nil {
		bc.log.add(Event{
			Time:    now,
			Kind:    KindRefuteReject,
			Actor:   actor,
			Message: "反驳证据被拒绝：" + ExplainReason(err),
			State:   snapshotOf(ss, bc.pubA, bc.pubB),
			Detail: map[string]any{
				"reason":    ExplainReason(err),
				"sigAValid": aOK,
				"sigBValid": bOK,
			},
		})
		return err
	}

	if ss.Version <= bc.best.Version {
		bc.log.add(Event{
			Time:    now,
			Kind:    KindRefuteReject,
			Actor:   actor,
			Message: "反驳证据版本号不高于已采信版本，旧状态仍然有效",
			State:   snapshotOf(ss, bc.pubA, bc.pubB),
			Detail: map[string]any{
				"reason":          ExplainReason(ErrStaleVersion),
				"evidenceVersion": ss.Version,
				"bestVersion":     bc.best.Version,
				"deadline":        bc.deadline,
			},
		})
		return ErrStaleVersion
	}

	old := bc.best
	bc.best = ss
	bc.log.add(Event{
		Time:    now,
		Kind:    KindRefute,
		Actor:   actor,
		Message: "争议期内提交更高版本双签状态作为欺诈证明：旧版本结算失效，链上采信新版本",
		State:   snapshotOf(ss, bc.pubA, bc.pubB),
		Detail: map[string]any{
			"invalidatedVersion": old.Version,
			"newBestVersion":     ss.Version,
			"deadline":           bc.deadline,
		},
	})
	return nil
}

// Settle 在争议期结束后按已采信的最高版本状态执行最终结算。
// 争议期未结束时拒绝结算。
func (bc *OnChain) Settle() (*SignedState, error) {
	switch bc.status {
	case StatusSettled:
		return bc.best, ErrChannelSettled
	case StatusOpen:
		return nil, ErrNoDispute
	}
	now := bc.clock.Now()
	if now < bc.deadline {
		return nil, ErrDisputeActive
	}
	bc.finalVer = bc.best.Version
	bc.finalA = bc.best.BalanceA
	bc.finalB = bc.best.BalanceB
	bc.status = StatusSettled
	bc.log.add(Event{
		Time:    now,
		Kind:    KindSettled,
		Message: "争议期结束，无人再能反驳：链上按最高版本双签状态最终结算",
		State:   snapshotOf(bc.best, bc.pubA, bc.pubB),
		Detail: map[string]any{
			"winningVersion": bc.best.Version,
			"balanceA":       bc.finalA,
			"balanceB":       bc.finalB,
			"firstDisputeBy": string(bc.firstBy),
		},
	})
	return bc.best, nil
}
