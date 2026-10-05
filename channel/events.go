package channel

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
)

// Kind 是回放事件的类型。
type Kind string

const (
	KindChannelOpened Kind = "channel-opened" // 通道建立（初始状态 v1 双签）
	KindUpdateOK      Kind = "update-ok"      // 链下更新成功
	KindUpdateReject  Kind = "update-reject"  // 更新被拒（旧版本号 / 余额非法）
	KindDispute       Kind = "dispute"        // 一方发起链上争议
	KindChainReject   Kind = "chain-reject"   // 链上拒绝提交（伪造签名 / 账态非法）
	KindRefute        Kind = "refute"         // 争议期内欺诈证明（更高版本双签状态）
	KindRefuteReject  Kind = "refute-reject"  // 反驳被拒（版本不更高 / 超期 / 伪造）
	KindSettled       Kind = "settled"        // 争议期结束，链上最终结算
	KindNote          Kind = "note"           // 旁白：无协议响应的步骤（如消息丢失）
)

// Party 标识参与方位置。
type Party string

const (
	PartyA Party = "alice"
	PartyB Party = "bob"
)

// Event 记录一次通道交互，供 HTML 逐步回放。
type Event struct {
	Seq     int            `json:"seq"`
	Time    uint64         `json:"time"`
	Kind    Kind           `json:"kind"`
	Actor   Party          `json:"actor,omitempty"`
	Message string         `json:"message"`
	State   *StateSnapshot `json:"state,omitempty"` // 本次交互涉及的状态（含逐方签名校验结果）
	HeldA   *StateSnapshot `json:"heldA,omitempty"` // 事件发生后 Alice 持有的最新状态
	HeldB   *StateSnapshot `json:"heldB,omitempty"` // 事件发生后 Bob 持有的最新状态
	Chain   *ChainSnapshot `json:"chain,omitempty"` // 事件发生后的链上状态
	Detail  map[string]any `json:"detail,omitempty"`
}

// StateSnapshot 是回放界面使用的状态视图，附带逐方签名校验结果。
type StateSnapshot struct {
	ChannelID string `json:"channelId"`
	Version   uint64 `json:"version"`
	BalanceA  int64  `json:"balanceA"`
	BalanceB  int64  `json:"balanceB"`
	SigAHex   string `json:"sigA"`
	SigBHex   string `json:"sigB"`
	SigAValid bool   `json:"sigAValid"`
	SigBValid bool   `json:"sigBValid"`
}

// ChainSnapshot 是仲裁合约在某一时刻的只读视图。
type ChainSnapshot struct {
	Status       Status `json:"status"`
	BestVersion  uint64 `json:"bestVersion"`
	Deadline     uint64 `json:"deadline"`
	FinalVersion uint64 `json:"finalVersion,omitempty"`
	FinalA       int64  `json:"finalA,omitempty"`
	FinalB       int64  `json:"finalB,omitempty"`
}

func snapshotOf(ss *SignedState, pubA, pubB ed25519.PublicKey) *StateSnapshot {
	if ss == nil {
		return nil
	}
	sigAValid, sigBValid := ss.Verify(pubA, pubB)
	return &StateSnapshot{
		ChannelID: ss.ChannelID,
		Version:   ss.Version,
		BalanceA:  ss.BalanceA,
		BalanceB:  ss.BalanceB,
		SigAHex:   hex.EncodeToString(ss.SigA),
		SigBHex:   hex.EncodeToString(ss.SigB),
		SigAValid: sigAValid,
		SigBValid: sigBValid,
	}
}

// EventLog 收集事件，供 HTML 逐步回放。可通过 Bind 绑定通道与链，
// 每条事件落日志时自动附带当时双方持有状态与链状态的快照。
type EventLog struct {
	events []Event
	snap   func(*Event)
}

// Bind 把事件日志关联到一个链下通道与其仲裁合约。
func (l *EventLog) Bind(ch *Channel, bc *OnChain) {
	l.snap = func(e *Event) {
		e.HeldA = snapshotOf(ch.A.latest, ch.A.pub, ch.B.pub)
		e.HeldB = snapshotOf(ch.B.latest, ch.A.pub, ch.B.pub)
		e.Chain = &ChainSnapshot{
			Status:       bc.status,
			BestVersion:  bc.BestVersion(),
			Deadline:     bc.deadline,
			FinalVersion: bc.finalVer,
			FinalA:       bc.finalA,
			FinalB:       bc.finalB,
		}
	}
}

// Events 返回全部事件的副本。
func (l *EventLog) Events() []Event {
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}

func (l *EventLog) add(e Event) {
	e.Seq = len(l.events) + 1
	if l.snap != nil {
		l.snap(&e)
	}
	l.events = append(l.events, e)
}

// ExplainReason 把协议错误翻译成中文展示文本，仅供回放事件使用；
// 程序逻辑应通过 errors.Is 判定错误，不依赖任何一种自然语言文本。
func ExplainReason(err error) string {
	switch {
	case errors.Is(err, ErrWrongChannel):
		return "状态属于其他通道（通道 ID 不匹配）"
	case errors.Is(err, ErrStaleVersion):
		return "版本号未严格新于已知最新版本（重放被拒）"
	case errors.Is(err, ErrNegativeBalance):
		return "存在负余额（透支）"
	case errors.Is(err, ErrNotConserved):
		return "余额不满足通道存款守恒"
	case errors.Is(err, ErrProposalSig):
		return "提案发起方签名无效"
	case errors.Is(err, ErrFinalSig):
		return "双签状态签名校验失败（存在伪造签名）"
	case errors.Is(err, ErrExpiredRefute):
		return "已超过争议期，反驳证据不再被接受"
	case errors.Is(err, ErrNoDispute):
		return "该通道尚无进行中的争议"
	case errors.Is(err, ErrAlreadyDisputed):
		return "争议已存在，应提交更高版本证据而非重复发起"
	case errors.Is(err, ErrDisputeActive):
		return "争议期尚未结束，暂不能结算"
	case errors.Is(err, ErrChannelSettled):
		return "通道已完成最终结算"
	default:
		return err.Error()
	}
}
