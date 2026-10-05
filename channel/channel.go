// Package channel 实现一个简化的双方链下状态通道（记账/支付通道）。
//
// 协议要点：
//   - 账本状态 State 携带严格递增的版本号 Version；
//   - 每次链下更新必须得到双方 ed25519 签名才生效；
//   - 任何一方都可将"双方签名的最新状态"提交给链上仲裁器 Adjudicator；
//   - 仲裁器只认版本号更高且签名有效的状态，争议期内可用更新版本反驳。
package channel

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrBadSignature 表示状态上至少一方的签名无法通过校验（伪造或篡改）。
	ErrBadSignature = errors.New("channel: 签名校验失败")
	// ErrVersionNotMonotonic 表示更新未携带严格递增的版本号（重放/回滚攻击）。
	ErrVersionNotMonotonic = errors.New("channel: 版本号必须严格递增")
	// ErrBalanceNotConserved 表示更新前后账本总额不守恒（凭空增发）。
	ErrBalanceNotConserved = errors.New("channel: 账本总额不守恒")
)

// State 是通道账本的一个版本。字段即全部签名内容。
type State struct {
	ChannelID uint64 // 通道标识，防止跨通道重放
	Version   uint64 // 单调递增的版本号，从 0 开始
	BalanceA  uint64 // 参与方 A 的余额
	BalanceB  uint64 // 参与方 B 的余额
}

// Bytes 返回状态的确定性规范编码，双方签名的就是这段字节。
// 固定 32 字节大端序编码，不依赖任何外部序列化库。
func (s State) Bytes() []byte {
	buf := make([]byte, 32)
	binary.BigEndian.PutUint64(buf[0:8], s.ChannelID)
	binary.BigEndian.PutUint64(buf[8:16], s.Version)
	binary.BigEndian.PutUint64(buf[16:24], s.BalanceA)
	binary.BigEndian.PutUint64(buf[24:32], s.BalanceB)
	return buf
}

// SignedState 是一个状态加上双方各自的签名。
type SignedState struct {
	State State
	SigA  []byte // A 对 State.Bytes() 的 ed25519 签名
	SigB  []byte // B 对 State.Bytes() 的 ed25519 签名
}

// Sign 用私钥对状态签名。
func Sign(priv ed25519.PrivateKey, s State) []byte {
	return ed25519.Sign(priv, s.Bytes())
}

// VerifyFullySigned 校验状态上双方签名均有效，任一失败即视为伪造状态。
func VerifyFullySigned(st SignedState, pubA, pubB ed25519.PublicKey) error {
	if !ed25519.Verify(pubA, st.State.Bytes(), st.SigA) {
		return fmt.Errorf("%w: 参与方 A 的签名无效", ErrBadSignature)
	}
	if !ed25519.Verify(pubB, st.State.Bytes(), st.SigB) {
		return fmt.Errorf("%w: 参与方 B 的签名无效", ErrBadSignature)
	}
	return nil
}

// ValidateTransition 强制链下更新规则：
// 同一通道、版本号严格 +1、资金总额守恒。
func ValidateTransition(prev, next State) error {
	if next.ChannelID != prev.ChannelID {
		return errors.New("channel: 通道 ID 不匹配")
	}
	if next.Version != prev.Version+1 {
		return fmt.Errorf("%w: 收到 v%d，期望 v%d", ErrVersionNotMonotonic, next.Version, prev.Version+1)
	}
	if next.BalanceA+next.BalanceB != prev.BalanceA+prev.BalanceB {
		return fmt.Errorf("%w: %d+%d != %d+%d",
			ErrBalanceNotConserved, next.BalanceA, next.BalanceB, prev.BalanceA, prev.BalanceB)
	}
	return nil
}

// Genesis 构造通道的初始状态（v0）并由双方签名。
func Genesis(channelID, balA, balB uint64, privA, privB ed25519.PrivateKey) SignedState {
	s := State{ChannelID: channelID, Version: 0, BalanceA: balA, BalanceB: balB}
	return SignedState{State: s, SigA: Sign(privA, s), SigB: Sign(privB, s)}
}
