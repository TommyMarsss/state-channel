// Package channel 实现一个简化的双方链下状态通道（支付/记账通道）。
//
// 组件划分：
//   - types.go   ：通道状态、规范化签名载荷、双签状态及其校验
//   - party.go   ：参与方与链下通道（严格递增版本号的状态更新协议）
//   - chain.go   ：链上仲裁合约（争议期、欺诈证明/反驳、最终结算）
//   - events.go  ：供逐步回放使用的事件日志与只读视图
package channel

import (
	"crypto/ed25519"
	"encoding/binary"
)

// signingDomain 是签名载荷的域分隔前缀，避免本协议签名被复用到其他协议。
var signingDomain = []byte("state-channel/v1/state\n")

// State 是通道的一个账态。Version 必须严格单调递增。
type State struct {
	ChannelID string `json:"channelId"`
	Version   uint64 `json:"version"`
	BalanceA  int64  `json:"balanceA"`
	BalanceB  int64  `json:"balanceB"`
}

// SigningBytes 返回需要双方签名的规范化字节序列。
// 所有整数使用大端序定长编码，字符串带长度前缀，杜绝字段拼接歧义。
func (s State) SigningBytes() []byte {
	id := []byte(s.ChannelID)
	b := make([]byte, 0, len(signingDomain)+2+len(id)+8*3)
	b = append(b, signingDomain...)

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(id)))
	b = append(b, lenBuf[:]...)
	b = append(b, id...)

	var numBuf [8]byte
	binary.BigEndian.PutUint64(numBuf[:], s.Version)
	b = append(b, numBuf[:]...)
	binary.BigEndian.PutUint64(numBuf[:], uint64(s.BalanceA))
	b = append(b, numBuf[:]...)
	binary.BigEndian.PutUint64(numBuf[:], uint64(s.BalanceB))
	b = append(b, numBuf[:]...)
	return b
}

// SignedState 是携带双方签名的状态。链上仲裁只采信双签状态。
type SignedState struct {
	State
	SigA []byte `json:"-"`
	SigB []byte `json:"-"`
}

// NewSignedState 用两份签名组装双签状态（按参与方位置而非传入顺序归位）。
func NewSignedState(s State, sigA, sigB []byte) *SignedState {
	return &SignedState{State: s, SigA: sigA, SigB: sigB}
}

// Verify 分别校验 Alice / Bob 的签名，返回各自的校验结果。
func (ss *SignedState) Verify(pubA, pubB ed25519.PublicKey) (sigAValid, sigBValid bool) {
	msg := ss.State.SigningBytes()
	return ed25519.Verify(pubA, msg, ss.SigA),
		ed25519.Verify(pubB, msg, ss.SigB)
}

// VerifyBoth 在两份签名都有效时返回 true。
func (ss *SignedState) VerifyBoth(pubA, pubB ed25519.PublicKey) bool {
	a, b := ss.Verify(pubA, pubB)
	return a && b
}
