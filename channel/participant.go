package channel

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Role 标识参与方在通道中的位置（A 或 B）。
type Role int

const (
	RoleA Role = iota
	RoleB
)

// Participant 是一个链下参与方：持有密钥，保存自己见过的最新双签状态。
type Participant struct {
	Name   string
	Role   Role
	Pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	Latest SignedState // 本方持有的最新"双方签名"状态
}

// NewParticipant 从 32 字节种子确定性生成密钥，便于测试与回放复现。
func NewParticipant(name string, role Role, seed []byte) (*Participant, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("channel: 种子长度必须为 %d 字节", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Participant{Name: name, Role: role, Pub: pub, priv: priv}, nil
}

// Init 把创世状态装入参与方。
func (p *Participant) Init(genesis SignedState) {
	p.Latest = genesis
}

// Propose 基于本方最新状态构造下一版本（新余额），签上自己的签名，
// 得到一份"半签"提案发给对方。
func (p *Participant) Propose(balA, balB uint64) (SignedState, error) {
	next := State{
		ChannelID: p.Latest.State.ChannelID,
		Version:   p.Latest.State.Version + 1,
		BalanceA:  balA,
		BalanceB:  balB,
	}
	if err := ValidateTransition(p.Latest.State, next); err != nil {
		return SignedState{}, err
	}
	prop := SignedState{State: next}
	p.signSlot(&prop)
	return prop, nil
}

// CounterSign 是接收方的校验入口：只有版本号严格递增、总额守恒、
// 且对方签名有效的提案才会被会签。旧版本（重放攻击）在此被拒绝。
func (p *Participant) CounterSign(prop SignedState, peerPub ed25519.PublicKey) (SignedState, error) {
	if err := ValidateTransition(p.Latest.State, prop.State); err != nil {
		return SignedState{}, err
	}
	if err := verifyPeerSlot(prop, p.Role, peerPub); err != nil {
		return SignedState{}, err
	}
	p.signSlot(&prop)
	p.Latest = prop
	return prop, nil
}

// Confirm 是提案方的收口：收到对方会签后，校验双签完整再更新本地账本。
func (p *Participant) Confirm(st SignedState, peerPub ed25519.PublicKey) error {
	if err := ValidateTransition(p.Latest.State, st.State); err != nil {
		return err
	}
	if err := verifyPeerSlot(st, p.Role, peerPub); err != nil {
		return err
	}
	if !p.selfSigned(st) {
		return errors.New("channel: 缺少本方签名")
	}
	p.Latest = st
	return nil
}

// signSlot 在自己对应的签名位签名。
func (p *Participant) signSlot(st *SignedState) {
	sig := Sign(p.priv, st.State)
	if p.Role == RoleA {
		st.SigA = sig
	} else {
		st.SigB = sig
	}
}

// selfSigned 检查自己的签名位是否有效。
func (p *Participant) selfSigned(st SignedState) bool {
	if p.Role == RoleA {
		return ed25519.Verify(p.Pub, st.State.Bytes(), st.SigA)
	}
	return ed25519.Verify(p.Pub, st.State.Bytes(), st.SigB)
}

// verifyPeerSlot 校验提案中"对方"签名位上的签名。
func verifyPeerSlot(st SignedState, self Role, peerPub ed25519.PublicKey) error {
	var sig []byte
	if self == RoleA {
		sig = st.SigB
	} else {
		sig = st.SigA
	}
	if !ed25519.Verify(peerPub, st.State.Bytes(), sig) {
		return fmt.Errorf("%w: 对方签名无效", ErrBadSignature)
	}
	return nil
}
