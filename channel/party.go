package channel

import (
	"crypto/ed25519"
	"errors"
)

// 链下协议可能返回的错误。
var (
	ErrWrongChannel    = errors.New("state belongs to a different channel")
	ErrStaleVersion    = errors.New("state version is not strictly newer than the latest known version")
	ErrNegativeBalance = errors.New("state contains a negative balance")
	ErrNotConserved    = errors.New("state balances do not conserve the channel deposit")
	ErrProposalSig     = errors.New("proposer signature on proposal is invalid")
	ErrFinalSig        = errors.New("dual-signed state failed signature verification")
)

// Clock 是所有参与方与链共享的逻辑时钟（单调递增的逻辑时间）。
type Clock struct{ t uint64 }

func NewClock(start uint64) *Clock { return &Clock{t: start} }
func (c *Clock) Now() uint64       { return c.t }
func (c *Clock) Advance(d uint64) uint64 {
	c.t += d
	return c.t
}

// Participant 是一个通道参与方：持有自己的私钥、对方公钥与自己收到的最新双签状态。
type Participant struct {
	Name   Party
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	peer   ed25519.PublicKey
	latest *SignedState
}

// NewParty 生成一对 Ed25519 密钥并登记对方公钥。
func NewParty(name Party, peer ed25519.PublicKey) (*Participant, ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return &Participant{Name: name, priv: priv, pub: pub, peer: peer}, pub
}

// NewPartyWithKeys 用已有的密钥对构造参与方（测试用）。
func NewPartyWithKeys(name Party, priv ed25519.PrivateKey, peer ed25519.PublicKey) *Participant {
	pub := priv.Public().(ed25519.PublicKey)
	return &Participant{Name: name, priv: priv, pub: pub, peer: peer}
}

func (p *Participant) publicKey() ed25519.PublicKey { return p.pub }

// PublicKey 返回该参与方的 Ed25519 公钥（供链上合约登记/展示使用）。
func (p *Participant) PublicKey() ed25519.PublicKey { return p.pub }

// PrivateKey 返回该参与方的 Ed25519 私钥（演示/测试场景下构造伪造证据用）。
func (p *Participant) PrivateKey() ed25519.PrivateKey { return p.priv }

func (p *Participant) sign(s State) []byte {
	return ed25519.Sign(p.priv, s.SigningBytes())
}

// Latest 返回该方当前持有的最新双签状态（可能为 nil）。
func (p *Participant) Latest() *SignedState { return p.latest }

// LastVersion 返回该方已知的最新版本号；没有任何状态时为 0。
func (p *Participant) LastVersion() uint64 {
	if p.latest == nil {
		return 0
	}
	return p.latest.Version
}

// Proposal 是更新协议的第 1 步：发起方单方签名的新状态提案。
type Proposal struct {
	State
	SigProposer []byte
	From        Party
}

// Channel 编排两个参与方之间的链下消息交换，并把每次交互写入事件日志。
type Channel struct {
	ID    string
	A     *Participant
	B     *Participant
	Total int64 // 通道总存款，余额守恒常量
	clock *Clock
	log   *EventLog
}

// NewChannel 关联双方；双方公钥在此时互相确认。
func NewChannel(id string, a, b *Participant, total int64, clock *Clock, log *EventLog) *Channel {
	return &Channel{ID: id, A: a, B: b, Total: total, clock: clock, log: log}
}

func (c *Channel) party(p Party) *Participant {
	if p == PartyA {
		return c.A
	}
	return c.B
}

// validate 校验一个双签状态的通道归属、余额合法性与双方签名，
// 返回两个签名各自的校验结果，便于在回放界面逐方展示。
func (c *Channel) validate(ss *SignedState) (sigAValid, sigBValid bool, err error) {
	if ss.ChannelID != c.ID {
		return false, false, ErrWrongChannel
	}
	if ss.BalanceA < 0 || ss.BalanceB < 0 {
		return false, false, ErrNegativeBalance
	}
	if ss.BalanceA+ss.BalanceB != c.Total {
		return false, false, ErrNotConserved
	}
	sigAValid, sigBValid = ss.Verify(c.A.pub, c.B.pub)
	if !sigAValid || !sigBValid {
		return sigAValid, sigBValid, ErrFinalSig
	}
	return true, true, nil
}

// ingest 是接收方"装入"一个双签状态的统一入口：
// 先验签名与账态，再强制版本号必须严格新于自己已知的版本。
// 这是抵御重放攻击（提交旧版本状态）的核心检查。
func (c *Channel) ingest(p *Participant, ss *SignedState) (bool, bool, error) {
	aOK, bOK, err := c.validate(ss)
	if err != nil {
		return aOK, bOK, err
	}
	if ss.Version <= p.LastVersion() {
		return aOK, bOK, ErrStaleVersion
	}
	p.latest = ss
	return true, true, nil
}

// Open 建立通道：构造 v1 初始状态并由双方签名，双方各持一份。
func (c *Channel) Open(balA, balB int64) (*SignedState, error) {
	if balA < 0 || balB < 0 {
		return nil, ErrNegativeBalance
	}
	if balA+balB != c.Total {
		return nil, ErrNotConserved
	}
	s := State{ChannelID: c.ID, Version: 1, BalanceA: balA, BalanceB: balB}
	ss := NewSignedState(s, c.A.sign(s), c.B.sign(s))
	c.A.latest = ss
	c.B.latest = ss
	c.log.add(Event{
		Time:    c.clock.Now(),
		Kind:    KindChannelOpened,
		Message: "通道建立：初始状态 v1 由双方签名，各自保存",
		State:   snapshotOf(ss, c.A.pub, c.B.pub),
		Detail: map[string]any{
			"depositA": balA, "depositB": balB, "total": c.Total,
		},
	})
	return ss, nil
}

// Propose 是更新协议第 1 步：发起方构造 lastVersion+1 的新状态并签名。
// 它不改动任何一方持有的最新状态（对方可能不应答）。
func (c *Channel) Propose(from Party, balA, balB int64) (Proposal, error) {
	p := c.party(from)
	if p.latest == nil {
		return Proposal{}, errors.New("channel is not open")
	}
	s := State{
		ChannelID: c.ID,
		Version:   p.LastVersion() + 1,
		BalanceA:  balA,
		BalanceB:  balB,
	}
	return Proposal{State: s, SigProposer: p.sign(s), From: from}, nil
}

// Accept 是更新协议第 2 步：应答方校验提案（版本严格递增、余额合法、
// 发起方签名有效）后会签；应答方此时已持有完整双签状态并保存。
func (c *Channel) Accept(accepter Party, pr Proposal) (*SignedState, error) {
	ac := c.party(accepter)
	proposer := c.party(pr.From)

	if pr.ChannelID != c.ID {
		return nil, ErrWrongChannel
	}
	if pr.BalanceA < 0 || pr.BalanceB < 0 {
		return nil, ErrNegativeBalance
	}
	if pr.BalanceA+pr.BalanceB != c.Total {
		return nil, ErrNotConserved
	}
	if !ed25519.Verify(proposer.pub, pr.State.SigningBytes(), pr.SigProposer) {
		return nil, ErrProposalSig
	}
	// 严格递增：应答方只接受比自己已知版本更高的提案。
	if pr.Version <= ac.LastVersion() {
		return nil, ErrStaleVersion
	}

	ss := NewSignedState(pr.State, nil, nil)
	if pr.From == PartyA {
		ss.SigA = pr.SigProposer
		ss.SigB = ac.sign(pr.State)
	} else {
		ss.SigB = pr.SigProposer
		ss.SigA = ac.sign(pr.State)
	}
	// 应答方手中已是完整双签状态，直接保存。
	ac.latest = ss
	return ss, nil
}

// DeliverFinal 是更新协议第 3 步：会签后的状态送回发起方，
// 发起方重新校验双签与版本单调性后保存（此步可能因网络/对方离线而丢失）。
func (c *Channel) DeliverFinal(to Party, ss *SignedState) error {
	p := c.party(to)
	_, _, err := c.ingest(p, ss)
	return err
}

// Transfer 是一次完整成功的链下更新（提案 → 会签 → 回送），
// 双方保存同一版本，记录一条 update-ok 事件。
func (c *Channel) Transfer(from Party, amount int64) (*SignedState, error) {
	base := c.party(from).latest
	balA, balB := base.BalanceA, base.BalanceB
	if from == PartyA {
		balA -= amount
		balB += amount
	} else {
		balA += amount
		balB -= amount
	}

	pr, err := c.Propose(from, balA, balB)
	if err != nil {
		return nil, err
	}
	accepter := PartyB
	if from == PartyB {
		accepter = PartyA
	}
	ss, err := c.Accept(accepter, pr)
	if err != nil {
		c.logReject(from, pr.State, err)
		return nil, err
	}
	if err := c.DeliverFinal(from, ss); err != nil {
		c.logReject(from, ss.State, err)
		return nil, err
	}
	c.log.add(Event{
		Time:    c.clock.Now(),
		Kind:    KindUpdateOK,
		Actor:   from,
		Message: "链下更新成功：新版本由双方签名并交换",
		State:   snapshotOf(ss, c.A.pub, c.B.pub),
		Detail: map[string]any{
			"from": string(from), "amount": amount,
		},
	})
	return ss, nil
}

// Resubmit 模拟一方向对方/网络"重放提交"一个自己已持有的双签状态，
// 例如想把对自己不利的新版本撤回到旧版本。旧版本会被单调性检查拒绝。
func (c *Channel) Resubmit(submitter Party, ss *SignedState) error {
	p := c.party(submitter)
	aOK, bOK, err := c.ingest(p, ss)
	if err != nil {
		c.log.add(Event{
			Time:    c.clock.Now(),
			Kind:    KindUpdateReject,
			Actor:   submitter,
			Message: "链下提交被拒绝：" + ExplainReason(err),
			State:   snapshotOf(ss, c.A.pub, c.B.pub),
			Detail: map[string]any{
				"reason":      ExplainReason(err),
				"sigAValid":   aOK,
				"sigBValid":   bOK,
				"lastVersion": p.LastVersion(),
			},
		})
	}
	return err
}

func (c *Channel) logReject(from Party, s State, err error) {
	c.log.add(Event{
		Time:    c.clock.Now(),
		Kind:    KindUpdateReject,
		Actor:   from,
		Message: "链下更新被拒绝：" + ExplainReason(err),
		Detail:  map[string]any{"reason": ExplainReason(err), "version": s.Version},
	})
}

// Note 记录一条旁白事件（例如模拟消息丢失、对方离线等无协议响应的步骤）。
func (c *Channel) Note(msg string, detail map[string]any) {
	c.log.add(Event{Time: c.clock.Now(), Kind: KindNote, Message: msg, Detail: detail})
}
