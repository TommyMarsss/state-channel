// 命令 state-channel 驱动一组双方链下状态通道交互序列（正常更新、重放攻击、
// 链上争议、争议期欺诈证明、过期反驳、伪造状态），并把全过程导出为单一、
// 自包含的静态回放页面 replay.html（数据与逻辑全部内嵌，可直接用浏览器打开）。
package main

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/TommyMarsss/state-channel/channel"
)

//go:embed web/template.html
var htmlTemplate []byte

const deposit int64 = 100
const disputePeriod uint64 = 10

// Scenario 是一组共享一条事件日志的通道交互。
type Scenario struct {
	ID        string          `json:"id"`
	Title     string          `json:"title"`
	Narrative string          `json:"narrative"`
	Total     int64           `json:"total"`
	PubA      string          `json:"pubA"`
	PubB      string          `json:"pubB"`
	Events    []channel.Event `json:"events"`
}

// Report 是嵌入回放页面的完整数据。
type Report struct {
	Tool          string     `json:"tool"`
	DisputePeriod uint64     `json:"disputePeriod"`
	Deposit       int64      `json:"deposit"`
	Scenarios     []Scenario `json:"scenarios"`
}

func main() {
	scenarios := []Scenario{
		scenarioNormalAndReplay(),
		scenarioSuccessfulRefutation(),
		scenarioExpiredRefutation(),
		scenarioForgedState(),
	}

	report := Report{
		Tool:          "state-channel demo",
		DisputePeriod: disputePeriod,
		Deposit:       deposit,
		Scenarios:     scenarios,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatal(err)
	}
	// 防止 JSON 中的尖括号提前闭合 <script>。
	data = bytes.ReplaceAll(data, []byte("<"), []byte("\\u003c"))
	data = bytes.ReplaceAll(data, []byte(">"), []byte("\\u003e"))
	page := bytes.Replace(htmlTemplate, []byte("/*__REPORT_JSON__*/"), data, 1)

	if err := os.WriteFile("replay.html", page, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("已生成 replay.html（%d 个场景），用浏览器打开即可逐步回放。\n", len(scenarios))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func newSetup(id string) (*channel.Clock, *channel.Channel, *channel.OnChain, *channel.EventLog,
	*channel.Participant, *channel.Participant) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	a := channel.NewPartyWithKeys(channel.PartyA, privA, pubB)
	b := channel.NewPartyWithKeys(channel.PartyB, privB, pubA)
	log := &channel.EventLog{}
	clock := channel.NewClock(0)
	ch := channel.NewChannel(id, a, b, deposit, clock, log)
	bc := channel.NewOnChain(id, pubA, pubB, deposit, disputePeriod, clock, log)
	log.Bind(ch, bc)
	return clock, ch, bc, log, a, b
}

func scenarioOf(id, title, narrative string,
	a, b *channel.Participant, log *channel.EventLog) Scenario {
	return Scenario{
		ID:        id,
		Title:     title,
		Narrative: narrative,
		Total:     deposit,
		PubA:      hex.EncodeToString(a.PublicKey()),
		PubB:      hex.EncodeToString(b.PublicKey()),
		Events:    log.Events(),
	}
}

// 场景一：正常链下更新，随后一方尝试重放对自己不利的旧版本。
func scenarioNormalAndReplay() Scenario {
	clock, ch, _, log, a, b := newSetup("ch-normal")

	must2(ch.Open(100, 0)) // t=0 v1
	clock.Advance(1)
	must2(ch.Transfer(channel.PartyA, 10)) // t=1 v2: 90/10
	clock.Advance(1)
	v2 := ch.A.Latest()
	must2(ch.Transfer(channel.PartyB, 4)) // t=2 v3: 94/6
	clock.Advance(1)
	// Alice 反悔：试图把双签的旧版本 v2 重新提交，撤回到对自己更有利的账态。
	_ = ch.Resubmit(channel.PartyA, v2) // t=3 被单调性检查拒绝

	return scenarioOf("normal", "场景一：正常更新与重放攻击被拒",
		"双方先完成两笔链下转账。Alice 在 v3 中余额较少，于是试图重放旧的双签状态 v2 把账态撤回；版本号必须严格递增，重放被拒绝。",
		a, b, log)
}

// 场景二：回送消息丢失导致双方版本分叉；争议期内高版本反驳成功。
func scenarioSuccessfulRefutation() Scenario {
	clock, ch, bc, log, a, b := newSetup("ch-refute-ok")

	must2(ch.Open(100, 0)) // v1
	clock.Advance(1)
	must2(ch.Transfer(channel.PartyA, 10)) // v2 90/10，双方一致
	clock.Advance(1)

	// v3 提案：Alice 签名 → Bob 会签保存；会签状态回送 Alice 的消息丢失。
	pr, err := ch.Propose(channel.PartyA, 80, 20)
	must(err)
	v3, err := ch.Accept(channel.PartyB, pr)
	must(err)
	_ = v3
	ch.Note("网络故障：Bob 会签后的 v3 状态在回送途中丢失，Alice 仍停留在 v2，双方持有版本分叉",
		map[string]any{"heldByA": ch.A.LastVersion(), "heldByB": ch.B.LastVersion()})

	clock.Advance(1)
	ch.Note("Alice 发起新的链下更新请求，Bob 已离线不应答，等待超时……", nil)
	clock.Advance(1)
	// Alice 只能提交自己持有的最新双签状态 v2 上链。
	must(bc.Dispute(channel.PartyA, ch.A.Latest())) // t=4，争议期截止 t=14

	clock.Advance(5) // t=9，仍在争议期内
	must(bc.Refute(channel.PartyB, ch.B.Latest()))

	clock.Advance(6) // t=15，争议期结束
	_, err = bc.Settle()
	must(err)

	return scenarioOf("refute-ok", "场景二：链上争议与争议期内欺诈证明（反驳成功）",
		"v3 的回送消息丢失：Bob 持有 v3，Alice 只知道 v2。Alice 超时后用 v2 发起链上争议；Bob 在争议期内提交更高版本的双签状态 v3 作为欺诈证明，v2 结算失效，最终按 v3 结算。",
		a, b, log)
}

// 场景三：同样的版本分叉，但反驳晚于争议期截止，旧状态结算生效。
func scenarioExpiredRefutation() Scenario {
	clock, ch, bc, log, a, b := newSetup("ch-refute-late")

	must2(ch.Open(100, 0))
	clock.Advance(1)
	must2(ch.Transfer(channel.PartyA, 10)) // v2
	clock.Advance(1)

	pr, err := ch.Propose(channel.PartyA, 80, 20)
	must(err)
	v3, err := ch.Accept(channel.PartyB, pr)
	must(err)
	_ = v3
	ch.Note("v3 回送消息丢失：Alice 持有 v2，Bob 持有 v3",
		map[string]any{"heldByA": ch.A.LastVersion(), "heldByB": ch.B.LastVersion()})

	clock.Advance(2)
	must(bc.Dispute(channel.PartyA, ch.A.Latest())) // t=4，截止 t=14
	ch.Note("Bob 在此期间离线，没有监控链上争议……", nil)

	clock.Advance(12) // t=16，已超过争议期
	err = bc.Refute(channel.PartyB, ch.B.Latest())
	_ = err // 预期 ErrExpiredRefute，事件已记录
	_, err = bc.Settle()
	must(err) // 按 v2 结算

	return scenarioOf("refute-late", "场景三：超过争议期的反驳不再有效",
		"与场景二相同的版本分叉，但 Bob 直到争议期结束后才上线提交 v3。超过争议期后反驳证据不再被接受，旧的 v2 状态成为最终结算——这正是争议期设计的刚性边界。",
		a, b, log)
}

// 场景四：伪造签名状态上链被拒，随后合法争议正常结算。
func scenarioForgedState() Scenario {
	clock, ch, bc, log, a, b := newSetup("ch-forged")

	must2(ch.Open(100, 0))
	clock.Advance(1)
	must2(ch.Transfer(channel.PartyA, 10)) // v2 90/10
	clock.Advance(1)

	// 攻击者构造一个对自己有利的 v99 状态，骗到 Alice 的签名，
	// 但 Bob 的签名位置伪造（用第三方密钥）。
	_, privMallory, _ := ed25519.GenerateKey(nil)
	forgedState := channel.State{ChannelID: "ch-forged", Version: 99, BalanceA: 0, BalanceB: 100}
	forged := channel.NewSignedState(forgedState,
		ed25519.Sign(a.PrivateKey(), forgedState.SigningBytes()),
		ed25519.Sign(privMallory, forgedState.SigningBytes()),
	)
	ch.Note("攻击者提交伪造的 v99 状态：Alice 签名为真，但 Bob 签名位置是伪造的", nil)
	err := bc.Dispute(channel.PartyB, forged)
	_ = err // 预期 ErrFinalSig

	clock.Advance(1)
	must(bc.Dispute(channel.PartyA, ch.A.Latest())) // 合法争议 v2
	clock.Advance(disputePeriod + 1)
	_, err = bc.Settle()
	must(err)

	return scenarioOf("forged", "场景四：伪造签名状态被链上拒绝",
		"链上仲裁对提交的状态逐方核验 Ed25519 签名。伪造状态因 Bob 签名不匹配被直接拒绝，仲裁合约保持开启；随后合法的 v2 双签状态正常进入争议与结算流程。",
		a, b, log)
}

func must(err error) {
	if err != nil {
		fatal(err)
	}
}

func must2(_ *channel.SignedState, err error) { must(err) }
