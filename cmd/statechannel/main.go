// statechannel 运行一组脚本化的状态通道交互，并生成单文件 HTML 回放页。
//
// 用法：
//
//	go run ./cmd/statechannel [-out channel.html]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/TommyMarsss/state-channel/scenario"
)

func main() {
	out := flag.String("out", "channel.html", "输出 HTML 文件路径")
	flag.Parse()

	events := scenario.Run()
	if err := scenario.WriteHTML(events, *out); err != nil {
		fmt.Fprintln(os.Stderr, "生成失败:", err)
		os.Exit(1)
	}
	fmt.Printf("已生成 %s（%d 个事件），用浏览器打开即可逐步回放。\n", *out, len(events))
}
