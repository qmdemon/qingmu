package report

import (
	"fmt"
	"github.com/gingfrederik/docx"
	"strings"
	"sync"
)

func OutPutDocx(rep Report, wg *sync.WaitGroup) {
	//rep := <-do
	f := docx.NewFile()
	f.AddParagraph().AddText(rep.Title).Size(20)
	text := f.AddParagraph()

	text.AddText("漏洞地址：")
	text.AddText("\t" + rep.Addr + "\r\n").Color("0000ff")

	if rep.Detail.Links != nil {
		text.AddText("参考链接：")
		text.AddText("\t" + strings.Join(rep.Detail.Links, "\r\n") + "\r\n").Color("0000ff")

	}
	if rep.Detail.Description != "" {
		text.AddText("漏洞描述：")
		text.AddText("\t" + rep.Detail.Description + "\r\n").Color("0000ff")
	}

	if rep.Detail.Version != "" {
		text.AddText("漏洞版本：")
		text.AddText("\t" + rep.Detail.Version + "\r\n").Color("0000ff")
	}

	text.AddText("\r\n漏洞详情：\r\n").Size(15)
	text.AddText(fmt.Sprintf("一共发送%d次请求:\r\n", len(rep.Vul)))

	for i, key := range rep.Vul {
		text.AddText(fmt.Sprintf("发送第%d次请求:\r\n", i+1)).Color("ff0000")

		//text.AddText("请求URL：\r\n")
		//text.AddText("\t" + v.Url + "\r\n").Color("0000ff")
		text.AddText("请求数据包：\r\n")
		text.AddText(key.Req + "\r\n").Color("0000ff")
		text.AddText("请求响应包：\r\n")
		text.AddText(key.Resp + "\r\n").Color("0000ff")
		text.AddText("漏洞存在判断条件：\r\n")
		text.AddText(key.Expression + "\r\n").Color("0000ff")
		text.AddText("结果：\r\n")
		text.AddText("\t" + fmt.Sprintf("%v", "存在漏洞") + "\r\n").Color("0000ff")
	}

	f.Save("output/" + strings.ReplaceAll(rep.Title, "/", "") + ".docx")

	wg.Done()

}
