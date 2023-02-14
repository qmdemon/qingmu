package report

import (
	"fmt"
	"github.com/gingfrederik/docx"
	"strings"
)

func OutPutDocx(rep Report, order []string) {
	f := docx.NewFile()
	f.AddParagraph().AddText(rep.Title).Size(20)
	text := f.AddParagraph()

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

	text.AddText("漏洞详情：\r\n").Size(15)

	for i, key := range order {
		text.AddText(fmt.Sprintf("第%d次请求:\r\n", i+1)).Color("ff0000")
		//text.AddText("请求URL：\r\n")
		//text.AddText("\t" + v.Url + "\r\n").Color("0000ff")
		text.AddText("请求数据包：\r\n")
		text.AddText(rep.Vul[key].Req + "\r\n").Color("0000ff")
		text.AddText("请求响应包：\r\n")
		text.AddText(rep.Vul[key].Resp + "\r\n").Color("0000ff")
		text.AddText("结果：\r\n")
		text.AddText("\t" + fmt.Sprintf("%v", "存在漏洞") + "\r\n").Color("0000ff")
	}

	f.Save(rep.Title + ".docx")

}
