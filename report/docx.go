package report

import (
	"fmt"
	"github.com/gingfrederik/docx"
	"os"
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

	text.AddText(fmt.Sprintf("一共%d组payload:\r\n", len(rep.Vulmap)))

	for i, p := range rep.Vulmap {

		if p.Payload != "" {
			text.AddText(fmt.Sprintf("第%d组paylaod:\r\n %v \r\n", i+1, p.Payload)).Color("ff0000")
		}

		text.AddText(fmt.Sprintf("第%d组payload共发送%d次请求:\r\n", i+1, len(p.Vul)))

		for j, key := range p.Vul {
			text.AddText(fmt.Sprintf("发送第%d次请求:\r\n", j+1)).Color("ff0000")

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

	}

	//folderName := time.Now().Format("2006-01-02")
	//folderPath := filepath.Join(basePath, folderName)
	if _, err := os.Stat("output"); os.IsNotExist(err) {
		// 必须分成两步
		// 先创建文件夹
		os.Mkdir("output", 0777)
		// 再修改权限
		os.Chmod("output", 0777)
	}

	title := strings.ReplaceAll(strings.ReplaceAll(rep.Title, "http://", "http__"), "https://", "https__")

	title = strings.ReplaceAll(title, "/", "_")
	title = strings.ReplaceAll(title, ":", "_")

	f.Save("output/" + title + ".docx")

	wg.Done()

}
