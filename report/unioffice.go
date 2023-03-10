package report

import (
	"flag"
	"fmt"
	"github.com/unidoc/unioffice/color"
	"github.com/unidoc/unioffice/document"
	"github.com/unidoc/unioffice/measurement"
	"os"
	"strings"
	"sync"
)

//unioffice 使用的是1.4.0 可以不用添加许可
// 报告导出docx
func UniofficeOutPutDocx(rep Report, wg *sync.WaitGroup) {

	// 定义一个名为 "test.v" 的 flag，并指定默认值为 false
	flag.Bool("test.v", false, "加上这个可以隐藏unioffice 输出的信息")

	doc := document.New()

	//设置页脚（不会）
	//footer := doc.AddFooter()
	//foo := footer.AddParagraph()
	//foo.Properties().SetAlignment(wml.ST_JcRight)
	//run1 := foo.AddRun()
	//run1.Properties().SetSize(8)
	//run1.AddText("qingmu漏洞扫描工具：")
	//link1 := foo.AddHyperLink()
	//link1.SetTarget("https://github.com/qmdemon/qingmu")
	//run1 = link1.AddRun()
	//run1.Properties().SetStyle("Hyperlink")
	//run1.AddText("https://github.com/qmdemon/qingmu")
	////paragraph.AddRun().AddText()
	//
	//section := foo.Properties().AddSection(wml.ST_SectionMarkContinuous)
	//section.SetFooter(footer, wml.ST_HdrFtrDefault)

	// 设置标题
	para := doc.AddParagraph()
	run := para.AddRun()
	para.SetStyle("Title")
	run.AddText(rep.Title)

	// 设置一级大纲
	para = doc.AddParagraph()
	para.SetStyle("Heading1")
	run = para.AddRun()
	run.AddText("漏洞地址")

	//设置正文
	para = doc.AddParagraph()
	para.Properties().SetFirstLineIndent(0.5 * measurement.Inch) //空格
	run = para.AddRun()
	run.AddText(rep.Addr)

	if rep.Detail.Links != nil {
		// 设置一级大纲
		para = doc.AddParagraph()
		para.SetStyle("Heading1")
		run = para.AddRun()
		run.AddText("参考链接")

		//设置正文
		para = doc.AddParagraph()
		para.Properties().SetFirstLineIndent(0.5 * measurement.Inch) //空格
		run = para.AddRun()
		for _, link := range rep.Detail.Links {
			run.AddText(link)
		}
		//run.AddText( strings.Join(rep.Detail.Links, "\r\n"))

	}
	if rep.Detail.Description != "" {
		// 设置一级大纲
		para = doc.AddParagraph()
		para.SetStyle("Heading1")
		run = para.AddRun()
		run.AddText("漏洞描述")

		//设置正文
		para = doc.AddParagraph()
		para.Properties().SetFirstLineIndent(0.5 * measurement.Inch) //空格
		run = para.AddRun()
		run.AddText(rep.Detail.Description)
		//text.AddText("\t" + rep.Detail.Description + "\r\n").Color("0000ff")
	}

	if rep.Detail.Version != "" {
		// 设置一级大纲
		para = doc.AddParagraph()
		para.SetStyle("Heading1")
		run = para.AddRun()
		run.AddText("漏洞版本")

		//设置正文
		para = doc.AddParagraph()
		para.Properties().SetFirstLineIndent(0.5 * measurement.Inch) //空格
		run = para.AddRun()
		run.AddText(rep.Detail.Version)
		//text.AddText("\t" + rep.Detail.Version + "\r\n").Color("0000ff")
	}

	// 设置一级大纲
	para = doc.AddParagraph()
	para.SetStyle("Heading1")
	run = para.AddRun()
	run.AddText("漏洞详情")

	//设置正文
	para = doc.AddParagraph()
	para.Properties().SetFirstLineIndent(0.5 * measurement.Inch) //空格
	run = para.AddRun()
	run.AddText(fmt.Sprintf("一共%d组payload", len(rep.Vulmap)))

	for i, p := range rep.Vulmap {

		// 设置二级大纲
		para = doc.AddParagraph()
		para.SetStyle("Heading2")
		run = para.AddRun()
		run.AddText(fmt.Sprintf("第%d组payload共发送%d次请求", i+1, len(p.Vul)))

		if p.Payload != "" {
			//设置正文
			para = doc.AddParagraph()
			para.Properties().SetFirstLineIndent(0.5 * measurement.Inch) //空格
			run = para.AddRun()
			run.AddText(fmt.Sprintf("第%d组paylaod:   %v ", i+1, p.Payload))
			//text.AddText(fmt.Sprintf("第%d组paylaod:\r\n %v \r\n", i+1, p.Payload)).Color("ff0000")
		}

		for j, key := range p.Vul {
			// 设置二级大纲
			para = doc.AddParagraph()
			para.SetStyle("Heading3")
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.AddText(fmt.Sprintf("发送第%d次请求:", j+1))

			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			//run.Properties().SetBold(true)
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(11)
			run.AddText("请求数据包")

			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(9)
			run.Properties().SetColor(color.Blue)
			run.AddText(key.Req)

			doc.AddParagraph().AddRun().AddText("") //添加空行
			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			//run.Properties().SetBold(true)
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(11)
			run.AddText("请求响应包")

			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(9)
			run.Properties().SetColor(color.Blue)
			run.AddText(key.Resp)

			doc.AddParagraph().AddRun().AddText("") //添加空行
			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			//run.Properties().SetBold(true)
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(11)
			run.AddText("漏洞存在判断条件")

			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(9)
			run.Properties().SetColor(color.Blue)
			run.AddText(key.Expression)

			doc.AddParagraph().AddRun().AddText("") //添加空行
			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			//run.Properties().SetBold(true)
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(11)
			run.AddText("结果：")

			//设置正文
			para = doc.AddParagraph()
			//para.Properties().SetFirstLineIndent(0.5 * measurement.Inch)  //空格
			run = para.AddRun()
			run.Properties().SetBold(true)
			run.Properties().SetSize(9)
			run.Properties().SetColor(color.Blue)
			run.AddText("存在漏洞")

		}
	}

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

	doc.SaveToFile("output/" + title + ".docx")

	wg.Done()
}
