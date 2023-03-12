package report

import (
	"qingmu/pocstruct"
)

type Report struct {
	Title  string // 漏洞标题
	Addr   string // 漏洞地址
	Detail pocstruct.Detail
	Vulmap []VulMap
}

type VulMap struct {
	Payload string
	Vul     []ReqResp
}

type ReqResp struct {
	Description string
	Req         string
	Resp        string
	Expression  string
}

//func (r Report) Output() string {
//	//a :=  *r.Vul.Load("get")
//
//}

// 设置漏洞详情
func (r *Report) SetVulInfo(description, req string, resp string, Expression string) {

	r.Vulmap[0].Vul = append(r.Vulmap[0].Vul, ReqResp{
		description, req, resp, Expression,
	})
}

// 设置报告标题
func (r *Report) SetTitle(title string) {
	r.Title = title
}
