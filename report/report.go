package report

import (
	"qingmu/pocstruct"
)

type Report struct {
	Title  string // 漏洞标题
	Addr   string // 漏洞地址
	Detail pocstruct.Detail
	Vul    []ReqResp
}

type ReqResp struct {
	Req        string
	Resp       string
	Expression string
}

//func (r Report) Output() string {
//	//a :=  *r.Vul.Load("get")
//
//}

func (r *Report) Set(req string, resp string, Expression string) {
	r.Vul = append(r.Vul, ReqResp{
		req, resp, Expression,
	})
}
