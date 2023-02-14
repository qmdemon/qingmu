package report

import (
	"qingmu/pocstruct"
)

type Report struct {
	Title  string
	Detail pocstruct.Detail
	Vul    map[string]ReqResp
}

type ReqResp struct {
	Req  string
	Resp string
}
