package cel

import (
	"fmt"
	"github.com/valyala/fasthttp"
	"log"
	"qingmu/cel/proto"
	"qingmu/httpclient"
	"qingmu/pocstruct"
	"qingmu/report"
	"qingmu/utils"
	"strings"
)

// 执行yaml
func Eval(addr string, poc *pocstruct.Poc) (bool, report.Report) {
	if len(poc.Payloads.Payloads) == 0 {
		//fmt.Println(poc.Set)
		return EvalPoc(addr, poc)
		//return false, report.Report{}
	} else {

		//return false, report.Report{}

		set := poc.Set
		reps := report.Report{}
		for _, item := range poc.Payloads.Payloads {
			poc.Set = append(set, item)

			//fmt.Println(poc.Set)

			isvul, rep := EvalPoc(addr, poc)

			//fmt.Println(isvul)

			if isvul {
				if !poc.Payloads.Continue {
					return isvul, rep
				}

				reps.Addr = rep.Addr
				reps.Title = rep.Title
				reps.Detail = rep.Detail

				reps.Vulmap = append(reps.Vulmap, report.VulMap{
					Payload: item.Value.(string),
					Vul:     rep.Vulmap[0].Vul,
				})

			}
		}

		//fmt.Println(reps)

		if len(reps.Vulmap) != 0 {
			return true, reps
		}

		return false, reps

	}
}

//执行poc
func EvalPoc(addr string, poc *pocstruct.Poc) (bool, report.Report) {

	rep := report.Report{Vulmap: []report.VulMap{report.VulMap{}}}

	//rulekeysmap := utils.RuleKeys(filename) // 读取poc 用于解决map 遍历无序问题

	//pocRuleMap := make(map[string]bool) //用于xray动态函数注入，如：r0() && r1() 进行cel计算
	c := InitCelOptions()
	if poc.Set != nil {
		c.UpdateSetCompileOptions(poc.Set) //set基础类型注入

	}
	//
	rep.Title = addr + "存在" + poc.Name + "漏洞" //报告默认title
	rep.Addr = addr
	rep.Detail = poc.Detail

	celVarMap := SetCelVar(c, poc) //获取set中的全局变量

	for key, rule := range poc.Rules {

		//rule := poc.Rules[key]

		//fmt.Println(key, rule)

		//动态函数注入
		// 传递变量，动态向cel注入函数
		// 可以避免无效请求
		c.UpdateFunctionOptions(key, addr, rule, celVarMap, &rep)

	}

	env, err := InitCelEnv(&c)
	if err != nil {
		log.Println("初始化cel环境错误", err)
		//pocresult <- false
		return false, rep
	}

	//pocstruct.Expression = strings.ReplaceAll(pocstruct.Expression, "()", "('')")
	//fmt.Println("开始执行exp")

	out, err := Evaluate(env, poc.Expression, celVarMap)
	if err != nil {
		log.Println("执行Poc.Expression错误：", err)
		//pocresult <- false
		return false, rep
	}

	outvalue, isbool := out.Value().(bool)

	if !isbool {
		log.Println("执行poc.Expression结果不为bool值:", out.Value())
		//pocresult <- false
		return false, rep
	}
	//fmt.Println()

	//pocresult <- outvalue
	//rep.SetTitle(celVarMap["title"])
	if celVarMap["reptitle"] != nil {
		rep.SetTitle(fmt.Sprintf("%v存在%s漏洞", celVarMap["reptitle"], poc.Name))
	}
	return outvalue, rep

}

// 执行单个rule
func EvalRule(addr string, rule pocstruct.Rule, c CustomLib, celVarMap map[string]interface{}, rep *report.Report) bool {

	//var mux sync.RWMutex

	//fmt.Println(celVarMap)

	//替换poc中的变量

	//headers := make(map[string]string)
	//var path string
	//var body string

	var rulereq pocstruct.Request = pocstruct.Request{
		Method:          rule.Request.Method,
		Headers:         make(map[string]string),
		FollowRedirects: rule.Request.FollowRedirects,
	}

	for k1, v1 := range celVarMap {
		_, isMap := v1.(map[string]string) //断言，判断是否为map
		if isMap {
			continue
		}
		value := fmt.Sprintf("%v", v1)
		for k2, v2 := range rule.Request.Headers {

			if strings.Contains(v2, "{{"+k1+"}}") {
				rulereq.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
				//fmt.Println(rulereq.Headers[k2], k1)
			} else {
				rulereq.Headers[k2] = v2
			}

		}
		//fmt.Println(k1, rulereq.Headers)
		if strings.Contains(rule.Request.Path, "{{"+k1+"}}") {
			rulereq.Path = strings.ReplaceAll(strings.TrimSpace(rule.Request.Path), "{{"+k1+"}}", value)
		} else {
			rulereq.Path = strings.TrimSpace(rule.Request.Path)
		}
		if strings.Contains(rule.Request.Body, "{{"+k1+"}}") {
			rulereq.Body = strings.ReplaceAll(rule.Request.Body, "{{"+k1+"}}", value)
		} else {
			rulereq.Body = rule.Request.Body
		}

		//rule.Request.Path = path
		//rule.Request.Body = body
	}

	//rule.Request.Headers = headers
	//rule.Request.Path = path
	//rule.Request.Body = body

	resp, req, err := httpclient.HttpRequest(addr, rulereq, rule.Expression, rep)
	defer fasthttp.ReleaseResponse(resp.Resp) //在此释放resp资源

	// 重新赋值poc中的变量，让下一个payload可以获取到{{}}
	//fmt.Println(headers)

	//fmt.Println(rule.Request.Headers, headers)

	//reqresp := report.ReqResp{
	//	Req:  oreq.String(),
	//	Resp: resp.String(),
	//}
	//rep.Vul[key] = reqresp
	//rep.SetVulInfo(key, "", resp.String())

	if err != nil {

		log.Println("请求失败：", err)
		return false
	}
	//fmt.Println(resp.String())
	//req, err := httpclient.NetHttpReq(addr, &rule.Request)
	//defer req.Body.Close()
	if err != nil {

		log.Println("获取请求：", err)
		return false
	}

	pbresp, err := proto.GetResponse(resp, req)
	if err != nil {

		log.Println("生成protoResponse错误：", err)
		return false
	}
	celVarMap["response"] = pbresp

	pbreq, err := proto.GetRequest(req)
	if err != nil {

		log.Println("生成protoRequest错误：", err)
		return false
	}
	celVarMap["request"] = pbreq

	env, err := InitCelEnv(&c)
	if err != nil {
		log.Println("初始化cel环境错误", err)
		return false
	}

	out, err := Evaluate(env, rule.Expression, celVarMap)
	if err != nil {
		log.Println("执行rule.Expression错误：", err)
		return false
	}

	outvalue, isbool := out.Value().(bool)

	if !isbool {
		log.Println("执行rule.Expression结果不为bool值：", out.Value())
		return false
	}
	//判断rule.Expression 结果是否false ，若为false  就不执行output
	if !outvalue {
		return outvalue
	}

	if rule.OutPut != nil {
		//search := make(map[string]interface{})

		outmap := make(map[string]interface{})

		for _, item := range rule.OutPut {

			k := item.Key.(string)
			v := item.Value.(string)

			if outmap != nil {
				c.UpdateOutputCompileOptions(outmap) // output 类型注入
			}

			env, err := InitCelEnv(&c)
			if err != nil {
				log.Println("初始化cel环境错误", err)
				return false
			}

			out, err := Evaluate(env, v, celVarMap)
			if err != nil {
				if k == "reptitle" { //判断是否是获取reptitle 错误，若是reptitle错误，设置celVarMap["reptitle"] = nil 即跳过
					continue
				} else {
					log.Println("执行rule.output错误：", v, err)
					return false
				}

			}

			outmap[k] = out.Value()
			celVarMap[k] = out.Value()

		}
	}

	//if !outvalue {
	//	fmt.Println(resp.String())
	//}

	return outvalue

}

// 执行set，获取poc全局变量
func SetCelVar(c CustomLib, poc *pocstruct.Poc) map[string]interface{} {

	env, err := InitCelEnv(&c)

	if err != nil {
		log.Println("初始化cel环境错误", err)
		return nil
	}

	celVarMap := make(map[string]interface{})

	for _, item := range poc.Set {

		k := item.Key.(string)
		v := item.Value.(string)
		//fmt.Println(k, v)
		if v == "newReverse()" {
			celVarMap[k] = utils.NewReverse()
			continue
		}

		out, err := Evaluate(env, v, celVarMap)
		if err != nil {
			log.Println("执行setcelvar错误：", err)
			continue
		}

		switch value := out.Value().(type) {
		case *proto.UrlType:
			celVarMap[k] = UrlTypeToString(value)
		case int64:
			celVarMap[k] = int(value)
		default:
			//fmt.Println(out)
			celVarMap[k] = fmt.Sprintf("%v", out)
		}
	}
	return celVarMap

}

//urltype类型转string
func UrlTypeToString(u *proto.UrlType) string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteByte('/')
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

////生产根据pocRuleMap 生产新的环境用于计算poc.Expression
//func NewCelEnv(pocRuleMap map[string]bool, pocstruct *pocstruct.Poc) (*cel.Env, error) {
//	c := InitCelOptions(pocRuleMap)
//
//	if pocstruct.SetVulInfo != nil {
//		c.UpdateSetCompileOptions(pocstruct.SetVulInfo)
//
//	}
//
//	env, err := InitCelEnv(&c)
//	if err != nil {
//		log.Println("初始化cel环境错误", err)
//		return nil, err
//	}
//
//	return env, nil
//
//}
