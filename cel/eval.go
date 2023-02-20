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

//执行yaml
func EvalPoc(addr string, poc *pocstruct.Poc, filename string) (bool, report.Report) {

	rep := report.Report{}

	rulekeysmap := utils.RuleKeys(filename) // 读取poc 用于解决map 遍历无序问题

	//pocRuleMap := make(map[string]bool) //用于xray动态函数注入，如：r0() && r1() 进行cel计算
	c := InitCelOptions()
	if poc.Set != nil {
		c.UpdateSetCompileOptions(poc.Set, rulekeysmap["set"]) //set基础类型注入

	}
	//
	rep.Title = addr + "存在" + poc.Name + "漏洞" //报告title
	rep.Addr = addr
	rep.Detail = poc.Detail

	celVarMap := SetCelVar(c, poc, rulekeysmap["set"]) //获取set中的全局变量

	for _, key := range rulekeysmap["rules"] {

		rule := poc.Rules[key]
		outputkeys := rulekeysmap[key] //获取保存output 中的顺序

		//动态函数注入
		// 传递变量，动态向cel注入函数
		// 可以避免你无效请求
		c.UpdateFunctionOptions(key, addr, &rule, celVarMap, outputkeys, &rep)

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
	return outvalue, rep

}

// 执行单个rule
func EvalRule(addr string, rule *pocstruct.Rule, c CustomLib, celVarMap map[string]interface{}, outputkeys []string, rep *report.Report) bool {

	//var mux sync.RWMutex

	//fmt.Println(rule.Request.Path)

	//替换poc中的变量
	for k1, v1 := range celVarMap {
		_, isMap := v1.(map[string]string) //断言，判断是否为map
		if isMap {
			continue
		}
		value := fmt.Sprintf("%v", v1)
		//mux.RLock()
		for k2, v2 := range rule.Request.Headers {

			rule.Request.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)

		}
		//mux.Unlock()
		rule.Request.Path = strings.ReplaceAll(strings.TrimSpace(rule.Request.Path), "{{"+k1+"}}", value)
		rule.Request.Body = strings.ReplaceAll(strings.TrimSpace(rule.Request.Body), "{{"+k1+"}}", value)
	}

	resp, err := httpclient.HttpRequest(addr, &rule.Request, rule.Expression, rep)
	defer fasthttp.ReleaseResponse(resp) //在此释放resp资源

	//reqresp := report.ReqResp{
	//	Req:  oreq.String(),
	//	Resp: resp.String(),
	//}
	//rep.Vul[key] = reqresp
	//rep.Set(key, "", resp.String())

	if err != nil {

		log.Println("请求失败：", err)
		return false
	}
	//fmt.Println(resp.String())
	req, err := httpclient.NetHttpReq(addr, &rule.Request)
	defer req.Body.Close()
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

	if rule.OutPut != nil {
		//search := make(map[string]interface{})

		outmap := make(map[string]interface{})

		for _, k := range outputkeys {

			v := rule.OutPut[k]

			if outmap != nil {
				c.UpdateOutputCompileOptions(outmap) // output 类型注入
			}

			env, err := InitCelEnv(&c)
			if err != nil {
				log.Println("初始化cel环境错误", err)
				return false
			}

			out, err := Evaluate(env, fmt.Sprintf("%v", v), celVarMap)
			if err != nil {
				log.Println("执行rule.output错误：", v, err)
				return false
			}

			outmap[k] = out.Value()
			celVarMap[k] = out.Value()

		}
	}

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

	//if !outvalue {
	//	fmt.Println(resp.String())
	//}

	return outvalue

}

// 执行set，获取poc全局变量
func SetCelVar(c CustomLib, poc *pocstruct.Poc, setkeys []string) map[string]interface{} {

	env, err := InitCelEnv(&c)

	if err != nil {
		log.Println("初始化cel环境错误", err)
		return nil
	}

	celVarMap := make(map[string]interface{})

	for _, k := range setkeys {

		v := poc.Set[k]
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
//	if pocstruct.Set != nil {
//		c.UpdateSetCompileOptions(pocstruct.Set)
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
