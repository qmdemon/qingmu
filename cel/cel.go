package cel

import (
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v2"
	"qingmu/cel/proto"
	"qingmu/pocstruct"
	"qingmu/report"
	"strings"
)

type CustomLib struct {
	// 声明
	envOptions []cel.EnvOption
	// 实现
	programOptions []cel.ProgramOption
}

// 第一步定义 cel options
func InitCelOptions() CustomLib {
	custom := CustomLib{}
	custom.envOptions = []cel.EnvOption{
		cel.Container("proto"),
		//	类型注入
		cel.Types(
			&proto.UrlType{},
			&proto.Request{},
			&proto.Response{},
			&proto.Reverse{},
			//&proto.Se
		),
		// 定义变量变量
		cel.Declarations(
			decls.NewVar("request", decls.NewObjectType("proto.Request")),
			decls.NewVar("response", decls.NewObjectType("proto.Response")),
			decls.NewVar("reverse", decls.NewObjectType("proto.Reverse")),
			//decls.NewVar("ts", decls.NewObjectType("proto.A123")),
		),
		// 定义
		cel.Declarations(
			containsDec, icontainsDec, substrDec, replaceAllDec, startsWithDec, endsWithDec, dirDec,
			upperDec, revDec, sizeDec, bcontainsDec, bstartsWithDec, bsizeDec, base64Dec, bbase64Dec,
			base64DecodeDec, bbase64DecodeDec, urlencodeDec, burlencodeDec, urldecodeDec, burldecodeDec,
			hexDec, bhexDec, hexDecodeDec, bhexDecodeDec, md5Dec, bmd5Dec, shaDec, bshaDec, hmacShaDec,
			bhmacShaDec, randomIntDec, randomLowercaseDec, matchDec, bmatchDec, bsubmatchDech, submatchDech,
			reverseWaitDec, emptymapDech,
		),
	}

	// 实现
	custom.programOptions = []cel.ProgramOption{cel.Functions(
		containsFunc, icontainsFunc, substrFunc, replaceAllFunc, startsWithFunc, endsWithFunc, dirFunc,
		upperFunc, revFunc, sizeFunc, bcontainsFunc, bstartsWithFunc, bsizeFunc, base64Func, bbase64Func,
		base64DecodeFunc, bbase64DecodeFunc, urlencodeFunc, burlencodeFunc, urldecodeFunc, burldecodeFunc,
		hexFunc, bhexFunc, hexDecodeFunc, bhexDecodeFunc, md5Func, bmd5Func, shaFunc, bshaFunc, hmacShaFunc,
		bhmacShaFunc, randomIntFunc, randomLowercaseFunc, matchFunc, bmatchFunc, bsubmatchFunc, submatchFunc,
		reverseWaitFunc, emptymapFunc,
	)}

	return custom
}

// 第二步 根据cel options 创建 cel环境
func InitCelEnv(c *CustomLib) (*cel.Env, error) {
	return cel.NewEnv(cel.Lib(c))
}

func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
}

// set 类型注入
func (c *CustomLib) UpdateSetCompileOptions(set yaml.MapSlice) {
	for _, item := range set {

		k := item.Key.(string)
		v := item.Value.(interface{})

		var d *exprpb.Decl

		_, ok := v.(map[string]string)

		if ok {
			d = decls.NewIdent(k, decls.NewMapType(decls.String, decls.String), nil)
		} else {
			if strings.HasPrefix(fmt.Sprintf("%v", v), "randomInt") {
				d = decls.NewIdent(k, decls.Int, nil)
			} else if strings.HasPrefix(fmt.Sprintf("%v", v), "newReverse") {
				d = decls.NewIdent(k, decls.NewObjectType("proto.Reverse"), nil)
			} else {
				d = decls.NewIdent(k, decls.String, nil)
			}
		}

		c.envOptions = append(c.envOptions, cel.Declarations(d))
	}
}

// output 类型注入
func (c *CustomLib) UpdateOutputCompileOptions(args map[string]interface{}) {
	for k, v := range args {

		var d *exprpb.Decl

		//fmt.Println(v)

		_, ok := v.(map[string]string)

		if ok {
			d = decls.NewIdent(k, decls.NewMapType(decls.String, decls.String), nil)
		} else {
			d = decls.NewIdent(k, decls.String, nil)
		}
		c.envOptions = append(c.envOptions, cel.Declarations(d))
	}
}

//UpdateFunctionOptions 用来预先处理rule的键名，加载到env中
//后续处理类似 r0()&&r1()这类的expression，可以索引到env中执行
//动态函数注入
func (c *CustomLib) UpdateFunctionOptions(name string, addr string, rule pocstruct.Rule, celVarMap map[string]interface{}, rep *report.Report) {
	//expression:=v.Expression
	//declarations
	dec := decls.NewFunction(name, decls.NewOverload(name, []*exprpb.Type{}, decls.Bool))
	c.envOptions = append(c.envOptions, cel.Declarations(dec))
	function := &functions.Overload{
		Operator: name,
		Function: func(values ...ref.Val) ref.Val {
			//匿名函数，通过cel rule键进行注入，可以减少不必要的请求。
			isTrue := func() bool {
				return EvalRule(addr, rule, *c, celVarMap, rep)
			}()
			//执行 EvalRule

			//if !isTrue {
			//	fmt.Println(rule.Request.Path)
			//}

			return types.Bool(isTrue)
		},
	}
	c.programOptions = append(c.programOptions, cel.Functions(function))
}

//	计算单个表达式
func Evaluate(env *cel.Env, expression string, params map[string]interface{}) (ref.Val, error) {
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prg.Eval(params)
	if err != nil {
		return nil, err
	}
	return out, nil
}
