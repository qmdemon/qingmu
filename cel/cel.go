package cel

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"qingmu/cel/proto"
	"qingmu/pocstruct"
	"qingmu/report"
	"regexp"
	"strings"
)

//  字符串的 md5
var md5Dec = decls.NewFunction("md5", decls.NewOverload("md5_string", []*exprpb.Type{decls.String}, decls.String))
var md5Func = &functions.Overload{
	Operator: "md5_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
		}
		return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
	},
}

//  字符串的 base64
var base64Dec = decls.NewFunction("base64", decls.NewOverload("base64_string", []*exprpb.Type{decls.String}, decls.String))
var base64Func = &functions.Overload{
	Operator: "base64_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
		}
		return types.String(fmt.Sprintf("%s", base64.StdEncoding.EncodeToString([]byte(v))))
	},
}

//	判断b1 是否包含 b2
var bcontainsDec = decls.NewFunction("bcontains", decls.NewInstanceOverload("bytes_bcontains_bytes", []*exprpb.Type{decls.Bytes, decls.Bytes}, decls.Bool))
var bcontainsFunc = &functions.Overload{
	Operator: "bytes_bcontains_bytes",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
		}
		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
		}
		return types.Bool(bytes.Contains(v1, v2))
	},
}

// 通过正则表达生成map
var bsubmatchDech = decls.NewFunction("bsubmatch", decls.NewInstanceOverload("string_bsubmatch_map", []*exprpb.Type{decls.String, decls.Bytes}, decls.NewMapType(decls.String, decls.String)))
var bsubmatchFunc = &functions.Overload{
	Operator: "string_bsubmatch_map",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to string_bsubmatch_map", lhs.Type())
		}
		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to string_bsubmatch_map", rhs.Type())
		}

		v4 := types.String(v2)

		var v3 ref.TypeAdapter
		//t := new(ta)
		//v3 = t

		return types.NewStringStringMap(v3, func(re string, body string) map[string]string {
			r, err := regexp.Compile(re)
			if err != nil {
				return nil
			}
			result := r.FindStringSubmatch(body)
			names := r.SubexpNames()
			//fmt.Println(result, names)
			if len(result) > 1 && len(names) > 1 {
				paramsMap := make(map[string]string)
				for i, name := range names {
					//fmt.Println("i=", i)
					//fmt.Println("name=", name)
					if i > 0 && i <= len(result) {

						paramsMap[name] = result[i]
					}
				}
				//fmt.Println(paramsMap)
				return paramsMap
			}
			return nil
		}(string(v1), string(v4)))

	},
}

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
			//&proto.Search{},
		),
		// 定义变量变量
		cel.Declarations(
			decls.NewVar("request", decls.NewObjectType("proto.Request")),
			decls.NewVar("response", decls.NewObjectType("proto.Response")),
			//decls.NewVar("search", decls.NewObjectType("proto.Search")),
			//decls.NewVar("ts", decls.NewObjectType("proto.A123")),
		),
		// 定义
		cel.Declarations(
			md5Dec, bcontainsDec, base64Dec, bsubmatchDech,
			//bcontainsDec, iContainsDec, bmatchDec, md5Dec,
			////startsWithDec, endsWithDec,
			//inDec, randomIntDec, randomLowercaseDec,
			//base64StringDec, base64BytesDec, base64DecodeStringDec, base64DecodeBytesDec,
			//urlencodeStringDec, urlencodeBytesDec, urldecodeStringDec, urldecodeBytesDec,
			//substrDec, sleepDec, reverseWaitDec,
		),
	}

	// 实现
	custom.programOptions = []cel.ProgramOption{cel.Functions(
		md5Func, bcontainsFunc, base64Func, bsubmatchFunc,
		//containsFunc, iContainsFunc, bcontainsFunc, matchFunc, bmatchFunc, md5Func,
		////startsWithFunc,  endsWithFunc,
		//inFunc, randomIntFunc, randomLowercaseFunc,
		//base64StringFunc, base64BytesFunc, base64DecodeStringFunc, base64DecodeBytesFunc,
		//urlencodeStringFunc, urlencodeBytesFunc, urldecodeStringFunc, urldecodeBytesFunc,
		//substrFunc, sleepFunc, reverseWaitFunc,
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
func (c *CustomLib) UpdateSetCompileOptions(args map[string]string) {
	for k, v := range args {
		// 在执行之前是不知道变量的类型的，所以统一声明为字符型
		// 所以randomInt虽然返回的是int型，在运算中却被当作字符型进行计算，需要重载string_*_string
		var d *exprpb.Decl
		if strings.HasPrefix(v, "randomInt") {
			d = decls.NewIdent(k, decls.Int, nil)
		} else if strings.HasPrefix(v, "newReverse") {
			d = decls.NewIdent(k, decls.NewObjectType("proto.Reverse"), nil)
		} else {
			d = decls.NewIdent(k, decls.String, nil)
		}
		c.envOptions = append(c.envOptions, cel.Declarations(d))
	}
}

// output 类型注入
func (c *CustomLib) UpdateOutputCompileOptions(args map[string]interface{}) {
	for k, v := range args {

		var d *exprpb.Decl

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
func (c *CustomLib) UpdateFunctionOptions(name string, addr string, rule *pocstruct.Rule, celVarMap map[string]interface{}, outputkeys []string, rep *report.Report) {
	//expression:=v.Expression
	//declarations
	dec := decls.NewFunction(name, decls.NewOverload(name, []*exprpb.Type{}, decls.Bool))
	c.envOptions = append(c.envOptions, cel.Declarations(dec))
	function := &functions.Overload{
		Operator: name,
		Function: func(values ...ref.Val) ref.Val {
			//匿名函数
			f := func() bool {
				return EvalRule(addr, rule, *c, celVarMap, outputkeys, rep)
			}
			//执行 EvalRule
			isTrue := f()
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
