package cel

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"hash"
	"io"
	"math/rand"
	"net/url"
	"qingmu/cel/proto"
	"qingmu/pocstruct"
	"qingmu/report"
	"qingmu/utils"
	"regexp"
	"strings"
)

// func (s1 string) contains(s2 string) bool
// 判断 s1 是否包含 s2，返回 bool 类型结果
var containsDec = decls.NewFunction("contains", decls.NewInstanceOverload("contains_string", []*exprpb.Type{decls.String, decls.String}, decls.Bool))
var containsFunc = &functions.Overload{
	Operator: "contains_string",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to contains", lhs.Type())
		}
		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to contains", rhs.Type())
		}
		return types.Bool(strings.Contains(string(v1), string(v2)))
	},
}

// func (s1 string) icontains(s2 string) bool
// 判断 s1 是否包含 s2，返回 bool 类型结果, 与 contains 不同的是，icontains 忽略大小写
var icontainsDec = decls.NewFunction("icontains", decls.NewInstanceOverload("icontains_string", []*exprpb.Type{decls.String, decls.String}, decls.Bool))
var icontainsFunc = &functions.Overload{
	Operator: "icontains_string",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to icontains", lhs.Type())
		}
		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to icontains", rhs.Type())
		}
		return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
	},
}

// func substr(string, start int, length int) string
// 截取字符串
var substrDec = decls.NewFunction("substr", decls.NewOverload("substr_string_int_int", []*exprpb.Type{decls.String, decls.Int, decls.Int}, decls.String))
var substrFunc = &functions.Overload{
	Operator: "substr_string_int_int",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) == 3 {
			str, ok := values[0].(types.String)
			if !ok {
				return types.NewErr("invalid string to 'substr'")
			}
			start, ok := values[1].(types.Int)
			if !ok {
				return types.NewErr("invalid start to 'substr'")
			}
			length, ok := values[2].(types.Int)
			if !ok {
				return types.NewErr("invalid length to 'substr'")
			}
			runes := []rune(str)
			if start < 0 || length < 0 || int(start+length) > len(runes) {
				return types.NewErr("invalid start or length to 'substr'")
			}
			return types.String(runes[start : start+length])
		} else {
			return types.NewErr("too many arguments to 'substr'")
		}
	},
}

// func replaceAll(string, old string, new string) string
// 将 string 中的 old 替换为 new，返回替换后的 string
var replaceAllDec = decls.NewFunction("replaceAll", decls.NewOverload("replaceAll", []*exprpb.Type{decls.String, decls.String, decls.String}, decls.String))
var replaceAllFunc = &functions.Overload{
	Operator: "replaceAll",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) == 3 {
			str, ok := values[0].(types.String)
			if !ok {
				return types.NewErr("invalid string to 'replaceAll'")
			}
			old, ok := values[1].(types.String)
			if !ok {
				return types.NewErr("invalid start to 'replaceAll'")
			}
			new, ok := values[2].(types.String)
			if !ok {
				return types.NewErr("invalid length to 'replaceAll'")
			}

			return types.String(strings.ReplaceAll(string(str), string(old), string(new)))
		} else {
			return types.NewErr("too many arguments to 'replaceAll'")
		}
	},
}

// func printable(string) string
// 将 string 中的非 unicode 编码字符去掉

// 这个不会
//var printableDec = decls.NewFunction("printable", decls.NewOverload("printable", []*exprpb.Type{decls.String}, decls.String))
//var printableFunc = &functions.Overload{
//	Operator: "printable",
//	Unary: func(value ref.Val) ref.Val {
//		v, ok := value.(types.String)
//		if !ok {
//			return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
//		}
//		return types.String(strings.p)
//	},
//}

// func toUintString(s1 string, direction string) string
// direction 取值为 >,<表示读取方向, 将 s1 按 direction 读取为一个整数，返回该整数的字符串形式

// 这个没有看懂是什么意思
//var toUintStringDec = decls.NewFunction("toUintString", decls.NewOverload("toUintString", []*exprpb.Type{decls.String}, decls.String))
//var toUintStringFunc = &functions.Overload{
//	Operator: "toUintString",
//	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
//		s1, ok := lhs.(types.String)
//		if !ok {
//			return types.ValOrErr(lhs, "unexpected type '%v' passed to toUintString", lhs.Type())
//		}
//		direction, ok := rhs.(types.String)
//		if !ok {
//			return types.ValOrErr(rhs, "unexpected type '%v' passed to toUintString", rhs.Type())
//		}
//
//
//
//		if direction == "<" {
//
//		} else if direction == ">" {
//
//		} else {
//			return types.NewErr("direction 取值为 >,<表示读取方向")
//		}
//
//		return types.String()
//	},
//}

// func (s1 string) startsWith(s2 string) bool
// 判断 s1 是否由 s2 开头
var startsWithDec = decls.NewFunction("starts_with", decls.NewInstanceOverload("startsWith", []*exprpb.Type{decls.String, decls.String}, decls.Bool))
var startsWithFunc = &functions.Overload{
	Operator: "startsWith",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		s1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to startsWith", lhs.Type())
		}
		s2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to startsWith", rhs.Type())
		}
		return types.Bool(strings.HasPrefix(string(s1), string(s2)))
	},
}

// func (s1 string) endsWith(s2 string) bool
// 判断 s1 是否由 s2 结尾
var endsWithDec = decls.NewFunction("ends_with", decls.NewInstanceOverload("enith_string", []*exprpb.Type{decls.String, decls.String}, decls.Bool))
var endsWithFunc = &functions.Overload{
	Operator: "enith_string",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		s1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to endsWith", lhs.Type())
		}
		s2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to endsWith", rhs.Type())
		}
		return types.Bool(strings.HasSuffix(string(s1), string(s2)))
	},
}

// func basename(s1 string) string
// 返回 URL 的最后一个路径的名称
// 这个也没有看明白是什么意思

// func dir(s1 string) string
// 返回 URL 的路径
var dirDec = decls.NewFunction("dir", decls.NewOverload("dir", []*exprpb.Type{decls.String}, decls.String))
var dirFunc = &functions.Overload{
	Operator: "dir",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to dir", value.Type())
		}
		u, err := url.Parse(string(v))
		if err != nil {

			return types.NewErr(fmt.Sprintf("url 解析错误%v", err))
		}

		return types.String(u.Path)
	},
}

// func upper(s1 string) string
// 将 string 中的小写字母转换成大写
var upperDec = decls.NewFunction("upper", decls.NewOverload("upper", []*exprpb.Type{decls.String}, decls.String))
var upperFunc = &functions.Overload{
	Operator: "upper",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to upper", value.Type())
		}

		return types.String(strings.ToUpper(string(v)))
	},
}

// func rev(s1 string) string
// 将 string 反向输出，主要用于验证命令执行
var revDec = decls.NewFunction("rev", decls.NewOverload("rev", []*exprpb.Type{decls.String}, decls.String))
var revFunc = &functions.Overload{
	Operator: "rev",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to rev", value.Type())
		}

		// 字符串反转
		s := func(str string) string {
			// write code here
			if len(str) == 0 {
				return ""
			}
			runes := []rune(str)
			for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
				runes[i], runes[j] = runes[j], runes[i]
			}
			return string(runes)
		}(string(v))

		return types.String(s)
	},
}

// func size(s1 string) int
// 返回 string 的长度
var sizeDec = decls.NewFunction("size", decls.NewOverload("size_string", []*exprpb.Type{decls.String}, decls.Int))
var sizeFunc = &functions.Overload{
	Operator: "size_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to size", value.Type())
		}
		return types.Int(len(string(v)))
	},
}

//	判断b1 是否包含 b2
//func (b1 bytes) bcontains(b2 bytes) bool
//判断一个 b1 是否包含 b2，返回 bool 类型结果。与 contains 不同的是，bcontains 是字节流（bytes）的查找
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

// func (b1 bytes) bstartsWith(b2 bytes) bool
// 判断一个 b1 是否由 b2 开头，返回 bool 类型结果。与 startsWith 不同的是，bcontains 是字节流（bytes）的查找
var bstartsWithDec = decls.NewFunction("bstartsWith", decls.NewInstanceOverload("bstartsWith", []*exprpb.Type{decls.Bytes, decls.Bytes}, decls.Bool))
var bstartsWithFunc = &functions.Overload{
	Operator: "bstartsWith",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bstartsWith", lhs.Type())
		}
		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bstartsWith", rhs.Type())
		}
		//fmt.Println(v1, v2)
		return types.Bool(bytes.HasPrefix(v1, v2))
	},
}

// func (b1 bytes) bformat(int, int, string, int) string
// 将 bytes 进行进制转换编码，可以根据输入的参数转换成对应的进制编码，并可以自定义转换格式
// 这个又没有看懂这是什么意思

// func size(b1 bytes) int
// 返回 bytes 的长度
var bsizeDec = decls.NewFunction("size", decls.NewOverload("size_bytes", []*exprpb.Type{decls.Bytes}, decls.Int))
var bsizeFunc = &functions.Overload{
	Operator: "size_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to size", value.Type())
		}
		return types.Int(len(v))
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
		return types.String(fmt.Sprintf("%s", base64.URLEncoding.EncodeToString([]byte(v))))
	},
}

//  bytes的 base64
var bbase64Dec = decls.NewFunction("base64", decls.NewOverload("base64_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var bbase64Func = &functions.Overload{
	Operator: "base64_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
		}
		return types.String(fmt.Sprintf("%s", base64.URLEncoding.EncodeToString(v)))
	},
}

//  字符串的 base64 解码
var base64DecodeDec = decls.NewFunction("base64Decode", decls.NewOverload("base64Decode", []*exprpb.Type{decls.String}, decls.String))
var base64DecodeFunc = &functions.Overload{
	Operator: "base64Decode",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
		}

		str := strings.ReplaceAll(string(v), "+", "-")
		str = strings.ReplaceAll(str, "/", "_")

		decoder, err := base64.URLEncoding.DecodeString(str)
		if err != nil {
			return types.NewErr("base64解码错误", err)

		}
		return types.String(decoder)
	},
}

//  bytes的 base64 解码
var bbase64DecodeDec = decls.NewFunction("base64Decode", decls.NewOverload("base64Decode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var bbase64DecodeFunc = &functions.Overload{
	Operator: "base64Decode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
		}
		str := strings.ReplaceAll(string(v), "+", "-")
		str = strings.ReplaceAll(str, "/", "_")

		decoder, err := base64.URLEncoding.DecodeString(str)
		if err != nil {
			return types.NewErr("base64解码错误", err)

		}
		return types.String(decoder)
	},
}

// func urlencode(v1 string) string
// 将字符串 进行 urlencode 编码
var urlencodeDec = decls.NewFunction("urlencode", decls.NewOverload("urlencode_string", []*exprpb.Type{decls.String}, decls.String))
var urlencodeFunc = &functions.Overload{
	Operator: "urlencode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
		}

		return types.String(url.QueryEscape(string(v)))
	},
}

// func urlencode(v1 bytes) string
// 将 bytes 进行 urlencode 编码
var burlencodeDec = decls.NewFunction("urlencode", decls.NewOverload("urlencode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var burlencodeFunc = &functions.Overload{
	Operator: "urlencode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
		}

		return types.String(url.QueryEscape(string(v)))
	},
}

//func urldecode(v1 string/bytes) string 	将字符串或 bytes 进行 urldecode 解码
var urldecodeDec = decls.NewFunction("urldecode", decls.NewOverload("urldecode_string", []*exprpb.Type{decls.String}, decls.String))
var urldecodeFunc = &functions.Overload{
	Operator: "urldecode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
		}
		decoder, err := url.QueryUnescape(string(v))
		if err != nil {
			return types.NewErr("url解码错误", err)
		}

		return types.String(decoder)
	},
}

//func urldecode(v1 string/bytes) string 	将字符串或 bytes 进行 urldecode 解码
var burldecodeDec = decls.NewFunction("urldecode", decls.NewOverload("urldecode_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var burldecodeFunc = &functions.Overload{
	Operator: "urldecode_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
		}
		decoder, err := url.QueryUnescape(string(v))
		if err != nil {
			return types.NewErr("url解码错误", err)
		}

		return types.String(decoder)
	},
}

// func hex(string) string 	将字符串进行 hex 编码
var hexDec = decls.NewFunction("hex", decls.NewOverload("hex_string", []*exprpb.Type{decls.String}, decls.String))
var hexFunc = &functions.Overload{
	Operator: "hex_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to hex_string", value.Type())
		}

		return types.String(hex.EncodeToString([]byte(v)))
	},
}

// func hex(bytes) string 	将 bytes 进行 hex 编码
var bhexDec = decls.NewFunction("hex", decls.NewOverload("hex", []*exprpb.Type{decls.Bytes}, decls.String))
var bhexFunc = &functions.Overload{
	Operator: "hex",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to hex", value.Type())
		}

		return types.String(hex.EncodeToString(v))
	},
}

//func hexDecode(string) string 	将字符串进行 hex 解码
var hexDecodeDec = decls.NewFunction("hexDecode", decls.NewOverload("hexDecode_string", []*exprpb.Type{decls.String}, decls.String))
var hexDecodeFunc = &functions.Overload{
	Operator: "hexDecode_string",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.String)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to hexDecode_string", value.Type())
		}

		decoder, err := hex.DecodeString(string(v))
		if err != nil {
			return types.NewErr("hexdecoder 错误", err)
		}

		return types.String(decoder)
	},
}

// func hexDecode(bytes) string 	将 bytes 进行 hex 解码
var bhexDecodeDec = decls.NewFunction("hexDecode", decls.NewOverload("hexDecode", []*exprpb.Type{decls.Bytes}, decls.String))
var bhexDecodeFunc = &functions.Overload{
	Operator: "hexDecode",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to hexDecode", value.Type())
		}

		decoder, err := hex.DecodeString(string(v))
		if err != nil {
			return types.NewErr("hexdecoder 错误", err)
		}

		return types.String(decoder)
	},
}

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

// bytes 的 md5
var bmd5Dec = decls.NewFunction("md5", decls.NewOverload("md5_bytes", []*exprpb.Type{decls.Bytes}, decls.String))
var bmd5Func = &functions.Overload{
	Operator: "md5_bytes",
	Unary: func(value ref.Val) ref.Val {
		v, ok := value.(types.Bytes)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to md5_bytes", value.Type())
		}
		return types.String(fmt.Sprintf("%x", md5.Sum(v)))
	},
}

// func sha(v1 string, s1 string)string
// 该函数可以将指定字符串进行 sha 系列计算。
var shaDec = decls.NewFunction("sha", decls.NewOverload("sha_string", []*exprpb.Type{decls.String, decls.String}, decls.String))
var shaFunc = &functions.Overload{
	Operator: "sha_string",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to sha", lhs.Type())
		}
		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to sha", rhs.Type())
		}

		//var sha string
		//data := []byte(string(v1))

		switch v2 {
		case "1":
			t := sha1.New()
			io.WriteString(t, string(v1))
			return types.String(fmt.Sprintf("%x", t.Sum(nil)))
		case "224":
			return types.String(fmt.Sprintf("%x", sha256.Sum224([]byte(v1))))
		case "256":
			return types.String(fmt.Sprintf("%x", sha256.Sum256([]byte(v1))))
		case "384":
			return types.String(fmt.Sprintf("%x", sha512.Sum384([]byte(v1))))
		case "512":
			return types.String(fmt.Sprintf("%x", sha512.Sum512([]byte(v1))))
		default:
			return types.NewErr("please input 1/224/256/384/512")

		}
	},
}

// func sha(v1 bytes, s1 string)string
// 该函数可以将指定字符串进行 sha 系列计算。
var bshaDec = decls.NewFunction("sha", decls.NewOverload("sha_bytes", []*exprpb.Type{decls.Bytes, decls.String}, decls.String))
var bshaFunc = &functions.Overload{
	Operator: "sha_bytes",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to sha", lhs.Type())
		}
		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to sha", rhs.Type())
		}

		//var sha string
		//data := []byte(string(v1))

		switch v2 {
		case "1":
			t := sha1.New()
			io.WriteString(t, string(v1))
			return types.String(fmt.Sprintf("%x", t.Sum(nil)))
		case "224":
			return types.String(fmt.Sprintf("%x", sha256.Sum224(v1)))
		case "256":
			return types.String(fmt.Sprintf("%x", sha256.Sum256(v1)))
		case "384":
			return types.String(fmt.Sprintf("%x", sha512.Sum384(v1)))
		case "512":
			return types.String(fmt.Sprintf("%x", sha512.Sum512(v1)))
		default:
			return types.NewErr("please input 1/224/256/384/512")

		}
	},
}

// func hmacSha(v1 string s1 string, s2 string)string
// 该函数可以将指定字符串进行 hmac_sha 系列计算。
var hmacShaDec = decls.NewFunction("hmacSha", decls.NewOverload("hmacSha_string", []*exprpb.Type{decls.String, decls.String, decls.String}, decls.String))
var hmacShaFunc = &functions.Overload{
	Operator: "hmacSha_string",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) == 3 {
			data, ok := values[0].(types.String) //是加密的内容
			if !ok {
				return types.NewErr("invalid string to 'hmacSha_string'")
			}
			v2, ok := values[1].(types.String)
			if !ok {
				return types.NewErr("invalid start to 'hmacSha_string'")
			}
			key, ok := values[2].(types.String) //加密所使用的key
			if !ok {
				return types.NewErr("invalid length to 'hmacSha_string'")
			}

			var mac hash.Hash

			switch v2 {
			case "1":
				mac = hmac.New(sha1.New, []byte(key))
				mac.Write([]byte(data))
			case "224":
				mac = hmac.New(sha256.New224, []byte(key))
				mac.Write([]byte(data))
			case "256":
				mac = hmac.New(sha256.New, []byte(key))
				mac.Write([]byte(data))
			case "384":
				mac = hmac.New(sha512.New384, []byte(key))
				mac.Write([]byte(data))
			case "512":
				mac = hmac.New(sha512.New, []byte(key))
				mac.Write([]byte(data))
			default:
				return types.NewErr("please input 1/224/256/384/512")

			}
			return types.String(fmt.Sprintf("%x", mac.Sum(nil)))
		} else {
			return types.NewErr("too many arguments to 'hmacSha'")
		}

	},
}

// func hmacSha(v1 bytes s1 string, s2 string)string
// 该函数可以将指定 bytes 进行 hmac_sha 系列计算。
var bhmacShaDec = decls.NewFunction("hmacSha", decls.NewOverload("hmacSha_bytes", []*exprpb.Type{decls.Bytes, decls.String, decls.String}, decls.String))
var bhmacShaFunc = &functions.Overload{
	Operator: "hmacSha_bytes",
	Function: func(values ...ref.Val) ref.Val {
		if len(values) == 3 {
			data, ok := values[0].(types.Bytes) //是加密的内容
			if !ok {
				return types.NewErr("invalid string to 'hmacSha_bytes'")
			}
			v2, ok := values[1].(types.String)
			if !ok {
				return types.NewErr("invalid start to 'hmacSha_bytes'")
			}
			key, ok := values[2].(types.String) //加密所使用的key
			if !ok {
				return types.NewErr("invalid length to 'hmacSha_bytes'")
			}

			var mac hash.Hash

			switch v2 {
			case "1":
				mac = hmac.New(sha1.New, []byte(key))
				mac.Write(data)
			case "224":
				mac = hmac.New(sha256.New224, []byte(key))
				mac.Write(data)
			case "256":
				mac = hmac.New(sha256.New, []byte(key))
				mac.Write(data)
			case "384":
				mac = hmac.New(sha512.New384, []byte(key))
				mac.Write(data)
			case "512":
				mac = hmac.New(sha512.New, []byte(key))
				mac.Write(data)
			default:
				return types.NewErr("please input 1/224/256/384/512")

			}
			return types.String(fmt.Sprintf("%x", mac.Sum(nil)))
		} else {
			return types.NewErr("too many arguments to 'hmacSha'")
		}

	},
}

// func randomInt(from, to int) int
// 两个范围内的随机数
var randomIntDec = decls.NewFunction("randomInt", decls.NewOverload("randomInt_int_int", []*exprpb.Type{decls.Int, decls.Int}, decls.Int))
var randomIntFunc = &functions.Overload{
	Operator: "randomInt_int_int",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		from, ok := lhs.(types.Int)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
		}
		to, ok := rhs.(types.Int)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
		}
		min, max := int(from), int(to)
		return types.Int(rand.Intn(max-min) + min)
	},
}

//	指定长度的小写字母和数字组成的随机字符串
var randomLowercaseDec = decls.NewFunction("randomLowercase", decls.NewOverload("randomLowercase_int", []*exprpb.Type{decls.Int}, decls.String))
var randomLowercaseFunc = &functions.Overload{
	Operator: "randomLowercase_int",
	Unary: func(value ref.Val) ref.Val {
		n, ok := value.(types.Int)
		if !ok {
			return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
		}

		ra := func(n int) []byte {
			var letters = []byte("abcdefghjkmnpqrstuvwxyz123456789")
			if n <= 0 {
				return []byte{}
			}
			b := make([]byte, n)
			arc := uint8(0)
			if _, err := rand.Read(b[:]); err != nil {
				return []byte{}
			}
			for i, x := range b {
				arc = x & 31
				b[i] = letters[arc]
			}
			return b
		}(int(n))
		return types.String(ra)
	},
}

// func (s1 string) matches(s2 string) bool
// 使用正则表达式 s1 来匹配 s2，返回 bool 类型匹配结果
var matchDec = decls.NewFunction("matches", decls.NewInstanceOverload("matches_string", []*exprpb.Type{decls.String, decls.String}, decls.Bool))
var matchFunc = &functions.Overload{
	Operator: "matches_string",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to match", lhs.Type())
		}
		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to match", rhs.Type())
		}
		ok, err := regexp.Match(string(v1), []byte(v2))
		if err != nil {
			return types.NewErr("错误%v", err)
		}
		return types.Bool(ok)
	},
}

//	使用正则表达式s1 来 匹配b1
var bmatchDec = decls.NewFunction("bmatches", decls.NewInstanceOverload("bmatches_bytes", []*exprpb.Type{decls.String, decls.Bytes}, decls.Bool))
var bmatchFunc = &functions.Overload{
	Operator: "bmatches_bytes",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
		}
		v2, ok := rhs.(types.Bytes)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
		}
		ok, err := regexp.Match(string(v1), v2)
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.Bool(ok)
	},
}

// func (s1 string) bsubmatches(b1 bytes) map[string]string
//使用正则表达式 s1 来匹配 b1，返回 map[string]string 类型结果
//注：只返回具名的正则匹配结果 (?P…) 格式。与 matches 不同的是，bmatches 匹配的是字节流（bytes）
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

// func (s1 string) bsubmatches(b1 bytes) map[string]string
//使用正则表达式 s1 来匹配 b1，返回 map[string]string 类型结果
//注：只返回具名的正则匹配结果 (?P…) 格式。与 matches 不同的是，bmatches 匹配的是字节流（bytes）
var submatchDech = decls.NewFunction("submatch", decls.NewInstanceOverload("string_submatch_map", []*exprpb.Type{decls.String, decls.String}, decls.NewMapType(decls.String, decls.String)))
var submatchFunc = &functions.Overload{
	Operator: "string_submatch_map",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		v1, ok := lhs.(types.String)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to string_submatch_map", lhs.Type())
		}
		v2, ok := rhs.(types.String)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to string_submatch_map", rhs.Type())
		}

		//v4 := v2

		var v3 ref.TypeAdapter

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
		}(string(v1), string(v2)))

	},
}

//	反连平台结果
var reverseWaitDec = decls.NewFunction("wait", decls.NewInstanceOverload("reverse_wait_int", []*exprpb.Type{decls.Any, decls.Int}, decls.Bool))
var reverseWaitFunc = &functions.Overload{
	Operator: "reverse_wait_int",
	Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
		reverse, ok := lhs.Value().(*proto.Reverse)
		if !ok {
			return types.ValOrErr(lhs, "unexpected type '%v' passed to 'wait'", lhs.Type())
		}
		timeout, ok := rhs.Value().(int64)
		if !ok {
			return types.ValOrErr(rhs, "unexpected type '%v' passed to 'wait'", rhs.Type())
		}
		return types.Bool(utils.ReverseCheck(reverse, timeout))
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
			reverseWaitDec,
		),
	}

	// 实现
	custom.programOptions = []cel.ProgramOption{cel.Functions(
		containsFunc, icontainsFunc, substrFunc, replaceAllFunc, startsWithFunc, endsWithFunc, dirFunc,
		upperFunc, revFunc, sizeFunc, bcontainsFunc, bstartsWithFunc, bsizeFunc, base64Func, bbase64Func,
		base64DecodeFunc, bbase64DecodeFunc, urlencodeFunc, burlencodeFunc, urldecodeFunc, burldecodeFunc,
		hexFunc, bhexFunc, hexDecodeFunc, bhexDecodeFunc, md5Func, bmd5Func, shaFunc, bshaFunc, hmacShaFunc,
		bhmacShaFunc, randomIntFunc, randomLowercaseFunc, matchFunc, bmatchFunc, bsubmatchFunc, submatchFunc,
		reverseWaitFunc,
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
func (c *CustomLib) UpdateSetCompileOptions(set map[string]string, setkeys []string) {
	for _, k := range setkeys {

		v := set[k]
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
func (c *CustomLib) UpdateFunctionOptions(name string, addr string, rule *pocstruct.Rule, celVarMap map[string]interface{}, outputkeys []string, rep *report.Report) {
	//expression:=v.Expression
	//declarations
	dec := decls.NewFunction(name, decls.NewOverload(name, []*exprpb.Type{}, decls.Bool))
	c.envOptions = append(c.envOptions, cel.Declarations(dec))
	function := &functions.Overload{
		Operator: name,
		Function: func(values ...ref.Val) ref.Val {
			//匿名函数，通过cel rule键进行注入，可以减少不必要的请求。
			isTrue := func() bool {
				return EvalRule(addr, rule, *c, celVarMap, outputkeys, rep)
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
