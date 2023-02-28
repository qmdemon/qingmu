package pocstruct

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

// xray pocstruct
type Poc struct {
	Name       string          `yaml:"name"`
	Set        yaml.MapSlice   `yaml:"set"`
	Rules      map[string]Rule `yaml:"rules"`
	Detail     Detail          `yaml:"detail"`
	Expression string          `yaml:"expression"`
}

type Rule struct {
	Request    Request       `yaml:"request"`
	Expression string        `yaml:"expression"`
	OutPut     yaml.MapSlice `yaml:"output"`
}

type Request struct {
	Cache           bool              `yaml:"cache"`
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

func LoadPoc(fileName string) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		return nil, err
	}
	return p, err
}
