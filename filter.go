package sensitive

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Filter 敏感词过滤器
type Filter struct {
	mu    sync.RWMutex
	trie  *Trie
	noise *regexp.Regexp
}

// New 返回一个敏感词过滤器
func New() *Filter {
	return &Filter{
		trie:  NewTrie(),
		noise: regexp.MustCompile(`[\|\s&%$@*]+`),
	}
}

// UpdateNoisePattern 更新去噪模式
func (filter *Filter) UpdateNoisePattern(pattern string) {
	filter.mu.Lock()
	defer filter.mu.Unlock()
	filter.noise = regexp.MustCompile(pattern)
}

// LoadWordDict 加载敏感词字典
func (filter *Filter) LoadWordDict(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return filter.Load(f)
}

// Load common method to add words
func (filter *Filter) LoadBytes(ba []byte) error {
	return filter.Load(bytes.NewBuffer(ba))
}

// LoadNetWordDict 加载网络敏感词字典
func (filter *Filter) LoadNetWordDict(url string) error {
	return filter.LoadNetWordDictTimeout(url, false, 5000)
}

// LoadNetWordDictTimeout 加载网络敏感词字典，带超时设置
func (filter *Filter) LoadNetWordDictTimeout(url string, allowHtml bool, timeout int) error {
	c := http.Client{
		Timeout: time.Duration(timeout) * time.Millisecond,
	}
	rsp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode >= 400 {
		text := http.StatusText(rsp.StatusCode)
		return fmt.Errorf(text)
	} else if allowHtml == false {
		value := strings.ToLower(rsp.Header.Get("Content-Type"))
		if strings.Contains(value, "html") {
			return fmt.Errorf("html is not allowed.")
		}
	}
	return filter.Load(rsp.Body)
}

// Load common method to add words
func (filter *Filter) Load(rd io.Reader) error {
	filter.mu.Lock()
	defer filter.mu.Unlock()

	buf := bufio.NewReader(rd)
	for {
		line, _, err := buf.ReadLine()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		filter.trie.Add(string(line))
	}

	return nil
}

// AddWord 添加敏感词
func (filter *Filter) AddWord(words ...string) {
	filter.mu.Lock()
	defer filter.mu.Unlock()
	filter.trie.Add(words...)
}

// DelWord 删除敏感词
func (filter *Filter) DelWord(words ...string) {
	filter.mu.Lock()
	defer filter.mu.Unlock()
	filter.trie.Del(words...)
}

// Filter 过滤敏感词
func (filter *Filter) Filter(text string) string {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	return filter.trie.Filter(text)
}

// Replace 和谐敏感词
func (filter *Filter) Replace(text string, repl rune) string {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	return filter.trie.Replace(text, repl)
}

// FindIn 检测敏感词
func (filter *Filter) FindIn(text string) (bool, string) {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	text = filter.noise.ReplaceAllString(text, "")
	return filter.trie.FindIn(text)
}

// FindAll 找到所有匹配词
func (filter *Filter) FindAll(text string) []string {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	return filter.trie.FindAll(text)
}

// Validate 检测字符串是否合法
func (filter *Filter) Validate(text string) (bool, string) {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	text = filter.noise.ReplaceAllString(text, "")
	return filter.trie.Validate(text)
}

func (filter *Filter) ValidateWithWildcard(text string, wildcard rune) (bool, string) {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	text = filter.noise.ReplaceAllString(text, "")
	return filter.trie.ValidateWithWildcard(text, wildcard)
}

// RemoveNoise 去除空格等噪音
func (filter *Filter) RemoveNoise(text string) string {
	filter.mu.RLock()
	defer filter.mu.RUnlock()
	return filter.noise.ReplaceAllString(text, "")
}
