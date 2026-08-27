package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxControlBody = 8 << 20
	maxFormFields  = 1024
	envelopeType   = "application/vnd.proxyarea.proxy+json"
)

var errBodyTooLarge = errors.New("control body too large")

type value struct {
	text    string
	present bool
}

type controls struct {
	url, params, https, key value
	body                    io.ReadCloser
	contentType             string
	replacedBody            bool
}

type envelope struct {
	URL         *string         `json:"url"`
	Params      *string         `json:"params"`
	HTTPS       json.RawMessage `json:"https"`
	Key         *string         `json:"key"`
	Encoding    *string         `json:"encoding"`
	Body        json.RawMessage `json:"body"`
	ContentType *string         `json:"contentType"`
}

func parseControls(r io.ReadCloser, contentType string, query url.Values) (controls, error) {
	if r == nil {
		r = httpNoBody{}
	}
	c := controls{body: r, contentType: contentType}
	for name, dst := range map[string]*value{"url": &c.url, "params": &c.params, "https": &c.https, "key": &c.key} {
		if vals, ok := query[name]; ok {
			dst.present = true
			if len(vals) > 0 {
				dst.text = vals[0]
			}
		}
	}
	mediaType := ""
	params := map[string]string{}
	var err error
	lowerCT := strings.ToLower(contentType)
	switch {
	case contentIsControl(lowerCT):
		mediaType, params, err = mime.ParseMediaType(contentType)
		if err != nil {
			return controls{}, fmt.Errorf("invalid Content-Type: %w", err)
		}
	default:
		// 非控制类型: body 原样透传, 不缓冲、不做 MIME 严格校验
		return c, nil
	}
	raw, err := readBounded(r)
	if err != nil {
		return controls{}, err
	}
	_ = r.Close()
	c.body = io.NopCloser(bytes.NewReader(raw))
	var secondary controls
	switch mediaType {
	case envelopeType:
		secondary, err = parseEnvelope(raw)
	case "application/x-www-form-urlencoded":
		var vals url.Values
		vals, err = url.ParseQuery(string(raw))
		if err == nil {
			secondary, err = controlsFromValues(vals)
		}
	case "multipart/form-data":
		secondary, err = parseMultipart(raw, params["boundary"])
	}
	if err != nil {
		return controls{}, err
	}
	mergeMissing(&c, secondary)
	return c, nil
}

func contentIsControl(ct string) bool {
	if ct == envelopeType {
		return true
	}
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"),
		strings.HasPrefix(ct, "multipart/form-data"):
		return true
	}
	return false
}

func readBounded(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxControlBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxControlBody {
		return nil, errBodyTooLarge
	}
	return raw, nil
}

type httpNoBody struct{}

func (httpNoBody) Read([]byte) (int, error) { return 0, io.EOF }
func (httpNoBody) Close() error             { return nil }

func controlsFromValues(vals url.Values) (controls, error) {
	if len(vals) > maxFormFields {
		return controls{}, errBodyTooLarge
	}
	var c controls
	for name, dst := range map[string]*value{"url": &c.url, "params": &c.params, "https": &c.https, "key": &c.key} {
		if values, ok := vals[name]; ok {
			dst.present = true
			if len(values) > 0 {
				dst.text = values[0]
			}
		}
	}
	return c, nil
}

func parseMultipart(raw []byte, boundary string) (controls, error) {
	if boundary == "" {
		return controls{}, errors.New("multipart boundary is required")
	}
	mr := multipart.NewReader(bytes.NewReader(raw), boundary)
	var c controls
	fields := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return controls{}, fmt.Errorf("invalid multipart body: %w", err)
		}
		fields++
		if fields > maxFormFields {
			return controls{}, errBodyTooLarge
		}
		name := part.FormName()
		dst := map[string]*value{"url": &c.url, "params": &c.params, "https": &c.https, "key": &c.key}[name]
		if dst != nil && !dst.present {
			data, err := io.ReadAll(io.LimitReader(part, maxControlBody+1))
			if err != nil || len(data) > maxControlBody {
				return controls{}, errBodyTooLarge
			}
			dst.text, dst.present = string(data), true
		}
		_ = part.Close()
	}
	return c, nil
}

func parseEnvelope(raw []byte) (controls, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e envelope
	if err := dec.Decode(&e); err != nil {
		return controls{}, fmt.Errorf("invalid proxy envelope: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return controls{}, errors.New("invalid proxy envelope: extra JSON value")
	}
	var c controls
	set := func(dst *value, src *string) {
		if src != nil {
			dst.text, dst.present = *src, true
		}
	}
	set(&c.url, e.URL)
	set(&c.params, e.Params)
	set(&c.key, e.Key)
	if e.HTTPS != nil {
		c.https.present = true
		var b bool
		if err := json.Unmarshal(e.HTTPS, &b); err != nil {
			return controls{}, errors.New("invalid proxy envelope https")
		}
		c.https.text = strconv.FormatBool(b)
	}
	encoding := "none"
	if e.Encoding != nil {
		encoding = *e.Encoding
	}
	var body []byte
	switch encoding {
	case "none":
		if len(e.Body) != 0 && string(e.Body) != "null" {
			return controls{}, errors.New("envelope encoding none cannot include body")
		}
		if e.ContentType != nil {
			return controls{}, errors.New("envelope encoding none cannot include contentType")
		}
	case "json":
		if len(e.Body) == 0 {
			return controls{}, errors.New("envelope json body is required")
		}
		if !json.Valid(e.Body) {
			return controls{}, errors.New("invalid envelope JSON body")
		}
		body = append([]byte(nil), e.Body...)
		c.contentType = "application/json"
	case "text":
		if err := json.Unmarshal(e.Body, (*stringBytes)(&body)); err != nil {
			return controls{}, errors.New("envelope text body must be a string")
		}
		c.contentType = "text/plain; charset=utf-8"
	case "base64":
		var encoded string
		if err := json.Unmarshal(e.Body, &encoded); err != nil {
			return controls{}, errors.New("envelope base64 body must be a string")
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return controls{}, errors.New("invalid envelope base64 body")
		}
		body = data
	default:
		return controls{}, errors.New("invalid envelope encoding")
	}
	if e.ContentType != nil {
		if _, _, err := mime.ParseMediaType(*e.ContentType); err != nil {
			return controls{}, errors.New("invalid envelope contentType")
		}
		c.contentType = *e.ContentType
	}
	c.body = io.NopCloser(bytes.NewReader(body))
	c.replacedBody = true
	return c, nil
}

type stringBytes []byte

func (s *stringBytes) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*s = []byte(v)
	return nil
}

func mergeMissing(dst *controls, src controls) {
	for _, pair := range [][2]*value{{&dst.url, &src.url}, {&dst.params, &src.params}, {&dst.https, &src.https}, {&dst.key, &src.key}} {
		if !pair[0].present && pair[1].present {
			*pair[0] = *pair[1]
		}
	}
	if src.replacedBody {
		dst.body, dst.contentType, dst.replacedBody = src.body, src.contentType, true
	}
}

func buildTargetURL(c controls, defaultScheme string) (*url.URL, error) {
	if !c.url.present || c.url.text == "" {
		return nil, errors.New("缺少 url 参数")
	}
	target := c.url.text
	if strings.ContainsAny(target, "\x00\r\n") {
		return nil, errors.New("目标 URL 非法")
	}
	if !strings.Contains(target, "://") {
		scheme := defaultScheme
		if c.https.present {
			b, err := strconv.ParseBool(c.https.text)
			if err != nil {
				return nil, errors.New("https 参数必须为 true 或 false")
			}
			if b {
				scheme = "https"
			}
		}
		target = scheme + "://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("目标 URL 非法")
	}
	if _, err := url.ParseRequestURI(u.RequestURI()); err != nil {
		return nil, errors.New("目标 URL 非法")
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return nil, errors.New("目标端口非法")
		}
	}
	if c.params.present {
		params, err := url.ParseQuery(c.params.text)
		if err != nil {
			return nil, errors.New("params 参数非法")
		}
		q := u.Query()
		for k, vals := range params {
			for _, v := range vals {
				q.Add(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}
	return u, nil
}
