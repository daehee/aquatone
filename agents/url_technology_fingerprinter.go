package agents

import (
	"bytes"
	"fmt"
	"os"
	"regexp"

	"github.com/PuerkitoBio/goquery"
	"github.com/daehee/wap"
	"github.com/zemnmez/aquatone/core"
)

type FingerprintRegexp struct {
	Regexp *regexp.Regexp
}

type Fingerprint struct {
	Name               string
	Categories         []string
	Implies            []string
	Website            string
	Headers            map[string]string
	HTML               []string
	Script             []string
	Meta               map[string]string
	HeaderFingerprints map[string]FingerprintRegexp
	HTMLFingerprints   []FingerprintRegexp
	ScriptFingerprints []FingerprintRegexp
	MetaFingerprints   map[string]FingerprintRegexp
}

func (f *Fingerprint) LoadPatterns() {
	f.HeaderFingerprints = make(map[string]FingerprintRegexp)
	f.MetaFingerprints = make(map[string]FingerprintRegexp)
	for header, pattern := range f.Headers {
		fingerprint, err := f.compilePattern(pattern)
		if err != nil {
			continue
		}
		f.HeaderFingerprints[header] = fingerprint
	}

	for _, pattern := range f.HTML {
		fingerprint, err := f.compilePattern(pattern)
		if err != nil {
			continue
		}
		f.HTMLFingerprints = append(f.HTMLFingerprints, fingerprint)
	}

	for _, pattern := range f.Script {
		fingerprint, err := f.compilePattern(pattern)
		if err != nil {
			continue
		}
		f.ScriptFingerprints = append(f.ScriptFingerprints, fingerprint)
	}

	for meta, pattern := range f.Meta {
		fingerprint, err := f.compilePattern(pattern)
		if err != nil {
			continue
		}
		f.MetaFingerprints[meta] = fingerprint
	}
}

func (f *Fingerprint) compilePattern(p string) (FingerprintRegexp, error) {
	var fingerprint FingerprintRegexp
	r, err := regexp.Compile(p)
	if err != nil {
		return fingerprint, err
	}
	fingerprint.Regexp = r

	return fingerprint, nil
}

type URLTechnologyFingerprinter struct {
	session      *core.Session
	fingerprints []Fingerprint
}

func NewURLTechnologyFingerprinter() *URLTechnologyFingerprinter {
	return &URLTechnologyFingerprinter{}
}

func (a *URLTechnologyFingerprinter) ID() string {
	return "agent:url_technology_fingerprinter"
}

func (a *URLTechnologyFingerprinter) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	a.session = s
	a.loadFingerprints()

	return nil
}

func (a *URLTechnologyFingerprinter) loadFingerprints() {
	wapFile := "wappalyzer.json"
	_, err := os.Stat(wapFile)
	if os.IsNotExist(err) {
		a.session.Out.Debug("Wappalyzer fingerprints file doesn't exist, downloading...\n")
		if err := wap.DownloadSource(wapFile); err != nil {
			a.session.Out.Fatal("Can't download Wappalyzer fingerprints file\n")
			os.Exit(1)
		}
	}
	w, err := wap.Fingerprints(wapFile)
	if err != nil {
		a.session.Out.Fatal("Can't read Wappalyzer fingerprints file\n")
		os.Exit(1)
	}

	for _, v := range w.Fingerprints {
		a.fingerprints = append(a.fingerprints, Fingerprint{
			Name:       v.Name,
			Categories: v.Categories,
			Implies:    v.Implies,
			Website:    v.Website,
			Headers:    v.Headers,
			HTML:       v.HTML,
			Script:     v.Scripts,
			Meta:       v.Meta,
		})
	}

	for i, _ := range a.fingerprints {
		a.fingerprints[i].LoadPatterns()
	}
}

func (a *URLTechnologyFingerprinter) OnURLResponsive(url string) {
	a.session.Out.Debug("[%s] Received new responsive URL %s\n", a.ID(), url)
	page := a.session.GetPage(url)
	if page == nil {
		a.session.Out.Error("Unable to find page for URL: %s\n", url)
		return
	}

	a.session.WaitGroup.Add()
	go func(page *core.Page) {
		defer a.session.WaitGroup.Done()
		seen := make(map[string]struct{})
		fingerprints := append(a.fingerprintHeaders(page), a.fingerprintBody(page)...)
		for _, f := range fingerprints {
			if _, ok := seen[f.Name]; ok {
				continue
			}
			seen[f.Name] = struct{}{}
			page.AddTag(f.Name, "info", f.Website)
			for _, impl := range f.Implies {
				if _, ok := seen[impl]; ok {
					continue
				}
				seen[impl] = struct{}{}
				for _, implf := range a.fingerprints {
					if impl == implf.Name {
						page.AddTag(implf.Name, "info", implf.Website)
						break
					}
				}
			}
		}
	}(page)
}

func (a *URLTechnologyFingerprinter) fingerprintHeaders(page *core.Page) []Fingerprint {
	var technologies []Fingerprint

	for _, header := range page.Headers {
		for _, fingerprint := range a.fingerprints {
			for name, pattern := range fingerprint.HeaderFingerprints {
				if name != header.Name {
					continue
				}

				if pattern.Regexp.MatchString(header.Value) {
					a.session.Out.Debug("[%s] Identified technology %s on %s from %s response header\n", a.ID(), fingerprint.Name, page.URL, header.Name)
					technologies = append(technologies, fingerprint)
				}
			}
		}
	}

	return technologies
}

func (a *URLTechnologyFingerprinter) fingerprintBody(page *core.Page) []Fingerprint {
	var technologies []Fingerprint
	body, err := a.session.ReadFile(fmt.Sprintf("html/%s.html", page.BaseFilename()))
	if err != nil {
		a.session.Out.Debug("[%s] Error reading HTML body file for %s: %s\n", a.ID(), page.URL, err)
		return technologies
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		a.session.Out.Debug("[%s] Error when parsing HTML body file for %s: %s\n", a.ID(), page.URL, err)
		return technologies
	}

	strBody := string(body)
	scripts := doc.Find("script")
	meta := doc.Find("meta")

	for _, fingerprint := range a.fingerprints {
		for _, pattern := range fingerprint.HTMLFingerprints {
			if pattern.Regexp.MatchString(strBody) {
				a.session.Out.Debug("[%s] Identified technology %s on %s from HTML\n", a.ID(), fingerprint.Name, page.URL)
				technologies = append(technologies, fingerprint)
			}
		}

		for _, pattern := range fingerprint.ScriptFingerprints {
			scripts.Each(func(i int, s *goquery.Selection) {
				if script, exists := s.Attr("src"); exists {
					if pattern.Regexp.MatchString(script) {
						a.session.Out.Debug("[%s] Identified technology %s on %s from script tag\n", a.ID(), fingerprint.Name, page.URL)
						technologies = append(technologies, fingerprint)
					}
				}
			})
		}

		for name, pattern := range fingerprint.MetaFingerprints {
			meta.Each(func(i int, s *goquery.Selection) {
				if n, _ := s.Attr("name"); n == name {
					content, _ := s.Attr("content")
					if pattern.Regexp.MatchString(content) {
						a.session.Out.Debug("[%s] Identified technology %s on %s from meta tag\n", a.ID(), fingerprint.Name, page.URL)
						technologies = append(technologies, fingerprint)
					}
				}
			})
		}
	}

	return technologies
}
