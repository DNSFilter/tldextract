package tldextract

import (
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	cache      = "/tmp/tld.cache"
	tldExtract *TLDExtract
	err        error
)

func init() {
	tldExtract, err = New(cache, false)
	if err != nil {
		log.Fatal(err)
	}
}

func assertManual(url string, expected *Result, returned *Result, t *testing.T) {
	if (expected.Flag == returned.Flag) && (expected.Root == returned.Root) && (expected.Sub == returned.Sub) && (expected.Tld == returned.Tld) {
		return
	}
	t.Errorf("%s;expected:%+v;returned:%+v", url, expected, returned)
}
func aTestA(t *testing.T) {
	result := tldExtract.Extract("9down.cc.html&amp;sa=u&amp;ei=4sfsul-ximsb4ateiicaag&amp;ved=0cbkqfjac&amp;usg=afqjcnfmetjm8-gpgyszv9l1h6_5p369yg/wp-content/themes/airfolio/scripts/timthumb.php")
	fmt.Println(result)
}

// this runs the test cases against the legacy/v1 version of the extract functionality
// NOTE: Items called out that are different than v2
func TestExtractLegacy(t *testing.T) {
	cases := map[string]*Result{
		// legacy tests : mostly check for pre-processing URL data sanitation
		"http://joe.blogspot.co.uk":                       &Result{Flag: Domain, Sub: "", Root: "joe", Tld: "blogspot.co.uk"},
		"ftp://johndoe:5cr1p7k1dd13@1337.warez.com:2501/": &Result{Flag: Domain, Sub: "1337", Root: "warez", Tld: "com"},
		"git+ssh://www.github.com:8443/":                  &Result{Flag: Domain, Sub: "www", Root: "github", Tld: "com"},
		"http://www.!github.com:8443/":                    &Result{Flag: Malformed},
		"http://www.theregister.co.uk":                    &Result{Flag: Domain, Sub: "www", Root: "theregister", Tld: "co.uk"},
		"http://media.forums.theregister.co.uk":           &Result{Flag: Domain, Sub: "media.forums", Root: "theregister", Tld: "co.uk"},
		"http://192.168.0.103":                            &Result{Flag: Ip4, Root: "192.168.0.103"},
		"http://216.22.project.coop/":                     &Result{Flag: Malformed}, // Different from v2 : Legacy does not handle trailing slash
		"http://216.22.project.coop/somepath/index.html":  &Result{Flag: Malformed}, // Different from v2 : Legacy does not handle trailing slash
		"http://Gmail.org":                                &Result{Flag: Domain, Root: "gmail", Tld: "org"},
		"http://wiki.info":                                &Result{Flag: Domain, Root: "wiki", Tld: "info"},
		"http://wiki.information/":                        &Result{Flag: Malformed},
		"http://wiki/":                                    &Result{Flag: Malformed}, // Different from v2 : Legacy does not identify eTLD
		"http://258.15.32.876":                            &Result{Flag: Malformed},
		"http://www.cgs.act.edu.au/":                      &Result{Flag: Malformed}, // Different from v2 : Legacy does not handle trailing slash
		"http://www.metp.net.cn":                          &Result{Flag: Domain, Sub: "www", Root: "metp", Tld: "net.cn"},
		"http://net.cn":                                   &Result{Flag: Malformed}, // Different from v2 : Legacy does not identify eTLD
		"cy":                                              &Result{Flag: Malformed}, // Different from v2 : Legacy does not identify eTLD
		"c.cy":                                            &Result{Flag: Domain, Sub: "", Root: "c", Tld: "cy"},
		"b.c.cy":                                          &Result{Flag: Domain, Sub: "b", Root: "c", Tld: "cy"},
		"a.b.c.cy":                                        &Result{Flag: Domain, Sub: "a.b", Root: "c", Tld: "cy"},
		"blah.blogspot.co.uk":                             &Result{Flag: Domain, Sub: "", Root: "blah", Tld: "blogspot.co.uk"},
		"aac.bb.com":                                      &Result{Flag: Domain, Sub: "aac", Root: "bb", Tld: "com"},
		// exclusion tests : PSL entry = !city.kobe.jp
		"b.ide.kyoto.jp":   &Result{Flag: Domain, Sub: "", Root: "b", Tld: "ide.kyoto.jp"},
		"a.b.ide.kyoto.jp": &Result{Flag: Domain, Sub: "a", Root: "b", Tld: "ide.kyoto.jp"},
		"b.c.kobe.jp":      &Result{Flag: Domain, Sub: "", Root: "b", Tld: "c.kobe.jp"},
		"a.b.c.kobe.jp":    &Result{Flag: Domain, Sub: "a", Root: "b", Tld: "c.kobe.jp"},
		"city.kobe.jp":     &Result{Flag: Domain, Sub: "", Root: "city", Tld: "kobe.jp"},
		"city.a.kobe.jp":   &Result{Flag: Domain, Sub: "", Root: "city", Tld: "a.kobe.jp"},

		// eTLD/suffix tests
		// Different than v2 : Legacy does not identify eTLD
		//"net":            &Result{Flag: eTLD, Sub: "", Root: "", Tld: "net"},
		//"blogspot.co.uk": &Result{Flag: eTLD, Sub: "", Root: "", Tld: "blogspot.co.uk"},
		//"google.com":     &Result{Flag: eTLD, Sub: "", Root: "", Tld: "google.com"},
		//"msn.com":        &Result{Flag: eTLD, Sub: "", Root: "", Tld: "msn.com"},
		//"r.msn.com":      &Result{Flag: eTLD, Sub: "", Root: "", Tld: "r.msn.com"},
		// invalid TLDs
		"local":                        &Result{Flag: Malformed},
		"singlelevel.local":            &Result{Flag: Malformed},
		"let.the.rabbits.wear.glasses": &Result{Flag: Malformed},
		// wildcard tests : PSL entry = *.s5y.io
		"qqq.zyx.abc.s5y.io": &Result{Flag: Domain, Sub: "qqq", Root: "zyx", Tld: "abc.s5y.io"},
		"s5y.io":             &Result{Flag: Malformed}, // different than v2 : does not identify eTLD
		"zzz.s5y.io":         &Result{Flag: Malformed}, // different than v2 : does not identify eTLD
		// IDN tests
		"한국":             &Result{Flag: Malformed}, // different than v2 : does not identify eTLD
		"abc.한국":         &Result{Flag: Domain, Sub: "", Root: "abc", Tld: "한국"},
		"def.zyx.abc.한국": &Result{Flag: Domain, Sub: "def.zyx", Root: "abc", Tld: "한국"},
		// IP tests
		"3.171.139.127": &Result{Flag: Ip4, Sub: "", Root: "3.171.139.127", Tld: ""},
		"3.4.5.900":     &Result{Flag: Malformed},

		// IPv6 fails to be identified
		//"2600:9000:24f4:5400:d:ac18:e2c0:93a1": &Result{Flag: Ip6, Sub: "", Root: "city", Tld: ""},
	}
	for url, expected := range cases {
		returned := tldExtract.Extract(url)
		assertManual(url, expected, returned, t)
	}
}

func TestExtractV2(t *testing.T) {
	cases := map[string]*Result{
		// legacy tests : mostly check for pre-processing URL data sanitation
		"http://joe.blogspot.co.uk":                       &Result{Flag: Domain, Sub: "", Root: "joe", Tld: "blogspot.co.uk"},
		"ftp://johndoe:5cr1p7k1dd13@1337.warez.com:2501/": &Result{Flag: Domain, Sub: "1337", Root: "warez", Tld: "com"},
		"git+ssh://www.github.com:8443/":                  &Result{Flag: Domain, Sub: "www", Root: "github", Tld: "com"},
		"http://www.!github.com:8443/":                    &Result{Flag: Malformed},
		"http://www.theregister.co.uk":                    &Result{Flag: Domain, Sub: "www", Root: "theregister", Tld: "co.uk"},
		"http://media.forums.theregister.co.uk":           &Result{Flag: Domain, Sub: "media.forums", Root: "theregister", Tld: "co.uk"},
		"http://192.168.0.103":                            &Result{Flag: Ip4, Root: "192.168.0.103"},
		"http://216.22.project.coop/":                     &Result{Flag: Domain, Sub: "216.22", Root: "project", Tld: "coop"},
		"http://216.22.project.coop/somepath/index.html":  &Result{Flag: Domain, Sub: "216.22", Root: "project", Tld: "coop"},
		"http://Gmail.org":                                &Result{Flag: Domain, Root: "gmail", Tld: "org"},
		"http://wiki.info":                                &Result{Flag: Domain, Root: "wiki", Tld: "info"},
		"http://wiki.information/":                        &Result{Flag: Malformed},
		"http://wiki/":                                    &Result{Flag: eTLD, Sub: "", Root: "", Tld: "wiki"},
		"http://258.15.32.876":                            &Result{Flag: Malformed},
		"http://www.cgs.act.edu.au/":                      &Result{Flag: Domain, Sub: "www", Root: "cgs", Tld: "act.edu.au"},
		"http://www.metp.net.cn":                          &Result{Flag: Domain, Sub: "www", Root: "metp", Tld: "net.cn"},
		"http://net.cn":                                   &Result{Flag: eTLD, Sub: "", Root: "", Tld: "net.cn"},
		"cy":                                              &Result{Flag: eTLD, Sub: "", Root: "", Tld: "cy"},
		"c.cy":                                            &Result{Flag: Domain, Sub: "", Root: "c", Tld: "cy"},
		"b.c.cy":                                          &Result{Flag: Domain, Sub: "b", Root: "c", Tld: "cy"},
		"a.b.c.cy":                                        &Result{Flag: Domain, Sub: "a.b", Root: "c", Tld: "cy"},
		"blah.blogspot.co.uk":                             &Result{Flag: Domain, Sub: "", Root: "blah", Tld: "blogspot.co.uk"},
		"aac.bb.com":                                      &Result{Flag: Domain, Sub: "aac", Root: "bb", Tld: "com"},
		// exclusion tests : PSL entry = !city.kobe.jp
		"b.ide.kyoto.jp":   &Result{Flag: Domain, Sub: "", Root: "b", Tld: "ide.kyoto.jp"},
		"a.b.ide.kyoto.jp": &Result{Flag: Domain, Sub: "a", Root: "b", Tld: "ide.kyoto.jp"},
		"b.c.kobe.jp":      &Result{Flag: Domain, Sub: "", Root: "b", Tld: "c.kobe.jp"},
		"a.b.c.kobe.jp":    &Result{Flag: Domain, Sub: "a", Root: "b", Tld: "c.kobe.jp"},
		"city.kobe.jp":     &Result{Flag: Domain, Sub: "", Root: "city", Tld: "kobe.jp"},
		"city.a.kobe.jp":   &Result{Flag: Domain, Sub: "", Root: "city", Tld: "a.kobe.jp"},
		// eTLD/suffix tests
		"net":            &Result{Flag: eTLD, Sub: "", Root: "", Tld: "net"},
		"blogspot.co.uk": &Result{Flag: eTLD, Sub: "", Root: "", Tld: "blogspot.co.uk"},
		"google.com":     &Result{Flag: eTLD, Sub: "", Root: "", Tld: "google.com"},
		"msn.com":        &Result{Flag: eTLD, Sub: "", Root: "", Tld: "msn.com"},
		"r.msn.com":      &Result{Flag: eTLD, Sub: "", Root: "", Tld: "r.msn.com"},
		// invalid TLDs
		"local":                        &Result{Flag: Malformed},
		"singlelevel.local":            &Result{Flag: Malformed},
		"let.the.rabbits.wear.glasses": &Result{Flag: Malformed},
		// wildcard tests : PSL entry = *.s5y.io
		"qqq.zyx.abc.s5y.io": &Result{Flag: Domain, Sub: "qqq", Root: "zyx", Tld: "abc.s5y.io"},
		"s5y.io":             &Result{Flag: eTLD, Sub: "", Root: "", Tld: "s5y.io"},
		"zzz.s5y.io":         &Result{Flag: eTLD, Sub: "", Root: "", Tld: "zzz.s5y.io"},
		// IDN tests
		"한국":             &Result{Flag: eTLD, Sub: "", Root: "", Tld: "한국"},
		"abc.한국":         &Result{Flag: Domain, Sub: "", Root: "abc", Tld: "한국"},
		"def.zyx.abc.한국": &Result{Flag: Domain, Sub: "def.zyx", Root: "abc", Tld: "한국"},
		// IP tests
		"3.171.139.127": &Result{Flag: Ip4, Sub: "", Root: "3.171.139.127", Tld: ""},
		"3.4.5.900":     &Result{Flag: Malformed},

		// IPv6 fails to be identified
		//"2600:9000:24f4:5400:d:ac18:e2c0:93a1": &Result{Flag: Ip6, Sub: "", Root: "city", Tld: ""},
	}
	for url, expected := range cases {
		returned := tldExtract.ExtractV2(url)
		assertManual(url, expected, returned, t)
	}
}

// cases:  Ensure eTLD/Suffix is correctly identified
func TestIsValidSuffix(t *testing.T) {

	inPsl := []string{
		"google.com",
		"amazon.com",
		"com",
		"co.uk",
		"broker.aero",
		"edu",
		"ring.com",
		"mobile.events.data.trafficmanager.net",
		"blogspot.co.uk",
		"한국",
		"msn.com",
		"r.msn.com",
	}

	notInPsl := []string{
		"api.google.com",
		"app.dnsfilter.com",
		"local",
		"x",
		"invalidtld",
		"a.b.한",
	}

	for _, url := range inPsl {
		isSuffix := tldExtract.IsValidSuffix(url)
		assert.True(t, isSuffix)
	}

	for _, url := range notInPsl {
		isSuffix := tldExtract.IsValidSuffix(url)
		assert.False(t, isSuffix)
	}

}
