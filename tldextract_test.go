package tldextract

import (
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

// this runs the test cases against the legacy/v1 version of the extract functionality
// NOTE: Items called out that are different than v2
func TestExtractLegacy(t *testing.T) {
	cases := map[string]*Result{
		// legacy tests : mostly check for pre-processing URL data sanitation
		"http://joe.blogspot.co.uk":                       {Flag: Domain, Sub: "", Root: "joe", Tld: "blogspot.co.uk"},
		"ftp://johndoe:5cr1p7k1dd13@1337.warez.com:2501/": {Flag: Domain, Sub: "1337", Root: "warez", Tld: "com"},
		"git+ssh://www.github.com:8443/":                  {Flag: Domain, Sub: "www", Root: "github", Tld: "com"},
		"http://www.!github.com:8443/":                    {Flag: Malformed},
		"http://www.theregister.co.uk":                    {Flag: Domain, Sub: "www", Root: "theregister", Tld: "co.uk"},
		"http://media.forums.theregister.co.uk":           {Flag: Domain, Sub: "media.forums", Root: "theregister", Tld: "co.uk"},
		"http://192.168.0.103":                            {Flag: Ip4, Root: "192.168.0.103"},
		"http://216.22.project.coop/":                     {Flag: Malformed}, // Different from v2 : Legacy does not handle trailing slash
		"http://216.22.project.coop/somepath/index.html":  {Flag: Malformed}, // Different from v2 : Legacy does not handle trailing slash
		"http://Gmail.org":                                {Flag: Domain, Root: "gmail", Tld: "org"},
		"http://wiki.info":                                {Flag: Domain, Root: "wiki", Tld: "info"},
		"http://wiki.information/":                        {Flag: Malformed},
		"http://wiki/":                                    {Flag: Malformed}, // Different from v2 : Legacy does not identify eTLD
		"http://258.15.32.876":                            {Flag: Malformed},
		"http://www.cgs.act.edu.au/":                      {Flag: Malformed}, // Different from v2 : Legacy does not handle trailing slash
		"http://www.metp.net.cn":                          {Flag: Domain, Sub: "www", Root: "metp", Tld: "net.cn"},
		"http://net.cn":                                   {Flag: Malformed}, // Different from v2 : Legacy does not identify eTLD
		"cy":                                              {Flag: Malformed}, // Different from v2 : Legacy does not identify eTLD
		"c.cy":                                            {Flag: Domain, Sub: "", Root: "c", Tld: "cy"},
		"b.c.cy":                                          {Flag: Domain, Sub: "b", Root: "c", Tld: "cy"},
		"a.b.c.cy":                                        {Flag: Domain, Sub: "a.b", Root: "c", Tld: "cy"},
		"blah.blogspot.co.uk":                             {Flag: Domain, Sub: "", Root: "blah", Tld: "blogspot.co.uk"},
		"aac.bb.com":                                      {Flag: Domain, Sub: "aac", Root: "bb", Tld: "com"},
		// exclusion tests : PSL entry = !city.kobe.jp
		"b.ide.kyoto.jp":   {Flag: Domain, Sub: "", Root: "b", Tld: "ide.kyoto.jp"},
		"a.b.ide.kyoto.jp": {Flag: Domain, Sub: "a", Root: "b", Tld: "ide.kyoto.jp"},
		"b.c.kobe.jp":      {Flag: Domain, Sub: "", Root: "b", Tld: "c.kobe.jp"},
		"a.b.c.kobe.jp":    {Flag: Domain, Sub: "a", Root: "b", Tld: "c.kobe.jp"},
		"city.kobe.jp":     {Flag: Domain, Sub: "", Root: "city", Tld: "kobe.jp"},
		"city.a.kobe.jp":   {Flag: Domain, Sub: "", Root: "city", Tld: "a.kobe.jp"},

		// eTLD/suffix tests
		// Different than v2 : Legacy does not identify eTLD
		//"net":            {Flag: eTLD, Sub: "", Root: "", Tld: "net"},
		//"blogspot.co.uk": {Flag: eTLD, Sub: "", Root: "", Tld: "blogspot.co.uk"},
		//"google.com":     {Flag: eTLD, Sub: "", Root: "", Tld: "google.com"},
		//"msn.com":        {Flag: eTLD, Sub: "", Root: "", Tld: "msn.com"},
		//"r.msn.com":      {Flag: eTLD, Sub: "", Root: "", Tld: "r.msn.com"},
		// invalid TLDs
		"local":                        {Flag: Malformed},
		"singlelevel.local":            {Flag: Malformed},
		"let.the.rabbits.wear.glasses": {Flag: Malformed},
		// wildcard tests : PSL entry = *.s5y.io
		"qqq.zyx.abc.s5y.io": {Flag: Domain, Sub: "qqq", Root: "zyx", Tld: "abc.s5y.io"},
		"s5y.io":             {Flag: Malformed}, // different than v2 : does not identify eTLD
		"zzz.s5y.io":         {Flag: Malformed}, // different than v2 : does not identify eTLD
		// IDN tests
		"한국":             {Flag: Malformed}, // different than v2 : does not identify eTLD
		"abc.한국":         {Flag: Domain, Sub: "", Root: "abc", Tld: "한국"},
		"def.zyx.abc.한국": {Flag: Domain, Sub: "def.zyx", Root: "abc", Tld: "한국"},
		// IP tests
		"3.171.139.127": {Flag: Ip4, Sub: "", Root: "3.171.139.127", Tld: ""},
		"3.4.5.900":     {Flag: Malformed},

		// IPv6 fails to be identified
		//"2600:9000:24f4:5400:d:ac18:e2c0:93a1": {Flag: Ip6, Sub: "", Root: "city", Tld: ""},
	}
	for url, expected := range cases {
		returned := tldExtract.Extract(url)
		assert.Equal(t, expected, returned)
	}
}

func TestExtractV2(t *testing.T) {
	cases := map[string]*Result{
		// legacy tests : mostly check for pre-processing URL data sanitation
		"http://joe.blogspot.co.uk":                       {Flag: Domain, Sub: "", Root: "joe", Tld: "blogspot.co.uk"},
		"ftp://johndoe:5cr1p7k1dd13@1337.warez.com:2501/": {Flag: Domain, Sub: "1337", Root: "warez", Tld: "com"},
		"git+ssh://www.github.com:8443/":                  {Flag: Domain, Sub: "www", Root: "github", Tld: "com"},
		"http://www.!github.com:8443/":                    {Flag: Malformed},
		"http://www.theregister.co.uk":                    {Flag: Domain, Sub: "www", Root: "theregister", Tld: "co.uk"},
		"http://media.forums.theregister.co.uk":           {Flag: Domain, Sub: "media.forums", Root: "theregister", Tld: "co.uk"},
		"http://192.168.0.103":                            {Flag: Ip4, Root: "192.168.0.103"},
		"http://216.22.project.coop/":                     {Flag: Domain, Sub: "216.22", Root: "project", Tld: "coop"},
		"http://216.22.project.coop/somepath/index.html":  {Flag: Domain, Sub: "216.22", Root: "project", Tld: "coop"},
		"http://Gmail.org":                                {Flag: Domain, Root: "gmail", Tld: "org"},
		"http://wiki.info":                                {Flag: Domain, Root: "wiki", Tld: "info"},
		"http://wiki.information/":                        {Flag: Malformed},
		"http://wiki/":                                    {Flag: ETld, Sub: "", Root: "", Tld: "wiki"},
		"http://258.15.32.876":                            {Flag: Malformed},
		"http://www.cgs.act.edu.au/":                      {Flag: Domain, Sub: "www", Root: "cgs", Tld: "act.edu.au"},
		"http://www.metp.net.cn":                          {Flag: Domain, Sub: "www", Root: "metp", Tld: "net.cn"},
		"http://net.cn":                                   {Flag: ETld, Sub: "", Root: "", Tld: "net.cn"},
		"cy":                                              {Flag: ETld, Sub: "", Root: "", Tld: "cy"},
		"c.cy":                                            {Flag: Domain, Sub: "", Root: "c", Tld: "cy"},
		"b.c.cy":                                          {Flag: Domain, Sub: "b", Root: "c", Tld: "cy"},
		"a.b.c.cy":                                        {Flag: Domain, Sub: "a.b", Root: "c", Tld: "cy"},
		"blah.blogspot.co.uk":                             {Flag: Domain, Sub: "", Root: "blah", Tld: "blogspot.co.uk"},
		"aac.bb.com":                                      {Flag: Domain, Sub: "aac", Root: "bb", Tld: "com"},
		// exclusion tests : PSL entry = !city.kobe.jp
		"b.ide.kyoto.jp":   {Flag: Domain, Sub: "", Root: "b", Tld: "ide.kyoto.jp"},
		"a.b.ide.kyoto.jp": {Flag: Domain, Sub: "a", Root: "b", Tld: "ide.kyoto.jp"},
		"b.c.kobe.jp":      {Flag: Domain, Sub: "", Root: "b", Tld: "c.kobe.jp"},
		"a.b.c.kobe.jp":    {Flag: Domain, Sub: "a", Root: "b", Tld: "c.kobe.jp"},
		"city.kobe.jp":     {Flag: Domain, Sub: "", Root: "city", Tld: "kobe.jp"},
		"city.a.kobe.jp":   {Flag: Domain, Sub: "", Root: "city", Tld: "a.kobe.jp"},
		// eTLD/suffix tests
		"net":            {Flag: ETld, Sub: "", Root: "", Tld: "net"},
		"blogspot.co.uk": {Flag: ETld, Sub: "", Root: "", Tld: "blogspot.co.uk"},
		"google.com":     {Flag: ETld, Sub: "", Root: "", Tld: "google.com"},
		"msn.com":        {Flag: ETld, Sub: "", Root: "", Tld: "msn.com"},
		"r.msn.com":      {Flag: ETld, Sub: "", Root: "", Tld: "r.msn.com"},
		// invalid TLDs
		"local":                        {Flag: Malformed},
		"singlelevel.local":            {Flag: Malformed},
		"let.the.rabbits.wear.glasses": {Flag: Malformed},
		// wildcard tests : PSL entry = *.s5y.io
		"qqq.zyx.abc.s5y.io": {Flag: Domain, Sub: "qqq", Root: "zyx", Tld: "abc.s5y.io"},
		"s5y.io":             {Flag: ETld, Sub: "", Root: "", Tld: "s5y.io"},
		"zzz.s5y.io":         {Flag: ETld, Sub: "", Root: "", Tld: "zzz.s5y.io"},
		// IDN tests
		"한국":             {Flag: ETld, Sub: "", Root: "", Tld: "한국"},
		"abc.한국":         {Flag: Domain, Sub: "", Root: "abc", Tld: "한국"},
		"def.zyx.abc.한국": {Flag: Domain, Sub: "def.zyx", Root: "abc", Tld: "한국"},
		// IP tests
		"3.171.139.127": {Flag: Ip4, Sub: "", Root: "3.171.139.127", Tld: ""},
		"3.4.5.900":     {Flag: Malformed},

		// IPv6 fails to be identified
		//"2600:9000:24f4:5400:d:ac18:e2c0:93a1": {Flag: Ip6, Sub: "", Root: "city", Tld: ""},
	}
	for url, expected := range cases {
		returned := tldExtract.ExtractV2(url)
		assert.Equal(t, expected, returned)
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
		"test.kobe.jp",
		"kobe.jp",
		"abc.uberspace.de",
		"zyx.uberspace.de",
	}

	notInPsl := []string{
		"api.google.com",
		"app.dnsfilter.com",
		"local",
		"x",
		"invalidtld",
		"a.b.한",
		"city.kobe.jp",
		"city.test.kobe.jp",
		"def.zyx.abc.uberspace.de",
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
