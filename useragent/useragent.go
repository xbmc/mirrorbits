// Copyright (c) 2012-2015 Miquel Sabaté Solà <mikisabate@gmail.com>
// Copyright (c) 2015 wsnipex
// Licensed under the MIT license

package useragent

import (
	. "github.com/wsnipex/mirrorbits/config"
	"github.com/op/go-logging"
	"regexp"
	"strings"
)

var (
	log = logging.MustGetLogger("main")
)

type section struct {
	Name    string
	Version string
	Comment []string
}

type UserAgent struct {
	UA         string
	Platform   string
	OS         string
	OSVer      string
	Browser    string
	BrowserVer string
	Engine     string
	EngineVer  string
}

type UaInfo struct {
	Platform string `redis:"platform" json:",omitempty"`
	OS       string `redis:"os" json:",omitempty"`
	Browser  string `redis:"browser" json:",omitempty"`
	Special  bool
}

// Read from the given string until the given delimiter or the
// end of the string have been reached.
//
// The first argument is the user agent string being parsed. The second
// argument is a reference pointing to the current index of the user agent
// string. The delimiter argument specifies which character is the delimiter
// and the cat argument determines whether nested '(' should be ignored or not.
//
// Returns an array of bytes containing what has been read.
func readUntil(ua string, index *int, delim byte, cat bool) []byte {
	var buffer []byte

	i := *index
	catalan := 0
	for ; i < len(ua); i++ {
		if ua[i] == delim {
			if catalan == 0 {
				*index = i + 1
				return buffer
			}
			catalan--
		} else if cat && ua[i] == '(' {
			catalan++
		}
		buffer = append(buffer, ua[i])
	}
	*index = i + 1
	return buffer
}

// Parse the given product
func parseProduct(product []byte) (string, string) {
	prod := strings.SplitN(string(product), "/", 2)
	if len(prod) == 2 {
		return prod[0], prod[1]
	}
	return string(product), ""
}

// Parse a section formatted as "Name/Version (comment)",
// returning a section containing the parsed information
func parseSection(ua string, index *int) (s section) {
	buffer := readUntil(ua, index, ' ', false)

	s.Name, s.Version = parseProduct(buffer)
	if *index < len(ua) && ua[*index] == '(' {
		*index++
		buffer = readUntil(ua, index, ')', true)
		s.Comment = strings.Split(string(buffer), "; ")
		*index++
	}
	return s
}

// Parse the given User-Agent string, returning an UserAgent object
func NewUserAgent(ua string) *UserAgent {
	p := &UserAgent{}
	p.Parse(ua)
	return p
}

// Parse the given User-Agent string
func (p *UserAgent) Parse(ua string) {
	p.UA = ua
	p.Platform = ""
	p.OS = ""
	p.OSVer = ""
	p.Browser = ""
	p.BrowserVer = ""
	p.Engine = ""
	p.EngineVer = ""
	comments := []string{}

	engines := GetConfig().UserAgentStatsConf.CheckEngines
	var sections []section

	for index, limit := 0, len(ua); index < limit; {
		s := parseSection(ua, &index)
		sections = append(sections, s)
	}

	if len(sections) > 1 {
		p.Engine = sections[1].Name
		p.EngineVer = sections[1].Version
	}

	if len(sections) > 0 {
		p.Browser = strings.Title(sections[0].Name)
		p.BrowserVer = sections[0].Version
		p.normalizeBrowser()

		// comments is the block in parentheses
		comments = sections[0].Comment
	}

	nc := len(comments)

	// usually the platform is the 1st field, OS the 2nd field in the comment block "()"
	// if there is only 1 field, we use it as platform and then try to refine later
	if nc >= 2 && len(comments[1]) > 2 {
		p.Platform = strings.Title(comments[0])
		p.OS = strings.Title(comments[1])

	} else if nc > 0 {
		p.Platform = strings.Title(comments[0])
		p.OS = "Unknown"

	} else {
		p.Platform = "Unknown"
		p.OS = "Unknown"

		if GetConfig().UserAgentStatsConf.LogUnknown {
			log.Debug("Unknown or incomplete UserAgent: %s", p.UA)
		}
		return
	}

	// special cases and normalization
	if strings.Contains(p.OS, "Android") || (nc >= 3 && strings.Contains(comments[2], "Android")) {
		// set platform to Android with the version limited to Major.Minor

		p.Platform = "Android"
		for _, com := range comments {
			if strings.ContainsAny(com, "0123456789") {
				o := strings.Split(com, " ")
				if len(o) >= 2 && strings.ContainsAny(o[1], "0123456789") {
					v := strings.Split(o[1], ".")
					if len(v) >= 2 {
						p.OS = "Android"
						p.OSVer = v[0] + "." + v[1]
						return
					}
				}
			}
		}
		p.OS = "Android Unknown"
		return

	} else if strings.Contains(p.UA, "Windows") {
		for _, com := range comments {
			if strings.Contains(com, "Windows NT") {
				p.Platform = com
			}
		}
		p.normalizeWindows()
		return

	} else if strings.Contains(p.Platform, "IPhone") {
		p.Platform = "IPhone"
		p.normalizeApple(comments)

	} else if strings.Contains(p.Platform, "IPod") {
		p.Platform = "IPod"
		p.normalizeApple(comments)

	} else if strings.Contains(p.Platform, "IPad") {
		p.Platform = "IPad"
		p.normalizeApple(comments)

	} else if strings.Contains(p.Platform, "AppleTV") {
		p.Platform = "AppleTV"
		p.normalizeApple(comments)

	} else if strings.Contains(p.Platform, "Macintosh") {
		p.Platform = "Macintosh"
		p.normalizeApple(comments)

	} else if p.OS == "Ubuntu" ||
		strings.Contains(p.Platform, "Linux") ||
		(p.Platform == "X11" && strings.Contains(p.OS, "Linux")) {

		p.Platform = "Linux"
		if p.OS == "Unknown" {
			p.OS = "Linux"
		}
		// don't return here, we still need to check the engines
	}

	// some user agents need special treatment
	for _, e := range engines {
		if strings.Contains(p.Engine, e) {
			p.OS = p.Engine
			p.OSVer = p.EngineVer
			break
		} else if strings.Contains(p.UA, e) {
			p.OS = e
			p.OSVer = p.EngineVer
			break
		}
		if strings.Contains(p.OS, "OpenELEC") || strings.Contains(p.OS, "Raspbian") {
			// Openelec and Raspbian are linux platforms
			p.Platform = "Linux"
			return
		}
	}

	// sanitize OS
	if strings.Trim(p.OS, " ") == "" ||
		strings.Contains(p.OS, "bot") ||
		strings.Contains(p.OS, "Mozilla") ||
		strings.ContainsAny(p.OS, ";-+:!") {

		p.OS = "Unknown"
	}

	// sanitize platform
	if len(p.Platform) < 3 ||
		p.Platform == "Compatible" ||
		strings.ContainsAny(p.Platform, ";-+:!") {
		p.Platform = "Unknown"

	} else if strings.Contains(strings.ToLower(p.Platform), "bot") {

		p.Platform = "Unknown"
		p.Browser = "Bots"

	} else if strings.Contains(p.Platform, "/") {
		p.Platform = strings.Split(p.Platform, "/")[0]
		if strings.Contains(strings.ToLower(p.Platform), "http") {
			p.Platform = "Unknown"
		}
	}
}

func (p *UserAgent) normalizeBrowser() {
	if len(p.Browser) < 3 || len(p.Browser) > 8 {
		p.Browser = "Unknown"
		return
	}

	browsersWithVer := GetConfig().UserAgentStatsConf.BrowsersWithVersion
	var browsers = map[string]string{
		"Trident":  "IE",
		"Edge":     "IE",
		"MSIE":     "IE",
		"Firefox":  "Firefox",
		"Chrome":   "Chrome",
		"Chromium": "Chrome",
		"Safari":   "Safari",
		"bot":      "Bots",
		"Bot":      "Bots",
		"http://":  "Bots"}

	bv := p.BrowserVer

	switch p.Browser {
	case "Mozilla":
		for m, bn := range browsers {
			if strings.Contains(p.UA, m) {
				p.Browser = bn
				p.BrowserVer = ""
				break
			}
		}
	case "Google":
		p.Browser = "Bots"
	default:
		bl := strings.ToLower(p.Browser)
		if strings.Contains(bl, "bot") || strings.Contains(bl, "crawler") {
			p.Browser = "Bots"
			p.OS = "Unknown"
			return
		}
	}

	for _, b := range browsersWithVer {
		if b == p.Browser {
			p.Browser = p.Browser + " " + bv
			break
		}
	}
}

func (p *UserAgent) normalizeWindows() {
	w := strings.SplitN(p.Platform, " ", 3)
	if len(w) != 3 {
		return
	}
	p.Platform = "Windows"
	switch w[2] {
	case "5.0":
		p.OS = "Windows"
		p.OSVer = "2000"
	case "5.01":
		p.OS = "Windows"
		p.OSVer = "2000"
	case "5.1":
		p.OS = "Windows"
		p.OSVer = "XP"
	case "5.2":
		p.OS = "Windows"
		p.OSVer = "XP"
	case "6.0":
		p.OS = "Windows"
		p.OSVer = "Vista"
	case "6.1":
		p.OS = "Windows"
		p.OSVer = "7"
	case "6.2":
		p.OS = "Windows"
		p.OSVer = "8"
	case "6.3":
		p.OS = "Windows"
		p.OSVer = "8.1"
	case "6.4":
		p.OS = "Windows"
		p.OSVer = "10"
	case "10.0":
		p.OS = "Windows"
		p.OSVer = "10"
	default:
		if strings.ContainsAny(w[2], "0123456789") {
			n := strings.Split(w[2], ", ")
			if len(n) > 1 {
				p.Platform = n[1]
				p.normalizeWindows()
			}
		} else {
			p.OS = "Windows Unknown"
		}
	}
}

func (p *UserAgent) normalizeApple(comments []string) {

	if p.Platform == "IPhone" ||
		p.Platform == "IPad" ||
		p.Platform == "IPod" ||
		p.Platform == "AppleTV" {

		// some Apple UAs don't separate by "; ", but by ";"
		if strings.Contains(p.Platform, ";") {
			tmp := strings.Split(p.Platform, ";")
			p.Platform = tmp[0]
			comments = tmp[1:]
		}
		// set OS to IOS with the version limited to Major.Minor
		for _, com := range comments {
			if strings.ContainsAny(com, "0123456789") {
				o := strings.Split(com, " ")
				v := []string{}
				if len(o) >= 4 && strings.ContainsAny(o[3], "0123456789") {
					v = strings.Split(o[3], "_")
				} else if len(o) >= 3 && strings.ContainsAny(o[2], "0123456789") {
					v = strings.Split(o[2], "_")
				}
				if len(v) >= 2 {
					p.OS = "IOS"
					p.OSVer = v[0] + "." + v[1]
					return
				}
			}
		}
		p.OS = "IOS Unknown"
		return

	} else if p.Platform == "Macintosh" {

		// set OS to OSX with the version limited to Major.Minor
		for _, com := range comments {
			if strings.ContainsAny(com, "0123456789") {
				o := strings.Split(com, " ")
				if len(o) >= 5 && strings.ContainsAny(o[4], "0123456789") {
					v := strings.Split(o[4], "_")
					if len(v) >= 2 {
						p.OS = "OSX"
						p.OSVer = v[0] + "." + v[1]
						return
					}
				}
			}
		}
		p.OS = "OSX Unknown"
		return
	}
}
