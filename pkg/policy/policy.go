// Package policy decides the Harbor level of a grype finding and explains the decision.
package policy

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

// Thresholds are grype risk scores (0–100) from which the ladder gives a level.
type Thresholds struct {
	Critical float64
	High     float64
	Medium   float64
}

// ExploitLookup returns the ids of Exploit-DB exploits for a CVE. The returned slice may be
// shared with the index: callers must not modify it.
type ExploitLookup interface {
	Lookup(cve string) []string
}

// Result is the level of one finding, the explanation shown in Harbor and links to exploits.
type Result struct {
	Severity harbor.Severity
	Reason   string
	Links    []string
}

const maxExploitLinks = 5

// Evaluate gives one grype match its Harbor level:
//  1. listed in the CISA KEV catalogue → Critical;
//  2. a malicious package or embedded malicious code → Critical;
//  3. otherwise the grype risk ladder when EPSS is known,
//  4. or grype's own severity capped at High when it is not;
//  5. a public exploit then raises levels below High.
func Evaluate(m grype.Match, lookup ExploitLookup, t Thresholds) Result {
	f := collectFacts(m, lookup)
	var r reason
	if len(f.vuln.KnownExploited) > 0 {
		r = kevRule(f)
	} else if ok, source := f.malware(); ok {
		r = malwareRule(source)
	} else {
		r = exploitRule(f, baseRule(f, t))
	}
	return Result{Severity: r.level, Reason: r.String(), Links: exploitLinks(f.exploits)}
}

func kevRule(f facts) reason {
	added, ransomware := "", false
	for _, k := range f.vuln.KnownExploited {
		date := k.DateAdded
		if len(date) > 10 {
			date = date[:10]
		}
		if date != "" && (added == "" || date < added) {
			added = date
		}
		if strings.EqualFold(k.KnownRansomwareCampaignUse, "known") {
			ransomware = true
		}
	}
	main := "есть в каталоге KEV"
	if added != "" {
		main += " с " + added
	}
	if ransomware {
		main += ", используется вымогателями"
	}
	r := reason{level: harbor.SevCritical, main: main}
	if f.hasExploit() {
		r.facts = append(r.facts, exploitFact(f))
	}
	r.facts = append(r.facts, "риск grype "+formatRisk(f.vuln.Risk))
	return r
}

func malwareRule(source string) reason {
	if source == "github" {
		return reason{level: harbor.SevCritical,
			main: "пакет помечен как вредоносный (бюллетень GitHub о вредоносном пакете), проверьте, откуда он в образе"}
	}
	return reason{level: harbor.SevCritical, main: "встроенный вредоносный код (CWE-506)"}
}

// base is the level from rule 3 or 4 and what it rests on, for "без эксплойта было бы …".
type base struct {
	reason
	basis string
}

func baseRule(f facts, t Thresholds) base {
	if len(f.vuln.EPSS) == 0 {
		return noEPSSRule(f)
	}
	return ladderRule(f, t)
}

// ladderRule is rule 3: grype risk compared with the thresholds. The risk is compared as the text
// shows it (shownRisk), so the level never contradicts the explanation.
func ladderRule(f facts, t Thresholds) base {
	est := estimateRisk(f.vuln)
	risk := shownRisk(est.value)
	level, threshold := harbor.SevLow, "ниже порога Medium"
	switch {
	case risk >= t.Critical:
		level, threshold = harbor.SevCritical, "порог Critical от "+formatThreshold(t.Critical)
	case risk >= t.High:
		level, threshold = harbor.SevHigh, "порог High от "+formatThreshold(t.High)
	case risk >= t.Medium:
		level, threshold = harbor.SevMedium, "порог Medium от "+formatThreshold(t.Medium)
	}
	sev := grypeSeverity(f.vuln.Severity)
	if est.rescaled {
		main := fmt.Sprintf("риск %s по максимальному EPSS бюллетеня (%s, %s), grype показывает %s; %s (критичность grype %s)",
			formatRisk(est.value), est.epss.CVE, formatPercent(est.epss.Score), formatRisk(est.reported), threshold, sev)
		return base{reason: reason{level: level, main: main}, basis: "риск " + formatRisk(est.value)}
	}
	main := fmt.Sprintf("риск grype %s, %s (EPSS %s, критичность grype %s)",
		formatRisk(est.value), threshold, formatPercent(est.epss.Score), sev)
	return base{reason: reason{level: level, main: main}, basis: "риск grype " + formatRisk(est.value)}
}

// noEPSSRule is rule 4: without EPSS there is no data about attacks, so grype's own
// severity is used but never above High.
func noEPSSRule(f facts) base {
	sev := grypeSeverity(f.vuln.Severity)
	b := base{basis: "EPSS нет"}
	switch strings.ToLower(f.vuln.Severity) {
	case "critical":
		b.reason = reason{level: harbor.SevHigh,
			main: "EPSS нет, взята критичность grype " + sev + ", понижена до High: без данных об атаках Critical не ставим"}
	case "high":
		b.reason = reason{level: harbor.SevHigh, main: "EPSS нет, взята критичность grype " + sev}
	case "medium":
		b.reason = reason{level: harbor.SevMedium, main: "EPSS нет, взята критичность grype " + sev}
	case "low":
		b.reason = reason{level: harbor.SevLow, main: "EPSS нет, взята критичность grype " + sev}
	case "negligible":
		b.reason = reason{level: harbor.SevLow, main: "EPSS нет, взята критичность grype " + sev + ", в Harbor это Low"}
	default:
		b.reason = reason{level: harbor.SevUnknown, main: "EPSS нет, критичность grype неизвестна"}
	}
	return b
}

// exploitRule is rule 5 and adds the facts the level did not already mention.
func exploitRule(f facts, b base) reason {
	r := b.reason
	switch {
	case !f.hasExploit() || r.level >= harbor.SevHigh:
		r.facts = append(r.facts, exploitFact(f))
	case f.network && isSerious(f.vuln.Severity):
		r = reason{level: harbor.SevHigh, main: fmt.Sprintf("%s, уязвимость доступна по сети, критичность grype %s",
			exploitFact(f), grypeSeverity(f.vuln.Severity))}
		r.facts = append(r.facts, wouldBe(b))
	case r.level < harbor.SevMedium:
		r = reason{level: harbor.SevMedium, main: exploitFact(f) + ", " + weakExploit(f)}
		r.facts = append(r.facts, wouldBe(b))
	default: // already Medium: the exploit is worth mentioning, not raising
		r.facts = append(r.facts, exploitFact(f))
	}
	r.facts = append(r.facts, "в KEV нет")
	return r
}

func wouldBe(b base) string {
	return fmt.Sprintf("без эксплойта было бы %s (%s)", b.level, b.basis)
}

// weakExploit says why an exploit raises the level only to Medium.
func weakExploit(f facts) string {
	switch {
	case f.network:
		return "но критичность grype " + grypeSeverity(f.vuln.Severity)
	case f.vectors:
		return "но уязвимость локальная"
	default:
		return "но вектор атаки неизвестен"
	}
}

func isSerious(severity string) bool {
	switch strings.ToLower(severity) {
	case "high", "critical":
		return true
	}
	return false
}

// grypeSeverity is grype's own severity as it prints it, "Unknown" when empty.
func grypeSeverity(severity string) string {
	if severity == "" {
		return "Unknown"
	}
	return severity
}

func exploitLinks(ids []string) []string {
	var links []string
	for _, id := range ids {
		if len(links) == maxExploitLinks {
			break
		}
		links = append(links, "https://www.exploit-db.com/exploits/"+id)
	}
	return links
}
