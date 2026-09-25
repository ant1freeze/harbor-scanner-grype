package policy

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

func TestReasonString(t *testing.T) {
	r := reason{level: harbor.SevHigh, main: "риск grype 69.0, порог High от 30", facts: []string{"эксплойтов не найдено", "в KEV нет"}}
	assert.Equal(t, "High: риск grype 69.0, порог High от 30; эксплойтов не найдено; в KEV нет.", r.String())

	malware := reason{level: harbor.SevCritical, main: "встроенный вредоносный код (CWE-506)"}
	assert.Equal(t, "Critical: встроенный вредоносный код (CWE-506).", malware.String())
}

func TestFormatPercent(t *testing.T) {
	assert.Equal(t, "92%", formatPercent(0.92))
	assert.Equal(t, "52.4%", formatPercent(0.524))
	assert.Equal(t, "5.1%", formatPercent(0.051))
	assert.Equal(t, "<0.1%", formatPercent(0.0003))
	assert.Equal(t, "0%", formatPercent(0))
}

func TestFormatRisk(t *testing.T) {
	assert.Equal(t, "69.0", formatRisk(69.0))
	assert.Equal(t, "2.9", formatRisk(2.88))
	assert.Equal(t, "<0.1", formatRisk(0.03))
	assert.Equal(t, "0.0", formatRisk(0))
}

func TestFormatThreshold(t *testing.T) {
	assert.Equal(t, "70", formatThreshold(70))
	assert.Equal(t, "12.5", formatThreshold(12.5))
}

func TestExploitFact(t *testing.T) {
	assert.Equal(t, "есть эксплойт в Exploit-DB (52134)",
		exploitFact(facts{exploits: []string{"52134"}, poc: "https://github.com/x/cve-2025-1"}), "Exploit-DB comes first")
	assert.Equal(t, "есть эксплойт в Exploit-DB (1, 2, 3 и ещё 2)", exploitFact(facts{exploits: []string{"1", "2", "3", "4", "5"}}))
	assert.Equal(t, "есть PoC (github.com/guiimoraes/CVE-2025-15467)", exploitFact(facts{poc: "https://github.com/guiimoraes/CVE-2025-15467"}))
	assert.Equal(t, "эксплойтов не найдено", exploitFact(facts{}))
}

func TestShortURL(t *testing.T) {
	assert.Equal(t, "exploit-db.com/exploits/52134", shortURL("https://www.exploit-db.com/exploits/52134"))
	long := shortURL("https://github.com/someone/" + strings.Repeat("a", 100))
	assert.Len(t, long, 80)
	assert.True(t, strings.HasSuffix(long, "..."))
}

func TestShortURLKeepsValidUTF8(t *testing.T) {
	long := shortURL("https://example.com/" + strings.Repeat("я", 100))
	assert.True(t, utf8.ValidString(long))
	assert.Equal(t, 80, utf8.RuneCountInString(long))
	assert.True(t, strings.HasSuffix(long, "..."))
}
