package scanner

import (
	"fmt"
	"math"
	"strings"
)

// cvss3BaseScore computes the CVSS 3.0/3.1 base score from a severity vector
// as produced by the OSV severity[].score field. The vector form and the
// roundup rule follow the FIRST CVSS v3.x specification.
func cvss3BaseScore(vector string) (float64, error) {
	metrics, roundup, err := parseCVSS3Vector(vector)
	if err != nil {
		return 0, err
	}

	impactSub := 1 - (1-metricValue(metrics, "C", impactMetrics))*(1-metricValue(metrics, "I", impactMetrics))*(1-metricValue(metrics, "A", impactMetrics))
	var impact float64
	if metrics["S"] == "U" {
		impact = 6.42 * impactSub
	} else {
		impact = 7.52*(impactSub-0.029) - 3.25*math.Pow(impactSub-0.02, 15)
	}
	exploitability := 8.22 * metricValue(metrics, "AV", attackVectorMetrics) * metricValue(metrics, "AC", attackComplexityMetrics) * metricValue(metrics, "PR", privilegesRequiredMetrics(metrics["S"])) * metricValue(metrics, "UI", userInteractionMetrics)

	if impact <= 0 {
		return 0, nil
	}
	if metrics["S"] == "U" {
		return roundup(math.Min(impact+exploitability, 10)), nil
	}
	return roundup(math.Min(1.08*(impact+exploitability), 10)), nil
}

// parseCVSS3Vector validates and splits a CVSS 3.0/3.1 vector into its metric
// map and selects the matching roundup rule.
func parseCVSS3Vector(vector string) (map[string]string, func(float64) float64, error) {
	segments := strings.Split(vector, "/")
	if len(segments) != 9 {
		return nil, nil, fmt.Errorf("cvss3 vector %q must carry the prefix and 8 metrics", vector)
	}
	var roundup func(float64) float64
	switch segments[0] {
	case "CVSS:3.0":
		roundup = roundup30
	case "CVSS:3.1":
		roundup = roundup31
	default:
		return nil, nil, fmt.Errorf("cvss3 vector %q carries an unsupported version", vector)
	}

	metrics := make(map[string]string, 8)
	for _, segment := range segments[1:] {
		key, value, found := strings.Cut(segment, ":")
		if !found {
			return nil, nil, fmt.Errorf("cvss3 metric %q misses a value", segment)
		}
		if !knownCVSS3Metric(key) {
			return nil, nil, fmt.Errorf("cvss3 metric %q is not a base metric", key)
		}
		if _, duplicate := metrics[key]; duplicate {
			return nil, nil, fmt.Errorf("cvss3 metric %q appears twice", key)
		}
		metrics[key] = value
	}
	if err := validateCVSS3Values(metrics); err != nil {
		return nil, nil, err
	}
	return metrics, roundup, nil
}

func knownCVSS3Metric(key string) bool {
	switch key {
	case "AV", "AC", "PR", "UI", "S", "C", "I", "A":
		return true
	default:
		return false
	}
}

// validateCVSS3Values rejects unknown metric values before scoring.
func validateCVSS3Values(metrics map[string]string) error {
	allowed := map[string][]string{
		"AV": {"N", "A", "L", "P"},
		"AC": {"L", "H"},
		"PR": {"N", "L", "H"},
		"UI": {"N", "R"},
		"S":  {"U", "C"},
		"C":  {"N", "L", "H"},
		"I":  {"N", "L", "H"},
		"A":  {"N", "L", "H"},
	}
	for key, values := range allowed {
		if !contains(values, metrics[key]) {
			return fmt.Errorf("cvss3 metric %q carries unsupported value %q", key, metrics[key])
		}
	}
	return nil
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

var attackVectorMetrics = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}

var attackComplexityMetrics = map[string]float64{"L": 0.77, "H": 0.44}

var userInteractionMetrics = map[string]float64{"N": 0.85, "R": 0.62}

var impactMetrics = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

// privilegesRequiredMetrics depends on the scope metric.
func privilegesRequiredMetrics(scope string) map[string]float64 {
	if scope == "U" {
		return map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	}
	return map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
}

func metricValue(metrics map[string]string, key string, values map[string]float64) float64 {
	return values[metrics[key]]
}

// roundup30 is the CVSS 3.0 roundup rule: plain ceiling to one decimal.
func roundup30(value float64) float64 {
	return math.Ceil(value*10) / 10
}

// roundup31 is the CVSS 3.1 roundup rule: integer-arithmetic ceiling that
// keeps exact tenths stable.
func roundup31(value float64) float64 {
	scaled := math.Round(value * 100000)
	if math.Mod(scaled, 10000) == 0 {
		return scaled / 100000
	}
	return (math.Floor(scaled/10000) + 1) / 10
}
