package report

import (
	"strings"
	"tricera/internal/intelligence"
	"tricera/internal/matcher"
)

type PSIRTSummary struct {
	TotalApplicable   int
	Confirmed         int
	NoEvidence        int
	ManualReview      int
	NotApplicable     int
	Critical          int
	High              int
	Medium            int
	Low               int
	CisaKev           int
	FirmwareRisk      string 
	ExposureRisk      string 
	GlobalRisk        string 
	GlobalRiskScore   int
	FirmwareRiskScore int
	ExposureRiskScore int
	FetchError        string
	IntelStatus       string
}

func GeneratePSIRTSummary(findings []matcher.PSIRTFinding) PSIRTSummary {
	if len(findings) == 1 && findings[0].Advisory.ID == "ERROR_FETCH" {
		status := "No verificable: sin datos live ni offline"
		desc := findings[0].Advisory.Description
		if strings.Contains(desc, "No verificable") {
			status = "No verificable: sin datos live ni offline"
		} else if strings.Contains(desc, "Live no disponible") {
			status = "Live no disponible; resuelto offline"
		}
		return PSIRTSummary{
			FetchError:  desc,
			IntelStatus: status,
		}
	}

	s := PSIRTSummary{
		TotalApplicable: len(findings),
	}

	if len(findings) > 0 {
		s.IntelStatus = findings[0].Advisory.Source
	} else {
		s.IntelStatus = "Resuelto desde catálogo offline embebido"
	}

	fwScore := 0
	expScore := 0

	for _, f := range findings {
		switch f.State {
		case intelligence.ExposureConfirmed:
			s.Confirmed++
		case intelligence.NoConfigEvidence:
			s.NoEvidence++
		case intelligence.ManualReviewRequired:
			s.ManualReview++
		case intelligence.NotApplicableByConfig:
			s.NotApplicable++
		}

		weight := 0
		switch f.Advisory.Severity {
		case "Critical":
			s.Critical++
			weight = 50
		case "High":
			s.High++
			weight = 30
		case "Medium":
			s.Medium++
			weight = 15
		case "Low":
			s.Low++
			weight = 5
		}

		fwScore += weight

		if f.State == intelligence.ExposureConfirmed {
			expScore += weight * 3 
		} else if f.State == intelligence.ManualReviewRequired {
			expScore += weight
		} else if f.State == intelligence.NoConfigEvidence {
			expScore += weight / 2
		}

		if f.Advisory.IsExploited {
			s.CisaKev++
			fwScore += 100
			if f.State == intelligence.ExposureConfirmed {
				expScore += 200
			} else {
				expScore += 50
			}
		}
	}

	s.FirmwareRiskScore = fwScore
	s.ExposureRiskScore = expScore
	s.GlobalRiskScore = (fwScore * 4 / 10) + (expScore * 6 / 10)

	s.FirmwareRisk = calculateRiskLabel(fwScore, 40)
	s.ExposureRisk = calculateRiskLabel(expScore, 60)
	s.GlobalRisk = calculateRiskLabel(s.GlobalRiskScore, 50)

	// Regla de oro: Si hay CISA KEV, el riesgo no puede ser bajo
	if s.CisaKev > 0 {
		if s.GlobalRisk == "Bajo" || s.GlobalRisk == "Moderado" {
			s.GlobalRisk = "Alto"
		}
		if s.FirmwareRisk == "Bajo" || s.FirmwareRisk == "Moderado" {
			s.FirmwareRisk = "Alto"
		}
	}

	return s
}

func calculateRiskLabel(score, threshold int) string {
	if score > threshold*4 {
		return "Extremo"
	} else if score > threshold*2 {
		return "Alto"
	} else if score > threshold {
		return "Moderado"
	}
	return "Bajo"
}
