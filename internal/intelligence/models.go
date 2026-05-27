package intelligence

type FindingState string

const (
	ApplicableByVersion   FindingState = "applicable_by_version"
	ExposureConfirmed     FindingState = "exposure_confirmed"
	NoConfigEvidence      FindingState = "no_config_evidence"
	NotApplicableByConfig FindingState = "not_applicable_by_config"
	ManualReviewRequired  FindingState = "manual_review_required"
)

type Advisory struct {
	ID                string            `json:"id"`
	Title             string            `json:"title"`
	CVEs              []string          `json:"cves"`
	Severity          string            `json:"severity"`
	CVSS              string            `json:"cvss"`
	Component         string            `json:"component"`
	AttackType        string            `json:"attack_type"`
	Description       string            `json:"description"`
	Reference         string            `json:"reference"`
	Source            string            `json:"source"`
	PublishedDate     string            `json:"published_date"`
	UpdatedDate       string            `json:"updated_date"`
	AffectedProducts  []AffectedProduct `json:"affected_products"`
	IsExploited       bool              `json:"is_exploited"` // From CISA KEV
	CisaKevReference  string            `json:"cisa_kev_reference"`
	ExploitStatusText string            `json:"exploit_status_text"`
	VendorSolution    string            `json:"vendor_solution"`
	Workaround        string            `json:"workaround"`
	FixedVersions     []string          `json:"fixed_versions"`
	RecommendedAction string            `json:"recommended_action"`
	MitreID           string            `json:"mitre_id"`
	EvidenceSummary   string            `json:"evidence_summary"`
	Enrichment        ThreatEnrichment  `json:"enrichment"`
}

type AffectedProduct struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

type ThreatEnrichment struct {
	CVE                 string
	PSIRTID             string
	Title               string
	VendorSeverity      string
	CVSS                string
	EPSSScore           float64
	EPSSPercentile      float64
	MitreTechniques     []string
	TriceraPriority     string
	TTPScore            int
	IsCisaKEV           bool
	CisaKevDueDate      string
	KnownExploited      bool
	ExploitStatus       string
	ExploitMaturity     string
	HasPublicExploit    bool
	PublicExploitNote   string
	HasVendorWorkaround bool
	VendorWorkaround    string
	VendorSolution      string
	FixedVersions       []string
	RecommendedAction   string
	ImmediateAction     string
	ValidationAction    string
	LongTermAction      string
	OperationalRisk     string
	BusinessImpact      string
	EvidenceSummary     string
	Sources             []ThreatSource
	IntelSource         string
}

type ThreatSource struct {
	Name        string
	URL         string
	RetrievedAt string
	Confidence  string
}

type FortiGuardDetail struct {
	PSIRTID          string
	Summary          string
	Description      string
	AffectedProducts []AffectedProduct
	Solutions        string
	Workaround       string
	FixedVersions    []string
	CVSS             string
	CVSSVector       string
	CWE              string
	AttackType       string
	Component        string
	PublishedDate    string
	UpdatedDate      string
	References       []string
}

type AssetFingerprint struct {
	Hostname string
	Version  string
}

type CisaKevEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}
