package main

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ============================================================================
// Styles
// ============================================================================

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000"))

	highlightStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true)
)

var downloadClient = &http.Client{Timeout: 60 * time.Second}

// ============================================================================
// API Types
// ============================================================================

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type PageInfo struct {
	EndCursor       string `json:"endCursor"`
	HasNextPage     bool   `json:"hasNextPage"`
	HasPreviousPage bool   `json:"hasPreviousPage"`
	StartCursor     string `json:"startCursor"`
}

type AuditResults struct {
	Data     []Audit  `json:"data"`
	PageInfo PageInfo `json:"pageInfo"`
}

type AuditResponse struct {
	Results AuditResults `json:"results"`
}

type Audit struct {
	ID                       string  `json:"id"`
	CustomerDisplayName      *string `json:"customerDisplayName"`
	CustomerOrganizationName string  `json:"customerOrganizationName"`
	Framework                string  `json:"framework"`
	AuditStartDate           string  `json:"auditStartDate"`
	AuditEndDate             string  `json:"auditEndDate"`
	CreationDate             string  `json:"creationDate"`
	AuditFocus               string  `json:"auditFocus"`
}

func (a Audit) Title() string {
	name := a.CustomerOrganizationName
	if a.CustomerDisplayName != nil && *a.CustomerDisplayName != "" {
		name = *a.CustomerDisplayName
	}
	return fmt.Sprintf("%s - %s", name, a.Framework)
}

func (a Audit) Description() string {
	return fmt.Sprintf("Audit Period: %s to %s", formatDate(a.AuditStartDate), formatDate(a.AuditEndDate))
}

func (a Audit) FilterValue() string {
	return a.Title()
}

type RelatedControl struct {
	Name         string   `json:"name"`
	SectionNames []string `json:"sectionNames"`
}

type Evidence struct {
	ID                string           `json:"id"`
	EvidenceID        string           `json:"evidenceId"`
	Name              string           `json:"name"`
	Status            string           `json:"status"`
	Description       *string          `json:"description"`
	EvidenceType      string           `json:"evidenceType"`
	TestStatus        *string          `json:"testStatus"`
	RelatedControls   []RelatedControl `json:"relatedControls"`
	CreationDate      string           `json:"creationDate"`
	StatusUpdatedDate string           `json:"statusUpdatedDate"`
}

type EvidenceResults struct {
	Data     []Evidence `json:"data"`
	PageInfo PageInfo   `json:"pageInfo"`
}

type EvidenceResponse struct {
	Results EvidenceResults `json:"results"`
}

type EvidenceURL struct {
	ID             string `json:"id"`
	URL            string `json:"url"`
	Filename       string `json:"filename"`
	IsDownloadable bool   `json:"isDownloadable"`
}

type EvidenceURLResults struct {
	Data     []EvidenceURL `json:"data"`
	PageInfo PageInfo      `json:"pageInfo"`
}

type EvidenceURLResponse struct {
	Results EvidenceURLResults `json:"results"`
}

// ============================================================================
// Metadata Types
// ============================================================================

type AuditInfo struct {
	ID                  string `json:"id"`
	CustomerName        string `json:"customer_name"`
	OrganizationName    string `json:"organization_name"`
	Framework           string `json:"framework"`
	AuditStartDate      string `json:"audit_start_date"`
	AuditEndDate        string `json:"audit_end_date"`
	ExportDate          string `json:"export_date"`
	TotalEvidenceItems  int    `json:"total_evidence_items"`
	TotalFilesExported  int    `json:"total_files_exported"`
	TotalControlFolders int    `json:"total_control_folders"`
}

type EvidenceMetadata struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Type              string   `json:"type"`
	Status            string   `json:"status"`
	Description       string   `json:"description"`
	TestStatus        string   `json:"test_status,omitempty"`
	Files             []string `json:"files"`
	CreationDate      string   `json:"creation_date"`
	StatusUpdatedDate string   `json:"status_updated_date"`
}

type ControlMetadata struct {
	ControlName   string             `json:"control_name"`
	EvidenceItems []EvidenceMetadata `json:"evidence_items"`
}

// ============================================================================
// API Client
// ============================================================================

type VantaClient struct {
	clientID     string
	clientSecret string
	accessToken  string
	tokenExpiry  time.Time
	httpClient   *http.Client
}

func NewVantaClient(clientID, clientSecret string) *VantaClient {
	return &VantaClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *VantaClient) authenticate() error {
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	data := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     c.clientID,
		"client_secret": c.clientSecret,
		"scope":         "auditor-api.audit:read auditor-api.auditor:read",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(
		"https://api.vanta.com/oauth/token",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-300) * time.Second)

	return nil
}

func (c *VantaClient) doRequest(method, endpoint string, params url.Values) ([]byte, error) {
	if err := c.authenticate(); err != nil {
		return nil, err
	}

	reqURL := "https://api.vanta.com/v1" + endpoint
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil // Return nil for 404s
		}
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (c *VantaClient) GetAudits() ([]Audit, error) {
	var allAudits []Audit
	var cursor string

	for {
		params := url.Values{"pageSize": {"100"}}
		if cursor != "" {
			params.Set("pageCursor", cursor)
		}

		body, err := c.doRequest("GET", "/audits", params)
		if err != nil {
			return nil, err
		}

		var resp AuditResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		allAudits = append(allAudits, resp.Results.Data...)

		if !resp.Results.PageInfo.HasNextPage {
			break
		}
		cursor = resp.Results.PageInfo.EndCursor
	}

	return allAudits, nil
}

func (c *VantaClient) GetEvidence(auditID string) ([]Evidence, error) {
	var allEvidence []Evidence
	var cursor string

	for {
		params := url.Values{"pageSize": {"100"}}
		if cursor != "" {
			params.Set("pageCursor", cursor)
		}

		body, err := c.doRequest("GET", fmt.Sprintf("/audits/%s/evidence", auditID), params)
		if err != nil {
			return nil, err
		}

		var resp EvidenceResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}

		allEvidence = append(allEvidence, resp.Results.Data...)

		if !resp.Results.PageInfo.HasNextPage {
			break
		}
		cursor = resp.Results.PageInfo.EndCursor
	}

	return allEvidence, nil
}

func (c *VantaClient) GetEvidenceURLs(auditID, evidenceID string) ([]EvidenceURL, error) {
	params := url.Values{"pageSize": {"100"}}

	body, err := c.doRequest("GET", fmt.Sprintf("/audits/%s/evidence/%s/urls", auditID, evidenceID), params)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return []EvidenceURL{}, nil // 404 = no URLs
	}

	var resp EvidenceURLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return resp.Results.Data, nil
}

// ============================================================================
// TUI Messages
// ============================================================================

type authSuccessMsg struct{}
type authErrorMsg struct{ err error }
type auditsLoadedMsg struct{ audits []Audit }
type auditsErrorMsg struct{ err error }
type exportStartMsg struct{ audit Audit }

type progressMsg struct {
	phase    string // "evidence", "urls", "download"
	current  int
	total    int
	detail   string
}

type downloadCompleteMsg struct {
	totalFiles int
	totalSize  int64
	errors     []string
	outputDir  string
}
type tickMsg time.Time

// ============================================================================
// TUI Model
// ============================================================================

type viewState int

const (
	viewCredentials viewState = iota
	viewAuth
	viewAuditList
	viewExporting
	viewComplete
)

type model struct {
	// State
	view       viewState
	client     *VantaClient
	audits     []Audit
	selectedAudit *Audit
	outputDir  string
	err        error

	// Credentials input
	clientIDInput     textinput.Model
	clientSecretInput textinput.Model
	focusedInput      int // 0 = clientID, 1 = clientSecret

	// Export progress
	progressPhase   string
	progressCurrent int
	progressTotal   int
	progressDetail  string
	exportErrors    []string
	totalFilesExported int
	totalSizeExported  int64
	exportOutputDir string

	// Components
	spinner  spinner.Model
	list     list.Model
	progress progress.Model

	// Dimensions
	width  int
	height int
}

func initialModel(client *VantaClient, outputDir string, needCredentials bool) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))

	p := progress.New(progress.WithDefaultGradient())

	// Set up text inputs for credentials
	clientIDInput := textinput.New()
	clientIDInput.Placeholder = "vci_xxxxxxxxxxxxxxxx"
	clientIDInput.CharLimit = 100
	clientIDInput.Width = 60
	clientIDInput.Prompt = "  "

	clientSecretInput := textinput.New()
	clientSecretInput.Placeholder = "vcs_xxxxxx_xxxxxxxxxxxxxxxx"
	clientSecretInput.CharLimit = 100
	clientSecretInput.Width = 60
	clientSecretInput.EchoMode = textinput.EchoPassword
	clientSecretInput.EchoCharacter = '*'
	clientSecretInput.Prompt = "  "

	// Pre-fill from env if available
	if envID := os.Getenv("VANTA_CLIENT_ID"); envID != "" {
		clientIDInput.SetValue(envID)
	}
	if envSecret := os.Getenv("VANTA_CLIENT_SECRET"); envSecret != "" {
		clientSecretInput.SetValue(envSecret)
	}

	initialView := viewCredentials
	if !needCredentials {
		initialView = viewAuth
	} else {
		clientIDInput.Focus()
	}

	return model{
		view:              initialView,
		client:            client,
		outputDir:         outputDir,
		spinner:           s,
		progress:          p,
		clientIDInput:     clientIDInput,
		clientSecretInput: clientSecretInput,
		focusedInput:      0,
		width:             80,
		height:            24,
	}
}

func (m model) Init() tea.Cmd {
	if m.view == viewCredentials {
		return textinput.Blink
	}
	return tea.Batch(
		m.spinner.Tick,
		authenticateCmd(m.client),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle credentials view
		if m.view == viewCredentials {
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "tab", "down":
				// Move to next input
				if m.focusedInput == 0 {
					m.focusedInput = 1
					m.clientIDInput.Blur()
					m.clientSecretInput.Focus()
				} else {
					m.focusedInput = 0
					m.clientSecretInput.Blur()
					m.clientIDInput.Focus()
				}
				return m, nil
			case "shift+tab", "up":
				// Move to previous input
				if m.focusedInput == 1 {
					m.focusedInput = 0
					m.clientSecretInput.Blur()
					m.clientIDInput.Focus()
				} else {
					m.focusedInput = 1
					m.clientIDInput.Blur()
					m.clientSecretInput.Focus()
				}
				return m, nil
			case "enter":
				clientID := m.clientIDInput.Value()
				clientSecret := m.clientSecretInput.Value()
				if clientID != "" && clientSecret != "" {
					m.client = NewVantaClient(clientID, clientSecret)
					m.view = viewAuth
					return m, tea.Batch(
						m.spinner.Tick,
						authenticateCmd(m.client),
					)
				}
				return m, nil
			}

			// Update the focused text input
			var cmd tea.Cmd
			if m.focusedInput == 0 {
				m.clientIDInput, cmd = m.clientIDInput.Update(msg)
			} else {
				m.clientSecretInput, cmd = m.clientSecretInput.Update(msg)
			}
			return m, cmd
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "enter":
			if m.view == viewAuditList {
				if i, ok := m.list.SelectedItem().(Audit); ok {
					m.selectedAudit = &i
					m.view = viewExporting
					return m, tea.Batch(
						m.spinner.Tick,
						exportAuditCmd(m.client, i, m.outputDir),
					)
				}
			}
			if m.view == viewComplete {
				return m, tea.Quit
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.list.Width() > 0 {
			m.list.SetSize(msg.Width-4, msg.Height-10)
		}
		m.progress.Width = msg.Width - 20

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case authSuccessMsg:
		m.view = viewAuditList
		return m, loadAuditsCmd(m.client)

	case authErrorMsg:
		m.err = msg.err
		return m, tea.Quit

	case auditsLoadedMsg:
		m.audits = msg.audits
		items := make([]list.Item, len(msg.audits))
		for i, a := range msg.audits {
			items[i] = a
		}
		delegate := list.NewDefaultDelegate()
		m.list = list.New(items, delegate, m.width-4, m.height-10)
		m.list.Title = "Select an Audit to Export"
		m.list.SetShowStatusBar(true)
		m.list.SetFilteringEnabled(true)
		return m, nil

	case auditsErrorMsg:
		m.err = msg.err
		return m, tea.Quit

	case progressMsg:
		m.progressPhase = msg.phase
		m.progressCurrent = msg.current
		m.progressTotal = msg.total
		m.progressDetail = msg.detail
		return m, nil

	case downloadCompleteMsg:
		m.view = viewComplete
		m.totalFilesExported = msg.totalFiles
		m.totalSizeExported = msg.totalSize
		m.exportErrors = msg.errors
		m.exportOutputDir = msg.outputDir
		return m, nil
	}

	// Update list
	if m.view == viewAuditList {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	var s strings.Builder

	s.WriteString("\n")
	s.WriteString(titleStyle.Render(" Vanta Evidence Exporter "))
	s.WriteString("\n\n")

	switch m.view {
	case viewCredentials:
		s.WriteString("Enter your Vanta API credentials:\n\n")

		// Client ID input
		clientIDLabel := "  Client ID:     "
		if m.focusedInput == 0 {
			clientIDLabel = highlightStyle.Render("> Client ID:     ")
		}
		s.WriteString(clientIDLabel)
		s.WriteString(m.clientIDInput.View())
		s.WriteString("\n\n")

		// Client Secret input
		clientSecretLabel := "  Client Secret: "
		if m.focusedInput == 1 {
			clientSecretLabel = highlightStyle.Render("> Client Secret: ")
		}
		s.WriteString(clientSecretLabel)
		s.WriteString(m.clientSecretInput.View())
		s.WriteString("\n\n")

		s.WriteString(infoStyle.Render("  Tab/Arrow keys to switch fields, Enter to submit\n"))
		s.WriteString(infoStyle.Render("  Credentials from VANTA_CLIENT_ID/SECRET env vars are pre-filled if set"))

	case viewAuth:
		s.WriteString(m.spinner.View())
		s.WriteString(" Authenticating with Vanta...")

	case viewAuditList:
		s.WriteString(m.list.View())

	case viewExporting:
		if m.selectedAudit != nil {
			s.WriteString(highlightStyle.Render("Exporting: "))
			s.WriteString(m.selectedAudit.Title())
			s.WriteString("\n\n")
		}

		s.WriteString(m.spinner.View())
		s.WriteString(" ")

		if m.progressTotal > 0 {
			percent := float64(m.progressCurrent) / float64(m.progressTotal)

			// Phase label
			phaseLabel := "Working"
			switch m.progressPhase {
			case "evidence":
				phaseLabel = "Fetching evidence"
			case "urls":
				phaseLabel = "Getting file URLs"
			case "download":
				phaseLabel = "Downloading files"
			case "zip":
				phaseLabel = "Creating zip archive"
			}

			s.WriteString(fmt.Sprintf("%s: %d/%d\n", phaseLabel, m.progressCurrent, m.progressTotal))
			s.WriteString(m.progress.ViewAs(percent))
			s.WriteString("\n")
			if m.progressDetail != "" {
				s.WriteString(infoStyle.Render(m.progressDetail))
			}
		} else {
			s.WriteString("Starting export...")
		}

	case viewComplete:
		s.WriteString(successStyle.Render("Export Complete!"))
		s.WriteString("\n\n")

		s.WriteString(fmt.Sprintf("  Files exported: %d\n", m.totalFilesExported))
		s.WriteString(fmt.Sprintf("  Total size: %s\n", formatBytes(m.totalSizeExported)))
		s.WriteString(fmt.Sprintf("  Output: %s\n", m.exportOutputDir))

		if len(m.exportErrors) > 0 {
			s.WriteString("\n")
			s.WriteString(errorStyle.Render(fmt.Sprintf("  Errors: %d (see _errors.log)", len(m.exportErrors))))
		}

		s.WriteString("\n\n")
		s.WriteString(infoStyle.Render("Press Enter or q to exit"))
	}

	if m.err != nil {
		s.WriteString("\n\n")
		s.WriteString(errorStyle.Render(fmt.Sprintf("Error: %v", m.err)))
	}

	return s.String()
}

// ============================================================================
// Commands
// ============================================================================

var program *tea.Program

func authenticateCmd(client *VantaClient) tea.Cmd {
	return func() tea.Msg {
		if err := client.authenticate(); err != nil {
			return authErrorMsg{err: err}
		}
		return authSuccessMsg{}
	}
}

func loadAuditsCmd(client *VantaClient) tea.Cmd {
	return func() tea.Msg {
		audits, err := client.GetAudits()
		if err != nil {
			return auditsErrorMsg{err: err}
		}
		return auditsLoadedMsg{audits: audits}
	}
}

func sendProgress(phase string, current, total int, detail string) {
	if program != nil {
		program.Send(progressMsg{
			phase:   phase,
			current: current,
			total:   total,
			detail:  detail,
		})
	}
}

func exportAuditCmd(client *VantaClient, audit Audit, baseOutputDir string) tea.Cmd {
	return func() tea.Msg {
		// Create output directory
		customerName := audit.CustomerOrganizationName
		if audit.CustomerDisplayName != nil && *audit.CustomerDisplayName != "" {
			customerName = *audit.CustomerDisplayName
		}
		dirName := sanitizeFilename(fmt.Sprintf("%s_%s_%s", customerName, audit.Framework, audit.ID[:8]))
		outputDir := filepath.Join(baseOutputDir, dirName)

		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return downloadCompleteMsg{errors: []string{err.Error()}, outputDir: outputDir}
		}

		// Fetch all evidence
		sendProgress("evidence", 0, 1, "Fetching evidence list...")
		evidence, err := client.GetEvidence(audit.ID)
		if err != nil {
			return downloadCompleteMsg{errors: []string{err.Error()}, outputDir: outputDir}
		}
		sendProgress("evidence", 1, 1, fmt.Sprintf("Found %d evidence items", len(evidence)))

		// Build control-to-evidence map
		controlMap := make(map[string][]Evidence)
		for _, e := range evidence {
			if len(e.RelatedControls) == 0 {
				controlMap["_Unassigned"] = append(controlMap["_Unassigned"], e)
			} else {
				for _, ctrl := range e.RelatedControls {
					controlMap[ctrl.Name] = append(controlMap[ctrl.Name], e)
				}
			}
		}

		// Collect all downloadable URLs first
		type downloadItem struct {
			url         EvidenceURL
			evidence    Evidence
			controlDir  string
			controlName string
		}
		var downloads []downloadItem
		var errors []string
		var indexRows [][]string
		indexRows = append(indexRows, []string{
			"evidence_id", "name", "type", "status", "test_status",
			"control_names", "file_count", "created_date", "status_updated_date",
		})

		// Phase 2: Get URLs for each evidence item
		processedEvidence := make(map[string][]EvidenceURL) // cache URLs by evidence ID
		urlsProcessed := 0
		for controlName, evidenceList := range controlMap {
			controlDir := filepath.Join(outputDir, sanitizeFilename(controlName))
			if err := os.MkdirAll(controlDir, 0755); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to create control dir %s: %v", controlName, err))
				continue
			}

			for _, e := range evidenceList {
				// Only fetch URLs once per evidence ID
				urls, cached := processedEvidence[e.ID]
				if !cached {
					urlsProcessed++
					sendProgress("urls", urlsProcessed, len(evidence), e.Name)

					var err error
					urls, err = client.GetEvidenceURLs(audit.ID, e.ID)
					if err != nil {
						errors = append(errors, fmt.Sprintf("Failed to get URLs for %s: %v", e.Name, err))
						continue
					}
					processedEvidence[e.ID] = urls
				}

				for _, u := range urls {
					if u.IsDownloadable {
						downloads = append(downloads, downloadItem{
							url:         u,
							evidence:    e,
							controlDir:  controlDir,
							controlName: controlName,
						})
					}
				}

				// Build index row
				desc := ""
				if e.Description != nil {
					desc = *e.Description
				}
				_ = desc // used for metadata
				testStatus := ""
				if e.TestStatus != nil {
					testStatus = *e.TestStatus
				}

				controlNames := make([]string, len(e.RelatedControls))
				for i, c := range e.RelatedControls {
					controlNames[i] = c.Name
				}
				indexRows = append(indexRows, []string{
					e.ID, e.Name, e.EvidenceType, e.Status, testStatus,
					strings.Join(controlNames, "; "), fmt.Sprintf("%d", len(urls)),
					formatDate(e.CreationDate), formatDate(e.StatusUpdatedDate),
				})
			}
		}

		// Phase 3: Download files
		var totalFiles int
		var totalSize int64
		downloadSem := make(chan struct{}, 5)
		var wg sync.WaitGroup
		var mu sync.Mutex
		downloaded := 0

		for _, d := range downloads {
			wg.Add(1)
			go func(d downloadItem) {
				defer wg.Done()
				downloadSem <- struct{}{}
				defer func() { <-downloadSem }()

				filename := sanitizeFilename(d.url.Filename)
				if filename == "" {
					filename = fmt.Sprintf("file_%s", d.url.ID[:8])
				}
				filePath := filepath.Join(d.controlDir, filename)
				filePath = getUniqueFilename(filePath)

				size, err := downloadFile(d.url.URL, filePath, outputDir)
				mu.Lock()
				downloaded++
				sendProgress("download", downloaded, len(downloads), filename)
				if err != nil {
					errors = append(errors, fmt.Sprintf("Failed to download %s: %v", filename, err))
				} else {
					totalFiles++
					totalSize += size
				}
				mu.Unlock()
			}(d)
		}
		wg.Wait()

		// Build and write metadata for each control
		for controlName, evidenceList := range controlMap {
			controlDir := filepath.Join(outputDir, sanitizeFilename(controlName))
			var controlMetadata ControlMetadata
			controlMetadata.ControlName = controlName

			for _, e := range evidenceList {
				desc := ""
				if e.Description != nil {
					desc = *e.Description
				}
				testStatus := ""
				if e.TestStatus != nil {
					testStatus = *e.TestStatus
				}
				controlMetadata.EvidenceItems = append(controlMetadata.EvidenceItems, EvidenceMetadata{
					ID:                e.ID,
					Name:              e.Name,
					Type:              e.EvidenceType,
					Status:            e.Status,
					Description:       desc,
					TestStatus:        testStatus,
					CreationDate:      e.CreationDate,
					StatusUpdatedDate: e.StatusUpdatedDate,
				})
			}

			metadataPath := filepath.Join(controlDir, "metadata.json")
			metadataJSON, err := json.MarshalIndent(controlMetadata, "", "  ")
			if err != nil {
				errors = append(errors, fmt.Sprintf("Failed to marshal metadata for %s: %v", controlName, err))
				continue
			}
			if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to write metadata for %s: %v", controlName, err))
			}
		}

		// Write master index CSV
		indexPath := filepath.Join(outputDir, "_index.csv")
		indexFile, err := os.Create(indexPath)
		if err == nil {
			writer := csv.NewWriter(indexFile)
			writer.WriteAll(indexRows)
			indexFile.Close()
		}

		// Write audit info
		auditInfo := AuditInfo{
			ID:                  audit.ID,
			CustomerName:        customerName,
			OrganizationName:    audit.CustomerOrganizationName,
			Framework:           audit.Framework,
			AuditStartDate:      audit.AuditStartDate,
			AuditEndDate:        audit.AuditEndDate,
			ExportDate:          time.Now().Format(time.RFC3339),
			TotalEvidenceItems:  len(evidence),
			TotalFilesExported:  totalFiles,
			TotalControlFolders: len(controlMap),
		}
		auditInfoJSON, err := json.MarshalIndent(auditInfo, "", "  ")
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to marshal audit info: %v", err))
		} else if err := os.WriteFile(filepath.Join(outputDir, "_audit_info.json"), auditInfoJSON, 0644); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to write audit info: %v", err))
		}

		// Write errors log if any
		if len(errors) > 0 {
			errLog := strings.Join(errors, "\n")
			_ = os.WriteFile(filepath.Join(outputDir, "_errors.log"), []byte(errLog), 0644) // #nosec G104 - best effort
		}

		// Create zip archive
		sendProgress("zip", 0, 1, "Creating zip archive...")
		zipPath := outputDir + ".zip"
		if err := zipDirectory(outputDir, zipPath); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to create zip: %v", err))
		}
		sendProgress("zip", 1, 1, "Zip complete")

		return downloadCompleteMsg{
			totalFiles: totalFiles,
			totalSize:  totalSize,
			errors:     errors,
			outputDir:  outputDir,
		}
	}
}

// ============================================================================
// Helpers
// ============================================================================

func downloadFile(rawURL, destPath, baseDir string) (int64, error) {
	// Validate URL to prevent SSRF attacks
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return 0, fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTPS URLs for security
	if parsedURL.Scheme != "https" {
		return 0, fmt.Errorf("only HTTPS URLs are allowed, got: %s", parsedURL.Scheme)
	}

	// Resolve absolute paths for proper comparison
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve base directory: %w", err)
	}
	absDest, err := filepath.Abs(destPath)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve destination path: %w", err)
	}

	// Verify the destination is within the base directory (path traversal protection)
	relPath, err := filepath.Rel(absBase, absDest)
	if err != nil || strings.HasPrefix(relPath, "..") || filepath.IsAbs(relPath) {
		return 0, fmt.Errorf("invalid file path: path traversal detected")
	}

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := downloadClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(absDest)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	return io.Copy(out, resp.Body)
}

func sanitizeFilename(name string) string {
	// Extract just the filename component (removes any path elements)
	name = filepath.Base(name)

	// Remove or replace invalid characters for filenames
	reg := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	name = reg.ReplaceAllString(name, "_")

	// Trim spaces and dots from ends
	name = strings.Trim(name, " .")

	// Limit length
	if len(name) > 200 {
		name = name[:200]
	}

	// Ensure we have a valid filename
	if name == "" || name == "." || name == ".." {
		name = "unnamed"
	}

	return name
}

func getUniqueFilename(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}

	dir := filepath.Dir(path)
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(filepath.Base(path), ext)

	for i := 1; ; i++ {
		newPath := filepath.Join(dir, fmt.Sprintf("%s_%d%s", base, i, ext))
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
	}
}

func formatDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}
	return t.Format("2006-01-02")
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func zipDirectory(sourceDir, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	baseDir := filepath.Base(sourceDir)

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		header.Name = filepath.Join(baseDir, relPath)

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

// ============================================================================
// Main
// ============================================================================

func main() {
	var (
		auditID      = flag.String("audit-id", "", "Export a specific audit by ID")
		all          = flag.Bool("all", false, "Export all audits")
		output       = flag.String("output", "./export", "Output directory")
		noTUI        = flag.Bool("no-tui", false, "Run without interactive TUI")
		clientIDFlag = flag.String("client-id", "", "Vanta Client ID (or use VANTA_CLIENT_ID env var)")
		secretFlag   = flag.String("client-secret", "", "Vanta Client Secret (or use VANTA_CLIENT_SECRET env var)")
	)
	flag.Parse()

	// Get credentials from flags or environment
	clientID := *clientIDFlag
	if clientID == "" {
		clientID = os.Getenv("VANTA_CLIENT_ID")
	}
	clientSecret := *secretFlag
	if clientSecret == "" {
		clientSecret = os.Getenv("VANTA_CLIENT_SECRET")
	}

	// Non-interactive mode requires credentials
	if *noTUI || *auditID != "" || *all {
		if clientID == "" || clientSecret == "" {
			fmt.Println(errorStyle.Render("Error: Credentials required for non-interactive mode"))
			fmt.Println("\nProvide via flags or environment variables:")
			fmt.Println("  --client-id=vci_xxx --client-secret=vcs_xxx")
			fmt.Println("  OR")
			fmt.Println("  export VANTA_CLIENT_ID=vci_xxx")
			fmt.Println("  export VANTA_CLIENT_SECRET=vcs_xxx")
			os.Exit(1)
		}

		client := NewVantaClient(clientID, clientSecret)
		if err := client.authenticate(); err != nil {
			fmt.Printf("Authentication failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(successStyle.Render("Authenticated successfully"))

		audits, err := client.GetAudits()
		if err != nil {
			fmt.Printf("Failed to fetch audits: %v\n", err)
			os.Exit(1)
		}

		var toExport []Audit
		if *all {
			toExport = audits
		} else if *auditID != "" {
			for _, a := range audits {
				if a.ID == *auditID {
					toExport = append(toExport, a)
					break
				}
			}
			if len(toExport) == 0 {
				fmt.Printf("Audit with ID %s not found\n", *auditID)
				os.Exit(1)
			}
		}

		for _, audit := range toExport {
			fmt.Printf("\nExporting: %s - %s\n", audit.CustomerOrganizationName, audit.Framework)
			msg := exportAuditCmd(client, audit, *output)()
			if result, ok := msg.(downloadCompleteMsg); ok {
				fmt.Printf("  Files: %d, Size: %s\n", result.totalFiles, formatBytes(result.totalSize))
				if len(result.errors) > 0 {
					fmt.Printf("  Errors: %d\n", len(result.errors))
				}
			}
		}
		return
	}

	// Interactive TUI mode - credentials can be entered interactively
	var client *VantaClient
	needCredentials := true
	if clientID != "" && clientSecret != "" {
		client = NewVantaClient(clientID, clientSecret)
		needCredentials = false
	}

	program = tea.NewProgram(initialModel(client, *output, needCredentials), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(1)
	}
}
