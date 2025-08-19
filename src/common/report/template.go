package report

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>codesucks-ai Security Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/themes/prism.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/plugins/line-numbers/prism-line-numbers.min.css">
    <style>
        :root {
            --primary-blue: #2563eb;
            --primary-purple: #7c3aed;
            --light-bg: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --secondary-text: #64748b;
            --border-color: #e2e8f0;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --error-color: #ef4444;
            --critical-color: #dc2626;
            --secret-verified: #059669;
            --secret-unverified: #d97706;
            --secret-color: #8b5cf6;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            background: var(--light-bg);
            color: var(--text-color);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: var(--card-bg);
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            border-left: 4px solid var(--primary-blue);
        }

        .header h1 {
            color: var(--primary-blue);
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }

        .header .target {
            color: var(--secondary-text);
            font-size: 1.1em;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
            background: var(--light-bg);
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            margin-top: 10px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border-left: 4px solid var(--primary-purple);
        }

        .stat-card h3 {
            color: var(--primary-purple);
            font-size: 1.2em;
            margin-bottom: 15px;
            font-weight: 600;
        }

        .stat-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }

        .stat-item:last-child {
            border-bottom: none;
        }

        .stat-label {
            color: var(--text-color);
            font-weight: 500;
        }

        .stat-value {
            background: var(--light-bg);
            padding: 4px 12px;
            border-radius: 20px;
            color: var(--primary-blue);
            font-weight: 600;
            font-size: 0.9em;
        }

        .severity-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-critical { background: var(--critical-color); color: white; }
        .severity-high { background: var(--error-color); color: white; }
        .severity-medium { background: var(--warning-color); color: white; }
        .severity-low { background: var(--success-color); color: white; }
        .severity-info { background: var(--secondary-text); color: white; }

        .vulnerability-card {
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            margin-bottom: 25px;
            overflow: hidden;
            border-left: 4px solid var(--error-color);
        }

        .vulnerability-card.severity-high {
            border-left-color: var(--error-color);
        }

        .vulnerability-card.severity-medium {
            border-left-color: var(--warning-color);
        }

        .vulnerability-card.severity-low {
            border-left-color: var(--success-color);
        }

        .vulnerability-card.severity-critical {
            border-left-color: var(--critical-color);
        }

        /* Secret card styles */
        .secret-card {
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            margin-bottom: 25px;
            overflow: hidden;
            border-left: 4px solid var(--secret-color);
        }

        .secret-card.verified-secret {
            border-left-color: var(--secret-verified);
        }

        .secret-card.unverified-secret {
            border-left-color: var(--secret-unverified);
        }

        .secret-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .secret-badge.verified {
            background: var(--secret-verified);
            color: white;
        }

        .secret-badge.unverified {
            background: var(--secret-unverified);
            color: white;
        }

        /* Agent validation styles */
        .validation-section {
            background: rgba(37, 99, 235, 0.05);
            border: 1px solid rgba(37, 99, 235, 0.2);
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
        }

        .validation-header {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
        }

        .validation-icon {
            width: 20px;
            height: 20px;
            margin-right: 8px;
        }

        .validation-title {
            font-weight: 600;
            color: var(--primary-blue);
            font-size: 1.1em;
        }

        .validation-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 16px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-left: 10px;
        }

        .validation-badge.legitimate {
            background: var(--success-color);
            color: white;
        }

        .validation-badge.filtered {
            background: var(--warning-color);
            color: white;
        }

        .confidence-bar {
            width: 100%;
            height: 6px;
            background: #e2e8f0;
            border-radius: 3px;
            overflow: hidden;
            margin: 10px 0;
        }

        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--error-color) 0%, var(--warning-color) 50%, var(--success-color) 100%);
            transition: width 0.3s ease;
        }

        .confidence-text {
            font-size: 0.9em;
            color: var(--secondary-text);
            margin-bottom: 8px;
        }

        .validation-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-top: 15px;
        }

        .validation-detail {
            background: white;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }

        .validation-detail-title {
            font-weight: 600;
            color: var(--text-color);
            margin-bottom: 8px;
            font-size: 0.9em;
        }

        .validation-detail-content {
            color: var(--secondary-text);
            font-size: 0.85em;
            line-height: 1.4;
        }

        .filtered-vulnerability {
            opacity: 0.7;
            border-left-color: var(--secondary-text) !important;
        }

        .filtered-badge {
            background: var(--secondary-text);
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
            margin-left: 10px;
        }

        .secret-title {
            color: var(--text-color);
            font-size: 1.3em;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .secret-container {
            background: var(--light-bg);
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
            border: 1px solid var(--border-color);
        }

        .secret-content {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
        }

        .detector-info, .redacted-value {
            margin-bottom: 10px;
        }

        .detector-label, .value-label {
            color: var(--secondary-text);
            font-weight: 600;
            margin-right: 8px;
        }

        .detector-name {
            color: var(--secret-color);
            font-weight: 600;
        }

        .redacted-value code {
            background: rgba(139, 92, 246, 0.1);
            padding: 4px 8px;
            border-radius: 4px;
            color: var(--secret-color);
            font-weight: 600;
        }

        .stat-card.secret-card {
            border-left-color: var(--secret-color);
        }

        .stat-card.secret-card h3 {
            color: var(--secret-color);
        }

        .card-header {
            padding: 20px 25px;
            border-bottom: 1px solid var(--border-color);
            background: rgba(0, 0, 0, 0.02);
        }

        .vulnerability-title {
            color: var(--text-color);
            font-size: 1.3em;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .file-path {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
            background: var(--light-bg);
            padding: 8px 12px;
            border-radius: 6px;
            color: var(--primary-blue);
            font-size: 0.9em;
            margin: 10px 0;
            word-break: break-all;
        }

        .file-path a {
            color: var(--primary-blue);
            text-decoration: none;
            border-bottom: 1px solid transparent;
            transition: border-bottom-color 0.3s ease;
        }

        .file-path a:hover {
            border-bottom-color: var(--primary-blue);
        }

        .card-body {
            padding: 25px;
        }

        .description {
            color: var(--secondary-text);
            font-size: 1em;
            line-height: 1.6;
            margin-bottom: 20px;
        }

        .code-container {
            background: #f8f9fa;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }

        .code-header {
            background: #e9ecef;
            padding: 10px 15px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9em;
            color: var(--secondary-text);
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
        }

        .code-content {
            padding: 15px;
            overflow-x: auto;
        }

        .code-content pre {
            margin: 0;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
            font-size: 0.9em;
            line-height: 1.5;
            color: var(--text-color);
        }

        .line-numbers {
            color: var(--secondary-text);
            margin-right: 15px;
            user-select: none;
        }

        .summary {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            text-align: center;
        }

        .summary h2 {
            color: var(--primary-blue);
            font-size: 1.8em;
            margin-bottom: 15px;
        }

        .summary-stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }

        .summary-stat {
            text-align: center;
        }

        .summary-stat .number {
            font-size: 2.5em;
            font-weight: 700;
            color: var(--primary-purple);
            display: block;
        }

        .summary-stat .label {
            color: var(--secondary-text);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: var(--secondary-text);
            border-top: 1px solid var(--border-color);
            margin-top: 50px;
        }

        .footer .logo {
            color: var(--primary-blue);
            font-weight: 600;
            font-size: 1.1em;
        }

        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-stats {
                flex-direction: column;
                gap: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Analysis Report</h1>
            <div class="target">Target: {{.Target}}</div>
        </div>

        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-stats">
                <div class="summary-stat">
                    <span class="number">{{len .Findings}}</span>
                    <span class="label">Total Findings</span>
                </div>
                <div class="summary-stat">
                    <span class="number">{{len .VulnerabilityStatsOrdering}}</span>
                    <span class="label">Vulnerability Types</span>
                </div>
                {{$legitimateCount := 0}}
                {{$filteredCount := 0}}
                {{range .Findings}}
                    {{if .AgentValidation}}
                        {{if .AgentValidation.IsLegitimate}}
                            {{$legitimateCount = (add $legitimateCount 1)}}
                        {{else}}
                            {{$filteredCount = (add $filteredCount 1)}}
                        {{end}}
                    {{end}}
                {{end}}
                {{if gt (add $legitimateCount $filteredCount) 0}}
                <div class="summary-stat">
                    <span class="number">{{$legitimateCount}}</span>
                    <span class="label">Legitimate</span>
                </div>
                <div class="summary-stat">
                    <span class="number">{{$filteredCount}}</span>
                    <span class="label">Filtered</span>
                </div>
                {{end}}
                <div class="summary-stat">
                    <span class="number">{{len .SecretFindings}}</span>
                    <span class="label">Secrets Found</span>
                </div>
                <div class="summary-stat">
                    <span class="number">{{len .SecretStatsOrdering}}</span>
                    <span class="label">Secret Types</span>
                </div>
                {{range $severity, $count := .SeverityStats}}
                <div class="summary-stat">
                    <span class="number">{{$count}}</span>
                    <span class="label">{{$severity}} Severity</span>
                </div>
                {{end}}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Vulnerability Types</h3>
                {{range .VulnerabilityStatsOrdering}}
                <div class="stat-item">
                    <span class="stat-label">{{.}}</span>
                    <span class="stat-value">{{index $.VulnerabilityStats .}}</span>
                </div>
                {{end}}
            </div>

            <div class="stat-card">
                <h3>Severity Distribution</h3>
                {{range .SeverityStatsOrdering}}
                {{if index $.SeverityStats .}}
                <div class="stat-item">
                    <span class="stat-label">{{.}}</span>
                    <span class="stat-value">{{index $.SeverityStats .}}</span>
                </div>
                {{end}}
                {{end}}
            </div>

            {{if .SecretStatsOrdering}}
            <div class="stat-card secret-card">
                <h3>🔐 Secret Types</h3>
                {{range .SecretStatsOrdering}}
                <div class="stat-item">
                    <span class="stat-label">{{.}}</span>
                    <span class="stat-value">{{index $.SecretStats .}}</span>
                </div>
                {{end}}
            </div>
            {{end}}

            {{if .MatrixConfig}}
            <div class="stat-card">
                <h3>🎯 Matrix Configuration</h3>
                <div class="stat-item">
                    <span class="stat-label">Primary Language</span>
                    <span class="stat-value">{{.MatrixConfig.Languages.Primary.Name}} ({{printf "%.1f" .MatrixConfig.Languages.Primary.Percentage}}%)</span>
                </div>
                {{if .MatrixConfig.Languages.Secondary.Name}}
                <div class="stat-item">
                    <span class="stat-label">Secondary Language</span>
                    <span class="stat-value">{{.MatrixConfig.Languages.Secondary.Name}} ({{printf "%.1f" .MatrixConfig.Languages.Secondary.Percentage}}%)</span>
                </div>
                {{end}}
                {{if ne .MatrixConfig.Frameworks.Primary "None"}}
                <div class="stat-item">
                    <span class="stat-label">Primary Framework</span>
                    <span class="stat-value">{{.MatrixConfig.Frameworks.Primary}}</span>
                </div>
                {{end}}
                {{if .MatrixConfig.Frameworks.Secondary}}
                <div class="stat-item">
                    <span class="stat-label">Secondary Frameworks</span>
                    <span class="stat-value">{{len .MatrixConfig.Frameworks.Secondary}} detected</span>
                </div>
                {{end}}
                <div class="stat-item">
                    <span class="stat-label">Rulesets Applied</span>
                    <span class="stat-value">{{len .MatrixConfig.Rulesets}}</span>
                </div>
                {{if .MatrixConfig.AutoDetected}}
                <div class="stat-item">
                    <span class="stat-label">Detection Method</span>
                    <span class="stat-value">Auto-detected</span>
                </div>
                {{end}}
            </div>
            {{end}}
        </div>

        <div class="findings-section">
            <h2 style="color: var(--primary-blue); font-size: 2em; margin-bottom: 25px; text-align: center;">Security Findings</h2>
            
            {{range .Findings}}
            <div class="vulnerability-card severity-{{toLowerCase .Severity}}{{if .IsFiltered}} filtered-vulnerability{{end}}">
                <div class="card-header">
                    <div class="vulnerability-title">
                        {{.VulnerabilityTitle}}
                        {{if .IsFiltered}}<span class="filtered-badge">Filtered</span>{{end}}
                    </div>
                    <span class="severity-badge severity-{{toLowerCase .Severity}}">{{.Severity}}</span>
                    <div class="file-path">
                        <a href="{{.GithubLink}}" target="_blank">{{.GithubLink}}</a>
                        <span style="color: var(--secondary-text); margin-left: 10px;">Lines {{.StartLine}}-{{.StopLine}}</span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="description">{{.Description}}</div>
                    
                    {{if .AgentValidation}}
                    <div class="validation-section">
                        <div class="validation-header">
                            <span class="validation-icon">🤖</span>
                            <span class="validation-title">Agent Validation</span>
                            <span class="validation-badge {{if .AgentValidation.IsLegitimate}}legitimate{{else}}filtered{{end}}">
                                {{if .AgentValidation.IsLegitimate}}Legitimate{{else}}False Positive{{end}}
                            </span>
                        </div>
                        
                        <div class="confidence-text">
                            Confidence: {{printf "%.0f" (mul .AgentValidation.Confidence 100)}}%
                        </div>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {{printf "%.0f" (mul .AgentValidation.Confidence 100)}}%"></div>
                        </div>
                        
                        <div class="validation-details">
                            <div class="validation-detail">
                                <div class="validation-detail-title">Analysis</div>
                                <div class="validation-detail-content">{{.AgentValidation.Reasoning}}</div>
                            </div>
                            <div class="validation-detail">
                                <div class="validation-detail-title">Context Analysis</div>
                                <div class="validation-detail-content">{{.AgentValidation.ContextAnalysis}}</div>
                            </div>
                            {{if .AgentValidation.FalsePositiveReason}}
                            <div class="validation-detail">
                                <div class="validation-detail-title">False Positive Reason</div>
                                <div class="validation-detail-content">{{.AgentValidation.FalsePositiveReason}}</div>
                            </div>
                            {{end}}
                            <div class="validation-detail">
                                <div class="validation-detail-title">Recommended Action</div>
                                <div class="validation-detail-content">{{.AgentValidation.RecommendedAction}}</div>
                            </div>
                        </div>
                    </div>
                    {{end}}
                    
                    <div class="code-container">
                        <div class="code-header">Vulnerable Code</div>
                        <div class="code-content">
                            <pre><code class="language-{{getLanguage .GithubLink}}">{{.Code}}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
            {{end}}
        </div>

        {{if .SecretFindings}}
        <div class="secrets-section">
            <h2 style="color: var(--primary-purple); font-size: 2em; margin-bottom: 25px; text-align: center;">🔐 Secret Findings</h2>
            
            {{range .SecretFindings}}
            <div class="secret-card {{if .Verified}}verified-secret{{else}}unverified-secret{{end}}">
                <div class="card-header">
                    <div class="secret-title">{{.SecretType}}</div>
                    <span class="secret-badge {{if .Verified}}verified{{else}}unverified{{end}}">
                        {{if .Verified}}✅ Verified{{else}}⚠️ Unverified{{end}}
                    </span>
                    <div class="file-path">
                        <a href="{{.GithubLink}}" target="_blank">{{.File}}</a>
                        <span style="color: var(--secondary-text); margin-left: 10px;">Line {{.StartLine}}</span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="description">{{.Description}}</div>
                    <div class="secret-container">
                        <div class="code-header">Detected Secret</div>
                        <div class="secret-content">
                            <div class="detector-info">
                                <span class="detector-label">Detector:</span>
                                <span class="detector-name">{{.DetectorName}}</span>
                            </div>
                            <div class="redacted-value">
                                <span class="value-label">Value:</span>
                                <code>{{.RedactedValue}}</code>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            {{end}}
        </div>
        {{end}}

        <div class="footer">
            <div class="logo">🔒 codesucks-ai</div>
            <div>AI-Powered Security Analysis Tool</div>
            <div style="margin-top: 10px; font-size: 0.9em;">
                Generated on {{.Target}} with ❤️ by codesucks-ai
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/components/prism-core.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/plugins/autoloader/prism-autoloader.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/plugins/line-numbers/prism-line-numbers.min.js"></script>
</body>
</html>
`
