/**
 * OSTE - Open Source Tool Evaluation
 * Report Generator
 * 
 * Generates PDF and JSON reports from analysis results.
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

class ReportGenerator {
  constructor() {
    this.outputDir = path.join(process.cwd(), 'reports');
    if (!fs.existsSync(this.outputDir)) {
      fs.mkdirSync(this.outputDir, { recursive: true });
    }
  }

  /**
   * Generate both JSON and PDF reports.
   */
  async generate(analysis) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const baseName = `oste-${analysis.type}-${this._sanitize(analysis.target)}-${timestamp}`;

    const jsonPath = await this.generateJSON(analysis, baseName);
    const pdfPath = await this.generatePDF(analysis, baseName);

    return { jsonPath, pdfPath };
  }

  /**
   * Generate JSON report.
   */
  async generateJSON(analysis, baseName) {
    const filePath = path.join(this.outputDir, `${baseName}.json`);
    const report = {
      meta: {
        tool: 'OSTE - Open Source Tool Evaluation',
        version: '1.1.0',
        generatedAt: new Date().toISOString(),
        target: analysis.target,
        type: analysis.type,
      },
      summary: {
        riskScore: analysis.riskScore?.overallRiskScore,
        riskLevel: analysis.riskScore?.riskLevel,
        decision: analysis.riskScore?.decision,
        confidence: analysis.riskScore?.confidenceLevel,
      },
      aiAssessment: analysis.aiAssessment,
      riskComponents: analysis.riskScore?.components,
      ...(analysis.type === 'opensource' ? {
        repository: analysis.data.repository,
        healthScore: analysis.data.healthScore,
        vulnerabilities: {
          summary: analysis.data.vulnerabilitySummary,
          details: (analysis.data.topVulnerabilities || analysis.data.vulnerabilities || []).slice(0, 50),
          scan: analysis.data.osvResult?.meta,
        },
        ownPackageAdvisories: analysis.data.selfAdvisories,
        dependencyStats: analysis.data.dependencyStats,
        dataSources: { githubLiteMode: analysis.data.liteMode, apiErrors: analysis.data.apiErrors },
        languages: analysis.data.languages,
        contributors: analysis.data.contributors,
        releases: analysis.data.releases,
        community: analysis.data.community,
      } : {
        toolInfo: analysis.data.toolInfo,
        virusTotal: analysis.data.virusTotal,
        hybridAnalysis: analysis.data.hybridAnalysis,
        domainReputation: analysis.data.domainReputation,
      }),
    };

    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  /**
   * Generate PDF report.
   */
  async generatePDF(analysis, baseName) {
    const filePath = path.join(this.outputDir, `${baseName}.pdf`);

    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: `OSTE Security Assessment - ${analysis.target}`,
          Author: 'OSTE - Open Source Tool Evaluation',
          Subject: 'Security Risk Assessment Report',
        },
      });

      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      // ---- Title Page ----
      doc.fontSize(28).font('Helvetica-Bold')
        .text('OSTE', { align: 'center' });
      doc.fontSize(14).font('Helvetica')
        .text('Open Source Tool Evaluation', { align: 'center' });
      doc.moveDown(2);

      doc.fontSize(18).font('Helvetica-Bold')
        .text('Security Risk Assessment Report', { align: 'center' });
      doc.moveDown();

      doc.fontSize(12).font('Helvetica')
        .text(`Target: ${analysis.target}`, { align: 'center' })
        .text(`Type: ${analysis.type === 'opensource' ? 'Open Source' : 'Freeware'}`, { align: 'center' })
        .text(`Date: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`, { align: 'center' });

      doc.moveDown(3);

      // Risk Score Box
      const score = analysis.riskScore?.overallRiskScore || 0;
      const level = analysis.riskScore?.riskLevel || 'UNKNOWN';
      const decision = analysis.riskScore?.decision || 'REVIEW_REQUIRED';
      const color = this._riskColor(level);

      doc.rect(150, doc.y, 300, 100).fillAndStroke(color, color);
      doc.fillColor('white').fontSize(36).font('Helvetica-Bold')
        .text(`${score}/100`, 150, doc.y - 90, { width: 300, align: 'center' });
      doc.fontSize(16)
        .text(level, 150, doc.y - 10, { width: 300, align: 'center' });
      doc.fillColor('black');
      doc.y += 30;

      doc.moveDown();
      doc.fontSize(14).font('Helvetica-Bold')
        .text(`Decision: ${decision.replace(/_/g, ' ')}`, { align: 'center' });

      // ---- Executive Summary ----
      doc.addPage();
      this._sectionHeader(doc, 'Executive Summary');

      const summary = analysis.aiAssessment?.executiveSummary || 'No AI assessment available. Configure GROQ_API_KEY for detailed analysis.';
      doc.fontSize(11).font('Helvetica').text(String(summary));
      const meta = analysis.aiAssessment?._meta;
      doc.fontSize(8).fillColor('#6b7280').text(meta?.source === 'llm' ? `Narrative generated by ${meta.model} (Groq). Score and decision are computed deterministically.` : 'Rule-based narrative (AI unavailable for this run). Score and decision are computed deterministically.');
      doc.fillColor('black');
      doc.moveDown(2);

      // ---- Risk Components ----
      this._sectionHeader(doc, 'Risk Score Breakdown');
      const components = analysis.riskScore?.components || {};
      for (const [key, comp] of Object.entries(components)) {
        if (doc.y > 720) doc.addPage();
        const unavailable = comp.available === false;
        const barWidth = unavailable ? 0 : (comp.score / 100) * 400;
        const label = unavailable
          ? `${comp.label}: no data (excluded from score)`
          : `${comp.label}: ${comp.score}/100 (weight: ${Math.round((comp.effectiveWeight ?? comp.weight) * 100)}%)`;
        doc.fillColor('black').fontSize(10).font('Helvetica-Bold').text(label, 50, doc.y + 5);
        doc.rect(50, doc.y + 2, 400, 12).stroke('#ccc');
        if (barWidth > 0) doc.rect(50, doc.y + 2, barWidth, 12).fill(this._riskColor(this._scoreToLevel(comp.score)));
        doc.fillColor('black');
        doc.y += 25;
      }

      doc.moveDown(2);

      // ---- Vulnerability Summary ----
      if (analysis.type === 'opensource') {
        this._sectionHeader(doc, 'Vulnerability Summary');
        const vulnSummary = analysis.data.vulnerabilitySummary || {};
        doc.fontSize(10).font('Helvetica');
        doc.text(`Total Vulnerabilities: ${vulnSummary.total || 0}`);
        doc.text(`Critical: ${vulnSummary.CRITICAL || 0}  |  High: ${vulnSummary.HIGH || 0}  |  Medium: ${vulnSummary.MEDIUM || 0}  |  Low: ${vulnSummary.LOW || 0}`);
        doc.text(`Total Packages Scanned: ${vulnSummary.totalPackages || 0}`);
        doc.moveDown();

        // Top vulnerabilities
        const topVulns = (analysis.data.topVulnerabilities || analysis.data.vulnerabilities || []).slice(0, 10);
        if (topVulns.length > 0) {
          this._sectionHeader(doc, 'Top Vulnerabilities');
          for (const v of topVulns) {
            if (doc.y > 700) doc.addPage();
            doc.fontSize(9).font('Helvetica-Bold')
              .text(`${v.id} [${v.severity}] ${v.cvssScore ? `CVSS: ${v.cvssScore}` : ''} ${v.epss?.score ? `EPSS: ${(v.epss.score * 100).toFixed(1)}%` : ''}`);
            doc.font('Helvetica')
              .text(v.summary || v.details?.substring(0, 200) || 'No description', { indent: 20 });
            if (v.affectedPackage) {
              doc.text(`Affected: ${v.affectedPackage} (${v.affectedEcosystem})`, { indent: 20 });
            }
            doc.moveDown(0.5);
          }
        }

        const self = analysis.data.selfAdvisories;
        if (self && self.found) {
          if (doc.y > 650) doc.addPage();
          this._sectionHeader(doc, 'Project Security Track Record');
          doc.fontSize(10).font('Helvetica');
          doc.text(`Published package: ${self.package} (${self.ecosystem}), version assessed: ${self.version || 'unknown'}`);
          doc.text(`Advisories affecting this version: ${self.current?.length || 0}`);
          doc.text(`All-time advisories: ${self.historicalCount} (sampled ${self.historicalSampled}: critical ${self.historicalSeverity?.CRITICAL || 0}, high ${self.historicalSeverity?.HIGH || 0})`);
          doc.moveDown();
        }
      } else {
        const vt = analysis.data.virusTotal || {};
        const dom = analysis.data.domainReputation || {};
        this._sectionHeader(doc, 'Scan Results');
        doc.fontSize(10).font('Helvetica');
        doc.text(`VirusTotal status: ${vt.status || 'n/a'}${vt.message ? ' - ' + vt.message : ''}${vt.error ? ' - ' + vt.error : ''}`);
        if (vt.status === 'completed') {
          doc.text(`Engines: malicious ${vt.malicious || 0}, suspicious ${vt.suspicious || 0}, harmless ${vt.harmless || 0}, undetected ${vt.undetected || 0}`);
          for (const d of (vt.detectionNames || []).slice(0, 10)) doc.text(`  - ${d.engine}: ${d.result || d.category}`);
        }
        if (dom.status === 'completed') doc.text(`Domain ${dom.target}: reputation ${dom.reputation}, malicious ${dom.malicious}, suspicious ${dom.suspicious}`);
        doc.text(`Hybrid Analysis: ${analysis.data.hybridAnalysis?.status || 'n/a'}${analysis.data.hybridAnalysis?.message ? ' - ' + analysis.data.hybridAnalysis.message : ''}`);
        doc.moveDown();
      }

      // ---- Recommendations ----
      if (analysis.aiAssessment?.recommendations) {
        if (doc.y > 600) doc.addPage();
        this._sectionHeader(doc, 'Recommendations');
        for (const rec of [].concat(analysis.aiAssessment.recommendations)) {
          if (doc.y > 700) doc.addPage();
          const r = typeof rec === 'string' ? { priority: 'INFO', action: rec } : rec;
          doc.fontSize(10).font('Helvetica-Bold')
            .text(`[${r.priority || 'INFO'}] ${r.action || ''}`);
          doc.font('Helvetica').fontSize(9)
            .text(String(r.rationale || ''), { indent: 20 });
          doc.moveDown(0.5);
        }
      }

      // ---- Footer ----
      doc.addPage();
      this._sectionHeader(doc, 'Disclaimer');
      doc.fontSize(9).font('Helvetica')
        .text('This report was generated by OSTE (Open Source Tool Evaluation). The assessment is based on automated analysis of publicly available data and should be used as one input in a broader security review process. OSTE does not guarantee the completeness or accuracy of third-party data sources. Organizations should perform their own due diligence before adopting any software.');

      doc.end();

      stream.on('finish', () => resolve(filePath));
      stream.on('error', reject);
    });
  }

  _sectionHeader(doc, title) {
    doc.fontSize(16).font('Helvetica-Bold').text(title);
    doc.moveTo(50, doc.y + 2).lineTo(545, doc.y + 2).stroke('#6366f1');
    doc.moveDown(0.5);
  }

  _riskColor(level) {
    const colors = {
      CRITICAL: '#dc2626',
      HIGH: '#ea580c',
      MEDIUM: '#d97706',
      LOW: '#2563eb',
      MINIMAL: '#16a34a',
      CLEAN: '#16a34a',
    };
    return colors[level] || '#6b7280';
  }

  _scoreToLevel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 35) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'MINIMAL';
  }

  _sanitize(str) {
    return str.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50);
  }
}

module.exports = ReportGenerator;
