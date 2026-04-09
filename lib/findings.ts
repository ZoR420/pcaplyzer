import { buildCorrelatedCaseView } from '@/lib/correlation'

export type Finding = {
  id: string
  title: string
  severity: 'low' | 'medium' | 'high'
  category: 'network' | 'file' | 'process' | 'behavior'
  summary: string
  iocs: string[]
}

const SUSPICIOUS_HOSTS = ['8.8.8.8', '1.1.1.1']
const SUSPICIOUS_PATH_MARKERS = ['appdata', 'temp', 'startup']
const SUSPICIOUS_PROCESS_NAMES = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'rundll32.exe']

function unique(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)))
}

export async function buildFindings(caseId: string) {
  const correlation = await buildCorrelatedCaseView(caseId)
  const findings: Finding[] = []

  const suspiciousNetwork = correlation.timeline.filter(
    (event) => event.category === 'network' && SUSPICIOUS_HOSTS.some((host) => event.summary.includes(host))
  )
  if (suspiciousNetwork.length > 0) {
    findings.push({
      id: 'finding-network-suspicious-destination',
      title: 'Suspicious network destinations observed',
      severity: suspiciousNetwork.length > 3 ? 'high' : 'medium',
      category: 'network',
      summary: `${suspiciousNetwork.length} network events matched flagged destinations.`,
      iocs: unique(suspiciousNetwork.flatMap((event) => [event.source || '', event.destination || '']))
    })
  }

  const suspiciousFiles = correlation.timeline.filter(
    (event) => event.category === 'file' && SUSPICIOUS_PATH_MARKERS.some((marker) => event.summary.toLowerCase().includes(marker))
  )
  if (suspiciousFiles.length > 0) {
    findings.push({
      id: 'finding-file-suspicious-paths',
      title: 'Suspicious file activity paths observed',
      severity: suspiciousFiles.length > 2 ? 'high' : 'medium',
      category: 'file',
      summary: `${suspiciousFiles.length} file events touched suspicious user-writable paths.`,
      iocs: unique(suspiciousFiles.map((event) => event.summary))
    })
  }

  const suspiciousProcesses = correlation.timeline.filter(
    (event) => event.category === 'process' && SUSPICIOUS_PROCESS_NAMES.some((name) => event.summary.toLowerCase().includes(name.replace('.exe', '')) || event.summary.toLowerCase().includes(name.toLowerCase()))
  )
  if (suspiciousProcesses.length > 0) {
    findings.push({
      id: 'finding-process-lolbins',
      title: 'Potential LOLBins or script execution processes observed',
      severity: suspiciousProcesses.length > 1 ? 'high' : 'medium',
      category: 'process',
      summary: `${suspiciousProcesses.length} process events matched common script or LOLBin executables.`,
      iocs: unique(suspiciousProcesses.map((event) => event.summary))
    })
  }

  if (findings.length === 0) {
    findings.push({
      id: 'finding-none',
      title: 'No heuristic findings yet',
      severity: 'low',
      category: 'behavior',
      summary: 'No suspicious heuristics matched current correlated data.',
      iocs: []
    })
  }

  const score = findings.reduce((acc, finding) => {
    if (finding.severity === 'high') return acc + 3
    if (finding.severity === 'medium') return acc + 2
    return acc + 1
  }, 0)

  const severity: 'low' | 'medium' | 'high' = score >= 6 ? 'high' : score >= 3 ? 'medium' : 'low'

  return {
    findings,
    iocs: unique(findings.flatMap((finding) => finding.iocs)),
    score,
    severity,
    generatedAt: new Date().toISOString()
  }
}
