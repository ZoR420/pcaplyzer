import { loadCase } from '@/lib/cases'
import { buildFindings } from '@/lib/findings'

export async function compareCases(leftCaseId: string, rightCaseId: string) {
  const [leftCase, rightCase, leftFindings, rightFindings] = await Promise.all([
    loadCase(leftCaseId),
    loadCase(rightCaseId),
    buildFindings(leftCaseId),
    buildFindings(rightCaseId)
  ])

  const leftArtifacts = leftCase.artifacts.map((artifact) => `${artifact.kind}:${artifact.originalName}`)
  const rightArtifacts = rightCase.artifacts.map((artifact) => `${artifact.kind}:${artifact.originalName}`)

  return {
    leftCaseId,
    rightCaseId,
    artifactDiff: {
      onlyInLeft: leftArtifacts.filter((item) => !rightArtifacts.includes(item)),
      onlyInRight: rightArtifacts.filter((item) => !leftArtifacts.includes(item))
    },
    findingDiff: {
      leftOnly: leftFindings.findings.filter((finding) => !rightFindings.findings.some((other) => other.title === finding.title)).map((finding) => finding.title),
      rightOnly: rightFindings.findings.filter((finding) => !leftFindings.findings.some((other) => other.title === finding.title)).map((finding) => finding.title)
    },
    severityComparison: {
      left: leftFindings.severity,
      right: rightFindings.severity,
      leftScore: leftFindings.score,
      rightScore: rightFindings.score
    },
    generatedAt: new Date().toISOString()
  }
}
