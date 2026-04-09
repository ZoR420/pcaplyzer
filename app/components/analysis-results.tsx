'use client'

import { useState } from 'react'
import { Button } from '@/app/components/ui/button'
import { Card } from '@/app/components/ui/card'
import { ScrollArea } from '@/app/components/ui/scroll-area'

interface AnalysisResultsProps {
  results: {
    trafficSummary?: {
      packet_count: number
      time_range: {
        start: string
        end: string
      }
      protocol_counts: Record<string, number>
      packet_sizes: {
        min: number
        max: number
        average: number
      }
      ip_addresses: {
        source: string[]
        destination: string[]
      }
      tcp_ports: number[]
      udp_ports: number[]
      dns_queries: Array<{
        query: string
        responses?: string[]
      }>
    }
  }
  fileName: string
  onClose?: () => void
}

export default function AnalysisResults({ results, fileName, onClose }: AnalysisResultsProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'protocols' | 'ports' | 'dns'>('overview')

  if (!results.trafficSummary) {
    return <div className="py-8 text-center text-gray-500">No analysis results available.</div>
  }

  const summary = results.trafficSummary
  const totalProtocolCount = Object.values(summary.protocol_counts).reduce((a, b) => a + b, 0)
  const topProtocols = Object.entries(summary.protocol_counts).map(([protocol, count]) => ({
    protocol,
    count,
    percentage: totalProtocolCount > 0 ? ((count / totalProtocolCount) * 100).toFixed(1) : '0.0'
  }))

  return (
    <div className="fixed inset-0 z-50 overflow-auto bg-white">
      <div className="mx-auto max-w-7xl p-6">
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-2xl font-bold">Analysis Results: {fileName}</h2>
          {onClose ? <Button variant="outline" onClick={onClose}>Close</Button> : null}
        </div>

        <div className="flex space-x-2 border-b pb-2">
          {(['overview', 'protocols', 'ports', 'dns'] as const).map((tab) => (
            <Button key={tab} variant={activeTab === tab ? 'default' : 'ghost'} onClick={() => setActiveTab(tab)}>
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </Button>
          ))}
        </div>

        <div className="mt-4">
          {activeTab === 'overview' ? (
            <Card className="p-4">
              <h3 className="mb-4 text-lg font-semibold">Traffic Overview</h3>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <h4 className="mb-2 font-medium">Summary</h4>
                  <ul className="space-y-1 text-sm">
                    <li>Total Packets: {summary.packet_count}</li>
                    <li>Time Range: {new Date(summary.time_range.start).toLocaleString()} to {new Date(summary.time_range.end).toLocaleString()}</li>
                    <li>Unique Source IPs: {summary.ip_addresses.source.length}</li>
                    <li>Unique Destination IPs: {summary.ip_addresses.destination.length}</li>
                  </ul>
                </div>
                <div>
                  <h4 className="mb-2 font-medium">Packet Sizes</h4>
                  <ul className="space-y-1 text-sm">
                    <li>Minimum: {summary.packet_sizes.min} bytes</li>
                    <li>Maximum: {summary.packet_sizes.max} bytes</li>
                    <li>Average: {summary.packet_sizes.average.toFixed(2)} bytes</li>
                  </ul>
                </div>
              </div>
            </Card>
          ) : null}

          {activeTab === 'protocols' ? (
            <Card className="p-4">
              <h3 className="mb-4 text-lg font-semibold">Protocol Distribution</h3>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3">
                {topProtocols.map((protocol) => (
                  <div key={protocol.protocol} className="rounded-lg bg-gray-50 p-4">
                    <div className="font-medium">{protocol.protocol}</div>
                    <div className="text-sm text-gray-600">{protocol.count} packets ({protocol.percentage}%)</div>
                  </div>
                ))}
              </div>
            </Card>
          ) : null}

          {activeTab === 'ports' ? (
            <Card className="p-4">
              <h3 className="mb-4 text-lg font-semibold">Port Analysis</h3>
              <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                <div>
                  <h4 className="mb-2 text-md font-medium">TCP Ports</h4>
                  <ScrollArea className="h-[200px] rounded-md border p-2">
                    <div className="space-y-1">
                      {summary.tcp_ports.sort((a, b) => a - b).map((port) => (
                        <div key={`tcp-${port}`} className="rounded bg-gray-50 p-2 text-sm">Port {port}</div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
                <div>
                  <h4 className="mb-2 text-md font-medium">UDP Ports</h4>
                  <ScrollArea className="h-[200px] rounded-md border p-2">
                    <div className="space-y-1">
                      {summary.udp_ports.sort((a, b) => a - b).map((port) => (
                        <div key={`udp-${port}`} className="rounded bg-gray-50 p-2 text-sm">Port {port}</div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              </div>
            </Card>
          ) : null}

          {activeTab === 'dns' ? (
            <Card className="p-4">
              <h3 className="mb-4 text-lg font-semibold">DNS Queries</h3>
              <ScrollArea className="h-[400px] rounded-md border p-2">
                <div className="space-y-2">
                  {summary.dns_queries.map((query, index) => (
                    <div key={`${query.query}-${index}`} className="rounded bg-gray-50 p-3 text-sm">
                      <div className="font-medium">{query.query}</div>
                      {query.responses?.length ? <div className="mt-1 text-xs text-gray-600">{query.responses.join(', ')}</div> : null}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </Card>
          ) : null}
        </div>
      </div>
    </div>
  )
}
