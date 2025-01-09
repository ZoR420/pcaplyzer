'use client'

import { Card } from "@/app/components/ui/card"
import { ScrollArea } from "@/app/components/ui/scroll-area"
import { Button } from "@/app/components/ui/button"
import { useState } from 'react'

interface TrafficSummary {
  totalPackets: number
  timeRange: {
    start: string
    end: string
  }
  protocolDistribution: Record<string, number>
  packetSizes: {
    minimum: number
    maximum: number
    average: number
  }
  uniqueAddresses: {
    sources: number
    destinations: number
    sourceList: string[]
    destinationList: string[]
  }
  topProtocols: Array<{
    protocol: string
    count: number
    percentage: number
  }>
  dnsQueries: Array<{
    query: string
    timestamp: string
  }>
  ports: {
    tcp: number[]
    udp: number[]
  }
}

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
      protocols: string[]
      tcp_ports: number[]
      udp_ports: number[]
      dns_queries: Array<{
        query: string
        timestamp: string
      }>
    }
  }
  fileName: string
  onClose?: () => void
}

export default function AnalysisResults({ results, fileName, onClose }: AnalysisResultsProps) {
  const [activeTab, setActiveTab] = useState('overview')
  const [displayedPackets, setDisplayedPackets] = useState(100)

  if (!results?.trafficSummary) {
    return (
      <div className="text-center text-gray-500 py-8">
        No analysis results available. Please run the analysis first.
      </div>
    )
  }

  const summary = results.trafficSummary
  const totalProtocolCount = Object.values(summary.protocol_counts).reduce((a, b) => a + b, 0)
  const topProtocols = Object.entries(summary.protocol_counts).map(([protocol, count]) => ({
    protocol,
    count,
    percentage: ((count / totalProtocolCount) * 100).toFixed(1)
  }))

  const renderOverview = () => (
    <Card className="p-4">
      <h3 className="text-lg font-semibold mb-4">Traffic Overview</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <h4 className="font-medium mb-2">Summary</h4>
          <ul className="space-y-1 text-sm">
            <li>Total Packets: {summary.packet_count}</li>
            <li>Time Range: {new Date(summary.time_range.start).toLocaleString()} to {new Date(summary.time_range.end).toLocaleString()}</li>
            <li>Unique Source IPs: {summary.ip_addresses.source.length}</li>
            <li>Unique Destination IPs: {summary.ip_addresses.destination.length}</li>
          </ul>
        </div>
        <div>
          <h4 className="font-medium mb-2">Packet Sizes</h4>
          <ul className="space-y-1 text-sm">
            <li>Minimum: {summary.packet_sizes.min} bytes</li>
            <li>Maximum: {summary.packet_sizes.max} bytes</li>
            <li>Average: {summary.packet_sizes.average.toFixed(2)} bytes</li>
          </ul>
        </div>
      </div>
    </Card>
  )

  const renderProtocols = () => (
    <Card className="p-4">
      <h3 className="text-lg font-semibold mb-4">Protocol Distribution</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
        {topProtocols.map((protocol) => (
          <div
            key={protocol.protocol}
            className="bg-gray-50 p-4 rounded-lg"
          >
            <div className="font-medium">{protocol.protocol}</div>
            <div className="text-sm text-gray-600">
              {protocol.count} packets ({protocol.percentage}%)
            </div>
            <div className="w-full bg-gray-200 h-2 rounded-full mt-2">
              <div
                className="bg-blue-500 h-2 rounded-full"
                style={{ width: `${protocol.percentage}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </Card>
  )

  const renderPorts = () => (
    <Card className="p-4">
      <h3 className="text-lg font-semibold mb-4">Port Analysis</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <h4 className="text-md font-medium mb-2">TCP Ports</h4>
          <ScrollArea className="h-[200px] rounded-md border p-2">
            <div className="space-y-1">
              {summary.tcp_ports.sort((a, b) => a - b).map((port, index) => (
                <div key={index} className="text-sm bg-gray-50 p-2 rounded">
                  Port {port}
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
        <div>
          <h4 className="text-md font-medium mb-2">UDP Ports</h4>
          <ScrollArea className="h-[200px] rounded-md border p-2">
            <div className="space-y-1">
              {summary.udp_ports.sort((a, b) => a - b).map((port, index) => (
                <div key={index} className="text-sm bg-gray-50 p-2 rounded">
                  Port {port}
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      </div>
    </Card>
  )

  const renderDNS = () => (
    <Card className="p-4">
      <h3 className="text-lg font-semibold mb-4">DNS Queries</h3>
      <ScrollArea className="h-[400px] rounded-md border p-2">
        <div className="space-y-2">
          {summary.dns_queries.map((query, index) => (
            <div key={index} className="text-sm bg-gray-50 p-3 rounded">
              <div className="font-medium">{query.query}</div>
              <div className="text-gray-600 text-xs mt-1">
                {new Date(query.timestamp).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </Card>
  )

  const PacketsTab = () => {
    const packets = data?.packets || [];
    const hasMorePackets = packets.length > displayedPackets;

    return (
      <div className="space-y-4">
        <div className="overflow-x-auto">
          <table className="min-w-full table-auto">
            {/* ... existing table header ... */}
            <tbody>
              {packets.slice(0, displayedPackets).map((packet, index) => (
                <tr key={index} className="border-b hover:bg-gray-50">
                  <td className="px-4 py-2">{packet.timestamp}</td>
                  <td className="px-4 py-2">{packet.source}</td>
                  <td className="px-4 py-2">{packet.destination}</td>
                  <td className="px-4 py-2">{packet.protocol}</td>
                  <td className="px-4 py-2">{packet.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {hasMorePackets && (
          <div className="flex justify-center mt-4">
            <button
              onClick={() => setDisplayedPackets(prev => prev + 100)}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              Load More Packets
            </button>
          </div>
        )}
        
        <div className="text-sm text-gray-500 text-center mt-2">
          Showing {Math.min(displayedPackets, packets.length)} of {packets.length} packets
        </div>
      </div>
    );
  };

  return (
    <div className="fixed inset-0 bg-white z-50 overflow-auto">
      <div className="max-w-7xl mx-auto p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold">Analysis Results: {fileName}</h2>
          {onClose && (
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          )}
        </div>
        
        <div className="flex space-x-2 border-b pb-2">
          <Button
            variant={activeTab === 'overview' ? 'default' : 'ghost'}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </Button>
          <Button
            variant={activeTab === 'protocols' ? 'default' : 'ghost'}
            onClick={() => setActiveTab('protocols')}
          >
            Protocols
          </Button>
          <Button
            variant={activeTab === 'ports' ? 'default' : 'ghost'}
            onClick={() => setActiveTab('ports')}
          >
            Ports
          </Button>
          <Button
            variant={activeTab === 'dns' ? 'default' : 'ghost'}
            onClick={() => setActiveTab('dns')}
          >
            DNS
          </Button>
        </div>

        <div className="mt-4">
          {activeTab === 'overview' && renderOverview()}
          {activeTab === 'protocols' && renderProtocols()}
          {activeTab === 'ports' && renderPorts()}
          {activeTab === 'dns' && renderDNS()}
        </div>
      </div>
    </div>
  )
} 