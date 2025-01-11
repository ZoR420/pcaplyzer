'use client'

import { useState, useEffect, useMemo, useRef } from 'react'
import { Button } from "@/app/components/ui/button"
import { Card } from "@/app/components/ui/card"
import { ScrollArea } from "@/app/components/ui/scroll-area"
import { Loader2 } from "lucide-react"
import FileUpload from './components/file-upload'
import AnalysisResults from './components/analysis-results'
import ErrorNotification from './components/error-notification'
import { ResponsiveBar } from '@nivo/bar'
import { ResponsiveLine } from '@nivo/line'
import { ResponsivePie } from '@nivo/pie'
import { ChevronUpIcon } from 'lucide-react'
import { PointTooltipProps as NivoPointTooltipProps } from '@nivo/line';
import { PieTooltipProps } from '@nivo/pie';
import { BarTooltipProps, BarDatum } from '@nivo/bar';
import { GoogleGenerativeAI } from "@google/generative-ai";
import { ResponsiveNetwork } from '@nivo/network'
import { ResponsiveHeatMap } from '@nivo/heatmap'
import { ResponsiveGeoMap } from '@nivo/geo'
import dynamic from 'next/dynamic'

// Add this near the top of your file with other imports
const NetworkGraphNoSSR = dynamic(
  () => import('@/app/components/network-graph').then(mod => mod.NetworkGraph),
  { 
    ssr: false,
    loading: () => (
      <div className="w-full h-full flex items-center justify-center bg-gray-50">
        <div className="text-gray-500">Loading network graph...</div>
      </div>
    )
  }
)

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  id: string;
}

interface DNSQuery {
  query: string;
  type: string;
  responses: string[];
  ttl?: number;
}

interface PacketSizes {
  min: number;
  max: number;
  average: number;
}

interface TimeRange {
  start: string;
  end: string;
  duration: number;
  file_created?: string;
  file_modified?: string;
}

interface IPAddresses {
  source: string[];
  destination: string[];
}

interface Packet {
  number: number;
  time: string | null;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  srcPort: string;
  dstPort: string;
}

interface RTTStats {
  min: number;
  max: number;
  average: number;
}

interface HandshakeStatus {
  syn: string;
  synAck: string;
  ack: string;
}

interface FlowStats {
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  handshakeStatus: HandshakeStatus | null;
  rttStats: RTTStats | null;
  retransmissionCount: number;
  throughput: number;
}

interface Conversation {
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  packetCount: number;
  dataVolume: number;
  duration: number;
  hasErrors: boolean;
  hasRetransmissions: boolean;
}

interface TimingStats {
  interPacketDelays: {
    min: number;
    max: number;
    avg: number;
    distribution: Array<{
      range: string;  // e.g., "0-1ms", "1-5ms"
      count: number;
      percentage: number;
    }>;
  };
  jitterStats: {
    avg: number;
    max: number;
    distribution: Array<{
      timestamp: string;
      value: number;
    }>;
  };
  packetOrder: {
    duplicateCount: number;
    outOfOrderCount: number;
    duplicatePercentage: number;
    outOfOrderPercentage: number;
  };
  sessionTiming: Array<{
    flowId: string,
    handshakeDuration: number,  // ms
    startTime: string,
    endTime: string,
    duration: number,
    idlePeriods: Array<{
      start: string,
      end: string,
      duration: number
    }>
  }>,
  latencyMetrics: {
    rtt: {
      icmp: RTTStats,
      tcp: RTTStats,
      application: RTTStats
    },
    spikes: Array<{
      timestamp: string,
      value: number,
      protocol: string
    }>,
    retransmissionDelays: Array<{
      timestamp: string,
      delay: number,
      flowId: string
    }>;
  };
  anomalies: Array<{
    type: 'timeout' | 'delay' | 'irregular',
    timestamp: string,
    description: string,
    value: number,
    threshold: number
  }>;
  tcpHandshakes: Array<{
    flowId: string,
    details: TCPHandshakeDetails,
    isComplete: boolean,
    anomalies?: string[]
  }>;
  retransmissions: RetransmissionMetrics;
}

interface TCPHandshakeDetails {
  syn: {
    timestamp: string;
    rtt: number;
  };
  synAck: {
    timestamp: string;
    rtt: number;
  };
  ack: {
    timestamp: string;
    rtt: number;
  };
  totalDuration: number;
}

interface RetransmissionMetrics {
  count: number;
  averageDelay: number;
  maxDelay: number;
  affectedFlows: string[];
}

interface TrafficSummary {
  file_size: number;
  total_bytes: number;
  packet_count: number;
  time_range: TimeRange;
  protocol_counts: { [key: string]: number };
  packet_sizes: PacketSizes;
  ip_addresses: IPAddresses;
  protocols: string[];
  tcp_ports: number[];
  udp_ports: number[];
  dns_queries: DNSQuery[];
  packets: Packet[];
  note?: string;
  flowStats?: FlowStats[];
  icmpStats?: {
    packetTypes: {
      echoRequest: number;
      echoReply: number;
      destUnreachable: number;
      ttlExpired: number;
      other: number;
    };
    errorMessages: {
      fragmentationNeeded: number;
      redirect: number;
      other: number;
    };
    totalPackets: number;
    rttStats: {
      min: number;
      max: number;
      avg: number;
    };
    anomalies: Array<{
      type: 'HighFrequency' | 'Malformed' | 'Tunneling' | 'Other';
      description: string;
      timestamp: string;
      sourceIP: string;
      count: number;
    }>;
    bytes: number;  // Add total bytes
    packetSizeDistribution: {
      small: number;    // < 64 bytes
      medium: number;   // 64-1024 bytes
      large: number;    // > 1024 bytes
    };
    timeBasedPatterns: Array<{
      timeWindow: string;
      frequency: number;
      type: string;
    }>;
  };
  arpStats?: {
    requests: number;
    replies: number;
    unresolvedRequests: number;
    gratuitousArp: number;
    duplicateMappings: Array<{
      ip: string;
      macs: string[];
      count: number;
    }>;
    conflicts: Array<{
      ip: string;
      description: string;
      timestamp: string;
    }>;
    bytes: number;  // Add total bytes
    resolutionStats: {
      successRate: number;
      averageResolutionTime: number;
      failedResolutions: Array<{
        ip: string;
        attempts: number;
        lastAttempt: string;
      }>;
    };
    networkSegments: Array<{
      subnet: string;
      activeHosts: number;
      arpActivity: number;
    }>;
  };
  timingStats?: TimingStats;
}

interface AnalysisResults {
  trafficSummary: TrafficSummary;
}

interface ChartDatum extends BarDatum {
  x: string;
  y: number;
}

interface PointTooltipProps {
  point: {
    data: {
      x: string | number;
      y: number;
    };
  };
}

interface SizeMap {
  [key: number]: string;
}

interface ICMPPacket {
  number: number;
  source: string;
  destination: string;
  size: number;
  time?: string;
  length?: number;
}

interface UnusualICMPData {
  number: number;
  time: string;
  source: string;
  destination: string;
  size: number;
  type: 'Malformed' | 'Tunneling' | 'High Frequency';
  details: string;
}

interface ChartData {
  x: string;
  y: number;
}

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

// Add type definitions at the top of the file
interface ResizableHeaderProps {
  children: React.ReactNode;
  width: number;
  onResize: (newWidth: number) => void;
  className?: string;
}

// Move ResizableHeader component definition before it's used
const ResizableHeader: React.FC<ResizableHeaderProps> = ({ 
  children, 
  width, 
  onResize, 
  className 
}) => {
  const startResizing = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    const startX = e.pageX;
    const startWidth = width;

    const onMouseMove = (e: MouseEvent) => {
      const newWidth = Math.max(50, startWidth + (e.pageX - startX));
      onResize(newWidth);
    };

    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    };

    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
  };

  return (
    <th 
      className={`${className} relative group`} 
      style={{ width: `${width}px` }}
    >
      <div className="flex items-center">
        {children}
        <div
          className="absolute right-0 top-0 bottom-0 w-1 cursor-col-resize group-hover:bg-gray-300 hover:bg-blue-400"
          onMouseDown={startResizing}
        />
      </div>
    </th>
  );
};

// Add this configuration near the top of your component
const genAI = new GoogleGenerativeAI(process.env.NEXT_PUBLIC_GEMINI_API_KEY || '');

// Add this near your other interface definitions
interface GeminiResponse {
  text: string;
  safetyRatings: Array<{
    category: string;
    probability: string;
  }>;
}

// First, add these interfaces at the top of the file with other interfaces
interface NetworkNode {
  id: string;
  bytes: number;
  packets: number;
  color: string;
}

interface NetworkLink {
  source: string;
  target: string;
  traffic: number;
}

export default function PCAPAnalyzer() {
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [inputMessage, setInputMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [analysisResults, setAnalysisResults] = useState<AnalysisResults | null>(null)
  const [showAnalysis, setShowAnalysis] = useState(false)
  const [activeTab, setActiveTab] = useState('overview')
  const [conversationSort, setConversationSort] = useState<{
    field: 'sourceIp' | 'destinationIp' | 'protocol' | 'packetCount' | 'dataVolume' | 'duration' | null;
    direction: 'asc' | 'desc';
  }>({ field: null, direction: 'asc' });
  const [selectedProtocol, setSelectedProtocol] = useState('all');
  const [viewType, setViewType] = useState('all'); // 'all', 'source', 'destination'
  const [selectedTimeRange, setSelectedTimeRange] = useState('all');
  const [dnsQueryType, setDnsQueryType] = useState('all');
  const [dnsQueryStatus, setDnsQueryStatus] = useState('all');
  const [dnsResponseTime, setDnsResponseTime] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [timingSort, setTimingSort] = useState<{
    field: 'number' | 'time' | 'delta' | 'protocol' | null;
    direction: 'asc' | 'desc';
  }>({ field: null, direction: 'asc' });
  const packetsPerPage = 15;  // Changed from 30 to 15
  const [securityPage, setSecurityPage] = useState(0);
  const [securityMetrics, setSecurityMetrics] = useState<{
    maliciousIPs: Array<{
      ip: string;
      risk: string;
      country: string;
      timestamp: string;
      details: string;
    }>;
    portScans: Array<{
      source: string;
      target: string;
      type: string;
      timestamp: string;
      details: string;
    }>;
    highRiskPorts: Array<{
      port: number;
      protocol: string;
      count: number;
      details: string;
    }>;
    protocolMisuse: Array<{
      type: string;
      source: string;
      details: string;
      timestamp: string;
    }>;
    authFailures: Array<{
      protocol: string;
      source: string;
      target: string;
      timestamp: string;
    }>;
    encryptionIssues: Array<{
      type: string;
      details: string;
      timestamp: string;
    }>;
    c2Patterns: Array<{
      source: string;
      target: string;
      pattern: string;
      timestamp: string;
    }>;
    trafficSpikes: Array<{
      timestamp: string;
      protocol: string;
      rate: number;
      baseline: number;
    }>;
  }>({
    maliciousIPs: [],
    portScans: [],
    highRiskPorts: [],
    protocolMisuse: [],
    authFailures: [],
    encryptionIssues: [],
    c2Patterns: [],
    trafficSpikes: []
  });
  const securityItemsPerPage = 20;
  const [c2Page, setC2Page] = useState(0);
  const c2ItemsPerPage = 20;
  const [spikesPage, setSpikesPage] = useState(0);
  const spikesItemsPerPage = 20;

  // Add state for column widths near the top of the component
  const [columnWidths, setColumnWidths] = useState({
    packetNum: 100,
    time: 100,
    source: 150,
    destination: 150,
    size: 120,
    type: 100,
    details: 200
  });

  const [flowStatsPage, setFlowStatsPage] = useState(0);
  const flowStatsPerPage = 10;
  const [flowStatsSort, setFlowStatsSort] = useState<{
    field: keyof FlowStats | null;
    direction: 'asc' | 'desc';
  }>({ field: null, direction: 'asc' });

  const [topTalkersPage, setTopTalkersPage] = useState(0);
  const topTalkersPerPage = 10;

  const [dnsPage, setDnsPage] = useState(1);
  const dnsPerPage = 30;

  // Add this near other state declarations
  const [dnsSort, setDnsSort] = useState<{
    field: 'queryName' | 'queryType' | 'response' | 'status' | 'responseTime' | 'timestamp' | null;
    direction: 'asc' | 'desc';
  }>({ field: null, direction: 'asc' });

  // Add these near other state declarations
  const [httpSort, setHttpSort] = useState<{
    field: 'method' | 'url' | 'statusCode' | 'hostname' | 'contentType' | 'timestamp' | null;
    direction: 'asc' | 'desc';
  }>({ field: null, direction: 'asc' });

  const [tlsSort, setTlsSort] = useState<{
    field: 'version' | 'cipherSuite' | 'hostname' | 'certIssuer' | 'certExpiration' | null;
    direction: 'asc' | 'desc';
  }>({ field: null, direction: 'asc' });

  // Add these near other state declarations
  const [httpPage, setHttpPage] = useState(0);
  const httpPerPage = 30;

  const [tlsPage, setTlsPage] = useState(0);
  const tlsPerPage = 30;

  // Add near other sort state declarations
  const [anomaliesSort, setAnomaliesSort] = useState<{
    field: 'type' | 'sourceIp' | 'destinationIp' | 'timestamp' | 'details' | null;
    direction: 'asc' | 'desc';
  }>({ field: null, direction: 'asc' });

  const [anomaliesPage, setAnomaliesPage] = useState(0);
  const anomaliesPerPage = 10;  // Changed from 30 to 10

  // Add near other state declarations
  const [conversationPage, setConversationPage] = useState(0);
  const conversationPerPage = 20;  // Changed from 10 to 20

  const scrollAreaRef = useRef<HTMLDivElement>(null)

  const handlePrevious = () => {
    setCurrentPage(prev => Math.max(0, prev - 1));
  };

  const handleNext = () => {
    if (!analysisResults?.trafficSummary) return;
    const totalPages = Math.ceil(analysisResults.trafficSummary.packets.length / packetsPerPage);
    setCurrentPage(prev => Math.min(totalPages - 1, prev + 1));
  };

  const handleSecurityPrevious = () => {
    setSecurityPage(prev => Math.max(0, prev - 1));
  };

  const handleSecurityNext = () => {
    const totalPages = Math.ceil(securityMetrics.maliciousIPs.length / securityItemsPerPage);
    setSecurityPage(prev => Math.min(totalPages - 1, prev + 1));
  };

  const handleC2Previous = () => {
    setC2Page(prev => Math.max(0, prev - 1));
  };

  const handleC2Next = () => {
    const totalPages = Math.ceil(securityMetrics.c2Patterns.length / c2ItemsPerPage);
    setC2Page(prev => Math.min(totalPages - 1, prev + 1));
  };

  const handleSpikesPrevious = () => {
    setSpikesPage(prev => Math.max(0, prev - 1));
  };

  const handleSpikesNext = () => {
    const totalPages = Math.ceil(securityMetrics.trafficSpikes.length / spikesItemsPerPage);
    setSpikesPage(prev => Math.min(totalPages - 1, prev + 1));
  };

  const handleTopTalkersPrevious = () => {
    setTopTalkersPage(prev => Math.max(0, prev - 1));
  };

  const handleTopTalkersNext = (totalItems: number) => {
    const totalPages = Math.ceil(totalItems / topTalkersPerPage);
    setTopTalkersPage(prev => Math.min(totalPages - 1, prev + 1));
  };

  const handleDnsPrevious = () => {
    setDnsPage(prev => Math.max(1, prev - 1));
  };

  const handleDnsNext = (totalItems: number) => {
    const totalPages = Math.ceil(totalItems / dnsPerPage);
    setDnsPage(prev => Math.min(totalPages, prev + 1));
  };

  const handleHttpPrevious = () => {
    setHttpPage(prev => Math.max(0, prev - 1));
  };

  const handleHttpNext = (totalItems: number) => {
    const totalPages = Math.ceil(totalItems / httpPerPage);
    setHttpPage(prev => Math.min(totalPages - 1, prev + 1));
  };

  const handleTlsPrevious = () => {
    setTlsPage(prev => Math.max(0, prev - 1));
  };

  const handleTlsNext = (totalItems: number) => {
    const totalPages = Math.ceil(totalItems / tlsPerPage);
    setTlsPage(prev => Math.min(totalPages - 1, prev + 1));
  };

  const handleConversationPrevious = () => {
    setConversationPage(prev => Math.max(0, prev - 1));
  };

  const handleConversationNext = (totalItems: number) => {
    const totalPages = Math.ceil(totalItems / conversationPerPage);
    setConversationPage(prev => Math.min(totalPages - 1, prev + 1));
  };

  // Add useEffect hooks to clear messages after 2 seconds
  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => {
        setError(null)
      }, 2000)
      return () => clearTimeout(timer)
    }
  }, [error])

  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => {
        setSuccess(null)
      }, 2000)
      return () => clearTimeout(timer)
    }
  }, [success])

  const handleAnalysis = async () => {
    if (!file) {
      setError('No file selected')
      return
    }
    
    try {
      setIsLoading(true)
      setError(null)
      console.log('Starting analysis for file:', file.name)
      
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ fileName: file.name }),
        headers: { 'Content-Type': 'application/json' },
      })
      
      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Analysis failed')
      }
      
      const data = await response.json()
      console.log('Analysis completed successfully:', data)
      
      if (!data.trafficSummary) {
        throw new Error('Invalid analysis results')
      }

      setAnalysisResults(data)
      setShowAnalysis(true)
      setActiveTab('overview')
    } catch (err) {
      console.error('Analysis error:', err)
      setError(err instanceof Error ? err.message : 'Failed to analyze the file')
      setAnalysisResults(null)
      setShowAnalysis(false)
    } finally {
      setIsLoading(false)
    }
  }

  const handleFileUpload = async (uploadedFile: File) => {
    try {
      setFile(uploadedFile)
      setError(null)
      setAnalysisResults(null)
      setIsLoading(true)
      console.log('Starting file upload:', uploadedFile.name)

      // First upload the file
      const formData = new FormData()
      formData.append('file', uploadedFile)

      console.log('Sending upload request...')
      const uploadResponse = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
        cache: 'no-store',
        next: { revalidate: 0 },
        headers: {
          // Remove Content-Type header to let the browser set it with the boundary
          'Accept': 'application/json',
        }
      })

      console.log('Upload response received:', {
        ok: uploadResponse.ok,
        status: uploadResponse.status,
        statusText: uploadResponse.statusText
      })

      if (!uploadResponse.ok) {
        let errorMessage = `Upload failed with status ${uploadResponse.status}`
        try {
        const errorData = await uploadResponse.json()
          errorMessage = errorData.error || errorMessage
        } catch (e) {
          console.error('Failed to parse error response:', e)
        }
        throw new Error(errorMessage)
      }

      const uploadData = await uploadResponse.json()
      console.log('Upload successful:', uploadData)

      // Then analyze the file
      console.log('Starting analysis...')
      const analyzeResponse = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ fileName: uploadedFile.name }),
      })
      
      if (!analyzeResponse.ok) {
        const errorData = await analyzeResponse.json()
        throw new Error(errorData.error || 'Failed to analyze file')
      }

      const analysisData = await analyzeResponse.json()
      console.log('Analysis successful:', analysisData)

      setAnalysisResults(analysisData)
      setIsLoading(false)
    } catch (error) {
      console.error('Error:', error)
      setError(error instanceof Error ? error.message : 'An unknown error occurred')
      setIsLoading(false)
    }
  }

  const handleUploadError = (message: string) => {
    setError(message)
    setSuccess(null)
  }

  const handleUploadSuccess = (message: string) => {
    setSuccess(message)
    setError(null)
    setTimeout(() => setSuccess(null), 5000)
  }

  const handleSaveChat = async (messageId: string) => {
    try {
      const chatToSave = messages.slice(0, messages.findIndex(m => m.id === messageId) + 1);
      
      // Create markdown content
      const markdownContent = `# PCAP Analysis Chat - ${new Date().toLocaleDateString()}

${chatToSave.map(message => {
  const timestamp = new Date(message.timestamp).toLocaleString();
  const role = message.role === 'user' ? '👤 User' : '🤖 Assistant';
  return `## ${role} - ${timestamp}\n\n${message.content}\n`;
}).join('\n---\n\n')}
`;
      
      // Create and download markdown file
      const blob = new Blob([markdownContent], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `pcap-analysis-chat-${new Date().toISOString().split('T')[0]}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      // Show success message
      setSuccess('Chat saved successfully');
    } catch (err) {
      console.error('Error saving chat:', err);
      setError('Failed to save chat');
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputMessage.trim() || !file || !analysisResults) return;

    const newMessage: ChatMessage = {
      role: 'user',
      content: inputMessage.trim(),
      timestamp: new Date().toISOString(),
      id: crypto.randomUUID()
    };

    setMessages(prev => [...prev, newMessage]);
    setInputMessage('');
    setIsLoading(true);
    setError(null);

    try {
      // Initialize the model
      const model = genAI.getGenerativeModel({ model: "gemini-pro" });

      // Create context from PCAP analysis
      const pcapContext = createPcapContext(analysisResults.trafficSummary);
      
      // Extract keywords from user's question to determine relevant context
      const question = inputMessage.toLowerCase();
      let relevantContext = '';

      // Add relevant sections based on the question
      if (question.includes('dns') || question.includes('domain')) {
        relevantContext += pcapContext.split('DNS Activity:')[1]?.split(/(?=\w+ Statistics:)/)[0] || '';
      }
      if (question.includes('flow') || question.includes('connection') || question.includes('traffic')) {
        relevantContext += pcapContext.split('Flow Statistics:')[1]?.split(/(?=\w+ Statistics:)/)[0] || '';
      }
      if (question.includes('performance') || question.includes('latency') || question.includes('rtt')) {
        relevantContext += pcapContext.split('Performance Metrics:')[1]?.split(/(?=\w+ Statistics:)/)[0] || '';
      }
      if (question.includes('icmp') || question.includes('ping')) {
        relevantContext += pcapContext.split('ICMP Statistics:')[1]?.split(/(?=\w+ Statistics:)/)[0] || '';
      }
      if (question.includes('arp')) {
        relevantContext += pcapContext.split('ARP Statistics:')[1]?.split(/(?=\w+ Statistics:)/)[0] || '';
      }

      // Always include basic file and network information
      const basicInfo = pcapContext.split('Network Overview:')[0] || '';
      relevantContext = basicInfo + (relevantContext || pcapContext.split('Network Overview:')[1]?.split('DNS Activity:')[0] || '');

      // Combine context with user's question
      const prompt = `
        PCAP Analysis Context:
        ${relevantContext.trim()}

        User Question: ${inputMessage}

        Please provide a detailed analysis based on this PCAP data, focusing specifically on answering the user's question.
      `.trim();

      // Send message with context
      const result = await model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();

      const assistantMessage: ChatMessage = {
        role: 'assistant',
        content: text,
        timestamp: new Date().toISOString(),
        id: crypto.randomUUID()
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      console.error('Error getting response from Gemini:', err);
      setError(err instanceof Error ? err.message : 'Failed to get response from the assistant');
    } finally {
      setIsLoading(false);
    }
  };

  // Add this helper function to create context from PCAP analysis
  const createPcapContext = (summary: TrafficSummary): string => {
    // Create a concise summary focusing on the most important information
    return `
      File Information:
      - Size: ${formatBytes(summary.file_size)}
      - Total Packets: ${summary.packet_count}
      - Time Range: ${summary.time_range.start} to ${summary.time_range.end}
      - Duration: ${formatDuration(summary.time_range.duration)}

      Network Overview:
      - Total Traffic Volume: ${formatBytes(summary.total_bytes)}
      - Unique Source IPs: ${summary.ip_addresses.source.length}
      - Unique Destination IPs: ${summary.ip_addresses.destination.length}
      - Active Protocols: ${summary.protocols.join(', ')}

      Packet Statistics:
      - Average Size: ${formatBytes(summary.packet_sizes.average)}
      - Min Size: ${formatBytes(summary.packet_sizes.min)}
      - Max Size: ${formatBytes(summary.packet_sizes.max)}

      ${summary.dns_queries.length > 0 ? `
      DNS Activity:
      - Total Queries: ${summary.dns_queries.length}
      - Top Queries: ${summary.dns_queries.slice(0, 5).map(q => q.query).join(', ')}
      ` : ''}

      ${summary.flowStats ? `
      Flow Statistics:
      - Total Flows: ${summary.flowStats.length}
      - Notable Issues: ${summary.flowStats.filter(f => f.retransmissionCount > 0).length} flows with retransmissions
      ` : ''}

      ${summary.timingStats ? `
      Performance Metrics:
      - Average TCP RTT: ${summary.timingStats.latencyMetrics.rtt.tcp.average.toFixed(2)}ms
      - Retransmissions: ${summary.timingStats.retransmissions.count}
      - Out of Order Packets: ${summary.timingStats.packetOrder.outOfOrderCount}
      ` : ''}

      ${summary.icmpStats ? `
      ICMP Statistics:
      - Total ICMP Packets: ${summary.icmpStats.totalPackets}
      - Echo Requests/Replies: ${summary.icmpStats.packetTypes.echoRequest}/${summary.icmpStats.packetTypes.echoReply}
      - Errors: ${summary.icmpStats.packetTypes.destUnreachable + summary.icmpStats.packetTypes.ttlExpired}
      ` : ''}

      ${summary.arpStats ? `
      ARP Statistics:
      - Requests: ${summary.arpStats.requests}
      - Replies: ${summary.arpStats.replies}
      - Unresolved: ${summary.arpStats.unresolvedRequests}
      ` : ''}
    `.trim().replace(/\n\s+/g, '\n').replace(/\n{3,}/g, '\n\n');
  }

  const renderOverview = () => {
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Overview Analysis</h3>
          <div className="text-sm text-gray-500">
            No analysis results available.
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;
    const networkData = processNetworkData(summary.packets);
    const safeData = {
      file_size: summary.file_size || 0,
      total_bytes: summary.total_bytes || 0,
      packet_count: summary.packet_count || 0,
      time_range: {
        start: summary.time_range?.start,
        end: summary.time_range?.end,
        duration: summary.time_range?.duration || 0,
        file_created: summary.time_range?.file_created,
        file_modified: summary.time_range?.file_modified
      },
      packet_sizes: {
        min: summary.packet_sizes?.min || 0,
        max: summary.packet_sizes?.max || 0,
        average: summary.packet_sizes?.average || 0
      },
      ip_addresses: {
        source: summary.ip_addresses?.source || [],
        destination: summary.ip_addresses?.destination || []
      }
    };

    return (
      <Card className="p-4">
        <h3 className="text-lg font-semibold mb-4">Overview Analysis</h3>
        <div className="space-y-6">
          {/* Overview Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-medium mb-2">Summary</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex justify-between">
                  <span className="text-gray-600">File Size:</span>
                  <span className="font-medium">{formatBytes(safeData.file_size)}</span>
                </li>
                <li className="flex justify-between">
                  <span className="text-gray-600">Total Packets:</span>
                  <span className="font-medium">{safeData.packet_count.toLocaleString()}</span>
                </li>
                <li className="flex flex-col">
                  <span className="text-gray-600 mb-1">Time Range:</span>
                  <div className="ml-4 space-y-1">
                    {safeData.time_range.start && (
                      <div className="flex justify-between">
                        <span className="text-gray-500">First Packet:</span>
                        <span className="font-medium">{new Date(safeData.time_range.start).toLocaleString()}</span>
          </div>
                    )}
                    {safeData.time_range.end && (
                      <div className="flex justify-between">
                        <span className="text-gray-500">Last Packet:</span>
                        <span className="font-medium">{new Date(safeData.time_range.end).toLocaleString()}</span>
          </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-gray-500">Duration:</span>
                      <span className="font-medium">{formatDuration(safeData.time_range.duration)}</span>
          </div>
                  </div>
                </li>
                <li className="flex justify-between">
                  <span className="text-gray-600">Unique Source IPs:</span>
                  <span className="font-medium">{safeData.ip_addresses.source.length}</span>
                </li>
                <li className="flex justify-between">
                  <span className="text-gray-600">Unique Destination IPs:</span>
                  <span className="font-medium">{safeData.ip_addresses.destination.length}</span>
                </li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-2">Packet Sizes</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex justify-between">
                  <span className="text-gray-600">Minimum:</span>
                  <span className="font-medium">{safeData.packet_sizes.min.toLocaleString()} bytes</span>
                </li>
                <li className="flex justify-between">
                  <span className="text-gray-600">Maximum:</span>
                  <span className="font-medium">{safeData.packet_sizes.max.toLocaleString()} bytes</span>
                </li>
                <li className="flex justify-between">
                  <span className="text-gray-600">Average:</span>
                  <span className="font-medium">{safeData.packet_sizes.average.toFixed(2)} bytes</span>
                </li>
                <li className="flex justify-between">
                  <span className="text-gray-600">Total Bytes:</span>
                  <span className="font-medium">{formatBytes(safeData.total_bytes)}</span>
                </li>
              </ul>
            </div>
          </div>

          {/* Network Graph */}
          <div className="h-[750px] bg-white rounded-lg shadow p-4">
            <h4 className="text-md font-medium mb-2">Network Traffic Graph</h4>
            <div className="h-[700px]" suppressHydrationWarning>
              <NetworkGraphNoSSR data={networkData} />
            </div>
          </div>

          {summary.note && (
            <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-md text-yellow-800">
              <p className="text-sm whitespace-pre-line">{summary.note}</p>
            </div>
          )}
        </div>
      </Card>
    );
  };

  // Data processing functions
  const processNetworkData = (packets: Packet[]) => {
    const nodes = new Map<string, NetworkNode>();
    const links = new Map<string, NetworkLink>();

    packets.forEach(packet => {
      if (!packet.source || !packet.destination) return;

      // Add nodes
      if (!nodes.has(packet.source)) {
        nodes.set(packet.source, {
          id: packet.source,
          bytes: 0,
          packets: 0,
          color: isInternalIP(packet.source) ? '#e63946' : '#457b9d'
        });
      }

      if (!nodes.has(packet.destination)) {
        nodes.set(packet.destination, {
          id: packet.destination,
          bytes: 0,
          packets: 0,
          color: isInternalIP(packet.destination) ? '#e63946' : '#457b9d'
        });
      }

      // Update node statistics
      const sourceNode = nodes.get(packet.source);
      const destNode = nodes.get(packet.destination);
      
      if (sourceNode && destNode) {
        sourceNode.bytes += packet.length;
        sourceNode.packets += 1;
        destNode.bytes += packet.length;
        destNode.packets += 1;

        // Add or update link
        const linkId = `${packet.source}-${packet.destination}`;
        if (!links.has(linkId)) {
          links.set(linkId, {
            source: packet.source,
            target: packet.destination,
            traffic: 0
          });
        }
        
        const link = links.get(linkId);
        if (link) {
          link.traffic += packet.length;
        }
      }
    });

    return {
      nodes: Array.from(nodes.values()),
      links: Array.from(links.values())
    };
  };

  // Helper function to determine if IP is internal
  const isInternalIP = (ip: string): boolean => {
    // Add logic to determine internal IPs based on your network
    return ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.');
  };

  // Add other data processing functions...

  const renderProtocols = () => {
    if (!analysisResults?.trafficSummary?.protocol_counts) {
      console.log('No protocol data available')
      return null
    }
    
    const summary = analysisResults.trafficSummary
    console.log('Rendering protocols with data:', summary.protocol_counts)
    
    const totalProtocolCount = Object.values(summary.protocol_counts).reduce((a: number, b: number) => a + b, 0);
    const topProtocols = Object.entries(summary.protocol_counts)
      .map(([protocol, count]: [string, number]) => ({
        protocol,
        count,
        percentage: ((count / totalProtocolCount) * 100).toFixed(1)
      }))
      .sort((a, b) => b.count - a.count); // Sort by count in descending order

    return (
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
                {protocol.count.toLocaleString()} packets ({protocol.percentage}%)
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
    );
  };

  const renderPorts = () => {
    if (!analysisResults?.trafficSummary) {
      console.log('No port data available')
      return null
    }
    
    const summary = analysisResults.trafficSummary
    console.log('Rendering ports with data:', { tcp: summary.tcp_ports, udp: summary.udp_ports })
    
    const tcpPorts = summary.tcp_ports || [];
    const udpPorts = summary.udp_ports || [];

    // Function to create port rows with service names
    const createPortRows = (ports: number[]) => {
      return ports
        .sort((a, b) => a - b)
        .map(port => ({
          port,
          service: getCommonPortName(port)
        }));
    };

    const tcpRows = createPortRows(tcpPorts);
    const udpRows = createPortRows(udpPorts);

    return (
      <Card className="p-4">
        <h3 className="text-lg font-semibold mb-4">Port Analysis</h3>
        <div className="grid grid-cols-2 gap-4">
          {/* TCP Ports Table */}
          <div>
            <h4 className="font-medium mb-2">TCP Ports ({tcpPorts.length})</h4>
            <div className="border rounded-md">
              <ScrollArea className="h-[750px]">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50 sticky top-0 z-10">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Port</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Service</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {tcpRows.map(({ port, service }, index) => (
                      <tr key={port} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-900">Port {port}</td>
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500">
                          {service ? (
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                              {service}
                            </span>
                          ) : (
                            <a 
                              href={`https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-500 hover:text-blue-700 hover:underline flex items-center gap-1"
                            >
                              <span>IANA Registry</span> <span>🌐</span>
                            </a>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </ScrollArea>
            </div>
          </div>

          {/* UDP Ports Table */}
          <div>
            <h4 className="font-medium mb-2">UDP Ports ({udpPorts.length})</h4>
            <div className="border rounded-md">
              <ScrollArea className="h-[750px]">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50 sticky top-0 z-10">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Port</th>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Service</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {udpRows.map(({ port, service }, index) => (
                      <tr key={port} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-900">Port {port}</td>
                        <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500">
                          {service ? (
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                              {service}
                            </span>
                          ) : (
                            <a 
                              href={`https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-500 hover:text-blue-700 hover:underline flex items-center gap-1"
                            >
                              <span>IANA Registry</span> <span>🌐</span>
                            </a>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </ScrollArea>
            </div>
          </div>
        </div>
      </Card>
    );
  };

  const renderDNS = () => {
    if (!analysisResults?.trafficSummary?.dns_queries) {
      console.log('No DNS data available')
      return null
    }
    
    const summary = analysisResults.trafficSummary
    console.log('Rendering DNS with data:', summary.dns_queries)
    
    return (
      <Card className="p-4">
        <h3 className="text-lg font-semibold mb-4">DNS Queries ({summary.dns_queries.length})</h3>
        <ScrollArea className="h-[400px] rounded-md border p-2">
          <div className="space-y-2">
            {summary.dns_queries.length > 0 ? (
              summary.dns_queries.map((query: DNSQuery, index: number) => (
                <div key={index} className="text-sm bg-gray-50 p-3 rounded">
                  <div className="font-medium">{query.query}</div>
                  <div className="text-gray-600 text-xs mt-1">
                    <div className="flex items-center gap-2">
                      <span className="bg-blue-100 text-blue-800 px-2 py-0.5 rounded">
                        {query.type}
                      </span>
                      {query.ttl && (
                        <span className="text-gray-500">
                          TTL: {query.ttl}s
                        </span>
                      )}
                    </div>
                    {query.responses && query.responses.length > 0 && (
                      <div className="mt-2">
                        <div className="font-medium text-gray-700">Responses:</div>
                        <ul className="list-disc pl-4 mt-1 space-y-1">
                          {query.responses.map((response, idx) => (
                            <li key={idx}>{response}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-sm text-gray-500 p-2">No DNS queries found</div>
            )}
          </div>
        </ScrollArea>
      </Card>
    );
  };

  const renderPackets = () => {
    if (!analysisResults?.trafficSummary?.packets) {
      console.log('No packet data available')
      return null
    }
    
    const summary = analysisResults.trafficSummary
    console.log('Rendering packets with data:', summary.packets)
    
    return (
      <Card className="p-4">
        <h3 className="text-lg font-semibold mb-4">Packet Content</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">No.</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Src Port</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Dst Port</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Length</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Info</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {summary.packets.map((packet) => (
                <tr key={packet.number} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.number}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {packet.time ? new Date(packet.time).toLocaleTimeString() : ''}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.source}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.srcPort}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.destination}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.dstPort}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.protocol}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{packet.length}</td>
                  <td className="px-6 py-4 text-sm text-gray-500 max-w-md truncate">{packet.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    );
  };

  const formatDuration = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainingSeconds = seconds % 60;
    
    const parts = [];
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (remainingSeconds > 0 || parts.length === 0) parts.push(`${remainingSeconds.toFixed(1)}s`);
    
    return parts.join(' ');
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'] as const;
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const getCommonPortName = (port: number): string => {
    const commonPorts: { [key: number]: string } = {
      // System Ports (0-1023)
      0: 'Reserved',
      1: 'TCPMUX',
      7: 'Echo Protocol',
      9: 'Wake-on-LAN/Discard',
      13: 'Daytime Protocol',
      17: 'QOTD (Quote of the Day)',
      19: 'CHARGEN',
      20: 'FTP Data Transfer',
      21: 'FTP Control',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      26: 'RSFTP',
      37: 'Time Protocol',
      43: 'WHOIS',
      49: 'TACACS',
      53: 'DNS',
      67: 'DHCP/BOOTP Server',
      68: 'DHCP/BOOTP Client',
      69: 'TFTP',
      70: 'Gopher',
      79: 'Finger',
      80: 'HTTP',
      81: 'TorPark',
      82: 'TorPark Control',
      88: 'Kerberos',
      109: 'POP2',
      110: 'POP3',
      111: 'RPCbind/SUN RPC',
      113: 'Ident/Auth',
      119: 'NNTP',
      123: 'NTP',
      135: 'Microsoft EPMAP',
      137: 'NetBIOS Name Service',
      138: 'NetBIOS Datagram',
      139: 'NetBIOS Session',
      143: 'IMAP',
      161: 'SNMP',
      162: 'SNMP Trap',
      179: 'BGP',
      194: 'IRC',
      389: 'LDAP',
      443: 'HTTPS',
      445: 'Microsoft-DS (SMB)',
      464: 'Kerberos Change/Set Password',
      465: 'SMTP over TLS/SSL',
      500: 'ISAKMP/IKE',
      502: 'Modbus',
      514: 'Shell/Syslog',
      515: 'LPD/LPR',
      520: 'RIP',
      546: 'DHCPv6 Client',
      547: 'DHCPv6 Server',
      587: 'SMTP Submission',
      631: 'IPP',
      636: 'LDAPS',
      873: 'rsync',
      989: 'FTPS Data',
      990: 'FTPS Control',
      993: 'IMAPS',
      995: 'POP3S',

      // Registered Ports (1024-49151)
      1080: 'SOCKS Proxy',
      1194: 'OpenVPN',
      1433: 'MS SQL',
      1434: 'MS SQL Monitor',
      1521: 'Oracle DB',
      1701: 'L2TP',
      1723: 'PPTP',
      1812: 'RADIUS Auth',
      1813: 'RADIUS Accounting',
      1883: 'MQTT',
      1900: 'SSDP/UPnP',
      2049: 'NFS',
      2082: 'cPanel',
      2083: 'cPanel SSL',
      2086: 'WHM',
      2087: 'WHM SSL',
      2375: 'Docker',
      2376: 'Docker SSL',
      3128: 'Squid Proxy',
      3306: 'MySQL',
      3389: 'RDP',
      3690: 'SVN',
      4369: 'RabbitMQ',
      5060: 'SIP',
      5061: 'SIP TLS',
      5222: 'XMPP Client',
      5223: 'XMPP Client SSL',
      5228: 'Android Market',
      5432: 'PostgreSQL',
      5671: 'AMQP SSL',
      5672: 'AMQP',
      5900: 'VNC',
      5938: 'TeamViewer',
      6379: 'Redis',
      6443: 'Kubernetes API',
      6514: 'Syslog TLS',
      6881: 'BitTorrent',
      8080: 'HTTP Alternate',
      8443: 'HTTPS Alternate',
      8883: 'MQTT SSL',
      9000: 'Portainer',
      9090: 'Prometheus',
      9200: 'Elasticsearch HTTP',
      9300: 'Elasticsearch Transport',
      11211: 'Memcached',
      27017: 'MongoDB',
      27018: 'MongoDB Shard',
      27019: 'MongoDB Config',
      49150: 'Inspider',
      49151: 'Reserved'
    };

    return commonPorts[port] || '';
  };

  const renderConversation = () => {
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Conversation Analysis</h3>
          <div className="text-sm text-gray-500">
            No analysis results available.
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;
    console.log('Rendering conversation with data:', summary);

    // Extract unique conversations from packets
    const conversations = new Map();
    summary.packets.forEach(packet => {
      if (packet.source && packet.destination) {
        const key = `${packet.source}-${packet.destination}`;
        if (!conversations.has(key)) {
          conversations.set(key, {
            sourceIp: packet.source,
            destinationIp: packet.destination,
            protocol: packet.protocol,
            packetCount: 1,
            dataVolume: packet.length,
            firstPacket: new Date(packet.time || 0),
            lastPacket: new Date(packet.time || 0),
            hasErrors: false,
            hasRetransmissions: false
          });
        } else {
          const conv = conversations.get(key);
          conv.packetCount++;
          conv.dataVolume += packet.length;
          if (packet.time) {
            const packetTime = new Date(packet.time);
            if (packetTime < conv.firstPacket) conv.firstPacket = packetTime;
            if (packetTime > conv.lastPacket) conv.lastPacket = packetTime;
          }
        }
      }
    });

    const conversationList = Array.from(conversations.values()).map(conv => ({
      ...conv,
      duration: (conv.lastPacket.getTime() - conv.firstPacket.getTime()) / 1000
    }));

    // Add the handleConversationSort function in the renderConversation function
    const handleConversationSort = (field: 'sourceIp' | 'destinationIp' | 'protocol' | 'packetCount' | 'dataVolume' | 'duration') => {
      setConversationSort(prev => ({
        field,
        direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
      }));
    };

    // Sort conversations based on current sort settings
    const sortedConversations = [...conversationList].sort((a, b) => {
      if (!conversationSort.field) return 0;
      
      const direction = conversationSort.direction === 'asc' ? 1 : -1;
      
      switch (conversationSort.field) {
        case 'sourceIp':
          return (a.sourceIp.localeCompare(b.sourceIp)) * direction;
        case 'destinationIp':
          return (a.destinationIp.localeCompare(b.destinationIp)) * direction;
        case 'protocol':
          return (a.protocol.localeCompare(b.protocol)) * direction;
        case 'packetCount':
          return (a.packetCount - b.packetCount) * direction;
        case 'dataVolume':
          return (a.dataVolume - b.dataVolume) * direction;
        case 'duration':
          return (a.duration - b.duration) * direction;
        default:
      return 0;
      }
    });

    // Calculate pagination values
    const startIndex = conversationPage * conversationPerPage;
    const endIndex = startIndex + conversationPerPage;
    const totalPages = Math.ceil(sortedConversations.length / conversationPerPage);

    return (
      <Card className="p-4">
        <h3 className="text-lg font-semibold mb-4">Conversation Analysis</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th 
                  scope="col" 
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                  onClick={() => handleConversationSort('sourceIp')}
                >
                  <div className="flex items-center space-x-1">
                    <span>Source IP</span>
                    <ChevronUpIcon 
                      className={`h-4 w-4 ${conversationSort.field === 'sourceIp' ? (conversationSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                    />
                  </div>
                </th>
                <th 
                  scope="col" 
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                  onClick={() => handleConversationSort('destinationIp')}
                >
                  <div className="flex items-center space-x-1">
                    <span>Destination IP</span>
                    <ChevronUpIcon 
                      className={`h-4 w-4 ${conversationSort.field === 'destinationIp' ? (conversationSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                    />
                  </div>
                </th>
                <th 
                  scope="col" 
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                  onClick={() => handleConversationSort('protocol')}
                >
                  <div className="flex items-center space-x-1">
                    <span>Protocol</span>
                    <ChevronUpIcon 
                      className={`h-4 w-4 ${conversationSort.field === 'protocol' ? (conversationSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                    />
                  </div>
                </th>
                <th 
                  scope="col" 
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                  onClick={() => handleConversationSort('packetCount')}
                >
                  <div className="flex items-center space-x-1">
                    <span>Packet Count</span>
                    <ChevronUpIcon 
                      className={`h-4 w-4 ${conversationSort.field === 'packetCount' ? (conversationSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                    />
                  </div>
                </th>
                <th 
                  scope="col" 
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                  onClick={() => handleConversationSort('dataVolume')}
                >
                  <div className="flex items-center space-x-1">
                    <span>Data Volume</span>
                    <ChevronUpIcon 
                      className={`h-4 w-4 ${conversationSort.field === 'dataVolume' ? (conversationSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                    />
                  </div>
                </th>
                <th 
                  scope="col" 
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                  onClick={() => handleConversationSort('duration')}
                >
                  <div className="flex items-center space-x-1">
                    <span>Duration</span>
                    <ChevronUpIcon 
                      className={`h-4 w-4 ${conversationSort.field === 'duration' ? (conversationSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                    />
                  </div>
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {sortedConversations.slice(startIndex, endIndex).map((conversation, index) => (
                <tr 
                  key={index}
                  className={`${
                    conversation.hasErrors || conversation.hasRetransmissions 
                      ? 'bg-red-50 hover:bg-red-100' 
                      : 'hover:bg-gray-50'
                  }`}
                >
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{conversation.sourceIp}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{conversation.destinationIp}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{conversation.protocol}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{conversation.packetCount.toLocaleString()}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{formatBytes(conversation.dataVolume)}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{formatDuration(conversation.duration)}</td>
                </tr>
              ))}
              {sortedConversations.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-4 text-center text-sm text-gray-500">
                    No conversations found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex justify-between items-center mt-4">
          <div className="text-sm text-gray-500">
            Showing {startIndex + 1} to {Math.min(endIndex, sortedConversations.length)} of {sortedConversations.length}
          </div>
          <div className="flex items-center space-x-4">
            <Button
              variant="outline"
              onClick={handleConversationPrevious}
              disabled={conversationPage === 0}
            >
              Previous
            </Button>
            <span className="text-sm text-gray-500">
              Page {conversationPage + 1} of {totalPages}
            </span>
            <Button
              variant="outline"
              onClick={() => handleConversationNext(sortedConversations.length)}
              disabled={conversationPage >= totalPages - 1}
            >
              Next
            </Button>
          </div>
        </div>
      </Card>
    );
  };

  const renderFlowStats = () => {
    if (!analysisResults?.trafficSummary?.flowStats) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Flow Statistics Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze flow statistics.</p>
          </div>
        </Card>
      );
    }

    const flowStats = analysisResults.trafficSummary.flowStats;

    // Prepare data for RTT and throughput trends (keep existing chart data preparation)
    const rttData: ChartData[] = flowStats
      .filter((flow: FlowStats) => flow.rttStats)
      .map((flow: FlowStats) => ({
        x: `${flow.sourceIp} → ${flow.destinationIp}`,
        y: flow.rttStats?.average || 0
      }));

    const throughputData: ChartData[] = flowStats.map((flow: FlowStats) => ({
      x: `${flow.sourceIp} → ${flow.destinationIp}`,
      y: flow.throughput || 0
    }));

    // Sort flow stats based on current sort settings
    const sortedFlowStats = [...flowStats].sort((a, b) => {
      if (!flowStatsSort.field) return 0;
      
      const aValue = a[flowStatsSort.field];
      const bValue = b[flowStatsSort.field];
      
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return flowStatsSort.direction === 'asc' ? aValue - bValue : bValue - aValue;
      }
      
      if (typeof aValue === 'string' && typeof bValue === 'string') {
        return flowStatsSort.direction === 'asc' ? 
          aValue.localeCompare(bValue) : 
          bValue.localeCompare(aValue);
      }
      
      return 0;
    });

    // Calculate pagination values
    const startIndex = flowStatsPage * flowStatsPerPage;
    const endIndex = startIndex + flowStatsPerPage;
    const totalPages = Math.ceil(sortedFlowStats.length / flowStatsPerPage);
    const currentFlowStats = sortedFlowStats.slice(startIndex, endIndex);

    const handleFlowStatsSort = (field: keyof FlowStats) => {
      setFlowStatsSort(prev => ({
        field,
        direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
      }));
    };

    return (
      <div className="space-y-6">
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Flow Statistics</h3>
          <div className="overflow-x-auto">
            <div className="max-h-[600px] overflow-y-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleFlowStatsSort('sourceIp')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Source IP</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${flowStatsSort.field === 'sourceIp' ? (flowStatsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleFlowStatsSort('destinationIp')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Destination IP</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${flowStatsSort.field === 'destinationIp' ? (flowStatsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleFlowStatsSort('protocol')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Protocol</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${flowStatsSort.field === 'protocol' ? (flowStatsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">
                      TCP Handshake Status
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleFlowStatsSort('retransmissionCount')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Retransmissions</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${flowStatsSort.field === 'retransmissionCount' ? (flowStatsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleFlowStatsSort('throughput')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Throughput (B/s)</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${flowStatsSort.field === 'throughput' ? (flowStatsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {currentFlowStats.map((flow: FlowStats, index: number) => (
                    <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {flow.sourceIp}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {flow.destinationIp}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {flow.protocol}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        {flow.handshakeStatus ? (
                          <div className="space-y-1">
                            <div className={`text-xs ${flow.handshakeStatus.syn !== 'X' ? 'text-green-600' : 'text-red-600'}`}>
                              SYN: {flow.handshakeStatus.syn || 'X'}
                            </div>
                            <div className={`text-xs ${flow.handshakeStatus.synAck !== 'X' ? 'text-green-600' : 'text-red-600'}`}>
                              SYN-ACK: {flow.handshakeStatus.synAck || 'X'}
                            </div>
                            <div className={`text-xs ${flow.handshakeStatus.ack !== 'X' ? 'text-green-600' : 'text-red-600'}`}>
                              ACK: {flow.handshakeStatus.ack || 'X'}
                            </div>
                          </div>
                        ) : (
                          <span className="text-gray-500">N/A</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {flow.retransmissionCount}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {(flow.throughput || 0).toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex justify-between items-center mt-4">
              <div className="text-sm text-gray-500">
                Showing flows {startIndex + 1} to {Math.min(endIndex, flowStats.length)} of {flowStats.length}
              </div>
              <div className="flex items-center space-x-4">
                <Button
                  variant="outline"
                  onClick={() => setFlowStatsPage(prev => Math.max(0, prev - 1))}
                  disabled={flowStatsPage === 0}
                >
                  Previous
                </Button>
                <span className="text-sm text-gray-500">
                  Page {flowStatsPage + 1} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  onClick={() => setFlowStatsPage(prev => Math.min(totalPages - 1, prev + 1))}
                  disabled={flowStatsPage >= totalPages - 1}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="p-4">
            <h4 className="text-md font-semibold mb-4">RTT Distribution</h4>
            <div className="h-64">
              {rttData.length > 0 ? (
                <ResponsiveBar
                  data={rttData}
                  keys={['y']}
                  indexBy="x"
                  margin={{ top: 10, right: 10, bottom: 40, left: 60 }}
                  padding={0.3}
                  valueScale={{ type: 'linear' }}
                  indexScale={{ type: 'band', round: true }}
                  colors={{ scheme: 'nivo' }}
                  axisBottom={{
                    tickRotation: -45,
                    truncateTickAt: 20
                  }}
                  axisLeft={{
                    tickSize: 5,
                    tickPadding: 5,
                    tickRotation: 0,
                    legend: 'RTT (ms)',
                    legendPosition: 'middle',
                    legendOffset: -50
                  }}
                  tooltip={({ data }: BarTooltipProps<{ x: string; y: number }>) => (
                    <div className="bg-white p-2 shadow rounded border">
                      <strong>{`${data.x}`}</strong>: {data.y.toFixed(2)}ms
                    </div>
                  )}
                />
              ) : (
                <div className="h-full flex items-center justify-center text-gray-500">
                  No RTT data available
                </div>
              )}
            </div>
          </Card>

          <Card className="p-4">
            <h4 className="text-md font-semibold mb-4">Throughput Distribution</h4>
            <div className="h-64">
              {throughputData.length > 0 ? (
                <ResponsiveBar
                  data={throughputData}
                  keys={['y']}
                  indexBy="x"
                  margin={{ top: 10, right: 10, bottom: 40, left: 60 }}
                  padding={0.3}
                  valueScale={{ type: 'linear' }}
                  indexScale={{ type: 'band', round: true }}
                  colors={{ scheme: 'nivo' }}
                  axisBottom={{
                    tickRotation: -45,
                    truncateTickAt: 20
                  }}
                  axisLeft={{
                    tickSize: 5,
                    tickPadding: 5,
                    tickRotation: 0,
                    legend: 'Throughput (B/s)',
                    legendPosition: 'middle',
                    legendOffset: -50
                  }}
                  tooltip={({ data }: BarTooltipProps<{ x: string; y: number }>) => (
                    <div className="bg-white p-2 shadow rounded border">
                      <strong>{`${data.x}`}</strong>: {formatBytes(data.y)}/s
                    </div>
                  )}
                />
              ) : (
                <div className="h-full flex items-center justify-center text-gray-500">
                  No throughput data available
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>
    );
  };

  const renderTopTalkers = () => {
    // Handle loading state
    if (isLoading) {
      return (
        <Card className="p-4">
          <div className="flex flex-col items-center justify-center space-y-4">
            <Loader2 className="h-8 w-8 animate-spin" />
            <p className="text-sm text-gray-500">Analyzing network traffic data...</p>
          </div>
        </Card>
      );
    }

    // Handle no file selected
    if (!file) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze network traffic.</p>
          </div>
        </Card>
      );
    }

    // Handle missing analysis results
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">Analysis Results Not Available</h3>
            <p className="text-sm text-gray-500">
              Unable to analyze network traffic. Please try analyzing the file again.
            </p>
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;
    
    // Handle empty packet data
    if (!summary.packets || summary.packets.length === 0) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Packet Data</h3>
            <p className="text-sm text-gray-500">
              No network packets found in the capture file.
            </p>
          </div>
        </Card>
      );
    }

    // Process IP statistics
    const ipStats = new Map();
    try {
      summary.packets.forEach(packet => {
        // Process source IP
        if (packet.source) {
          if (!ipStats.has(packet.source)) {
            ipStats.set(packet.source, {
              ip: packet.source,
              packetsSent: 0,
              packetsReceived: 0,
              bytesSent: 0,
              bytesReceived: 0,
              protocols: new Set()
            });
          }
          const sourceStats = ipStats.get(packet.source);
          sourceStats.packetsSent++;
          sourceStats.bytesSent += packet.length;
          sourceStats.protocols.add(packet.protocol);
        }

        // Process destination IP
        if (packet.destination) {
          if (!ipStats.has(packet.destination)) {
            ipStats.set(packet.destination, {
              ip: packet.destination,
              packetsSent: 0,
              packetsReceived: 0,
              bytesSent: 0,
              bytesReceived: 0,
              protocols: new Set()
            });
          }
          const destStats = ipStats.get(packet.destination);
          destStats.packetsReceived++;
          destStats.bytesReceived += packet.length;
          destStats.protocols.add(packet.protocol);
        }
      });
    } catch (error) {
      console.error('Error processing packet data:', error);
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">Data Processing Error</h3>
            <p className="text-sm text-gray-500">
              An error occurred while processing the network data. Please try again.
            </p>
          </div>
        </Card>
      );
    }

    // Convert to array and calculate totals
    const ipStatsArray = Array.from(ipStats.values()).map(stats => ({
      ...stats,
      totalPackets: stats.packetsSent + stats.packetsReceived,
      totalBytes: stats.bytesSent + stats.bytesReceived,
      protocols: Array.from(stats.protocols)
    }));

    // Handle no IP data
    if (ipStatsArray.length === 0) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No IP Data</h3>
            <p className="text-sm text-gray-500">
              No IP address information found in the capture file.
            </p>
          </div>
        </Card>
      );
    }

    // Sort IPs based on view type
    let sortedIPs = [...ipStatsArray];
    if (viewType === 'source') {
      sortedIPs = sortedIPs
        .filter(ip => ip.packetsSent > 0)
        .sort((a, b) => b.bytesSent - a.bytesSent);
    } else if (viewType === 'destination') {
      sortedIPs = sortedIPs
        .filter(ip => ip.packetsReceived > 0)
        .sort((a, b) => b.bytesReceived - a.bytesReceived);
    } else {
      sortedIPs = sortedIPs.sort((a, b) => b.totalBytes - a.totalBytes);
    }

    // Get unique protocols for filter
    const uniqueProtocols = Array.from(
      new Set(sortedIPs.flatMap(ip => ip.protocols))
    ).sort();

    // Apply protocol filter
    const filteredIPs = sortedIPs.filter(ip => 
      selectedProtocol === 'all' || ip.protocols.includes(selectedProtocol)
    );

    // Calculate pagination values
    const startIndex = topTalkersPage * topTalkersPerPage;
    const endIndex = startIndex + topTalkersPerPage;
    const totalPages = Math.ceil(filteredIPs.length / topTalkersPerPage);
    const currentPageIPs = filteredIPs.slice(startIndex, endIndex);

    // Prepare data for the bar chart based on view type
    const chartData = filteredIPs.slice(0, 10).map(ip => ({
      ip: ip.ip,
      bytes: viewType === 'source' ? ip.bytesSent : 
             viewType === 'destination' ? ip.bytesReceived : 
             ip.totalBytes
    }));

    return (
      <div className="space-y-6">
        <Card className="p-4">
          <div className="flex flex-col space-y-4">
            <h3 className="text-lg font-semibold">Top Talkers</h3>
            
            {/* Filters */}
            <div className="flex flex-wrap gap-4">
              <div className="flex-1">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  View Type
                </label>
                <select
                  className="w-full rounded-md border border-gray-300 p-2"
                  value={viewType}
                  onChange={(e) => setViewType(e.target.value)}
                >
                  <option value="all">All IPs</option>
                  <option value="source">Top Source IPs</option>
                  <option value="destination">Top Destination IPs</option>
                </select>
              </div>
              <div className="flex-1">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Protocol Filter
                </label>
                <select
                  className="w-full rounded-md border border-gray-300 p-2"
                  value={selectedProtocol}
                  onChange={(e) => setSelectedProtocol(e.target.value)}
                >
                  <option value="all">All Protocols</option>
                  {uniqueProtocols.map(protocol => (
                    <option key={protocol} value={protocol}>
                      {protocol}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* IP Statistics Table */}
            <div className="overflow-x-auto">
              <div className="max-h-[600px] overflow-y-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        IP Address
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        {viewType === 'source' ? 'Packets Sent' : 
                         viewType === 'destination' ? 'Packets Received' : 
                         'Total Packets'}
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        {viewType === 'source' ? 'Data Sent' : 
                         viewType === 'destination' ? 'Data Received' : 
                         'Total Data Volume'}
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Protocols
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Details
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {currentPageIPs.map((ip, index) => (
                      <tr key={ip.ip} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {ip.ip}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {viewType === 'source' ? ip.packetsSent.toLocaleString() :
                           viewType === 'destination' ? ip.packetsReceived.toLocaleString() :
                           ip.totalPackets.toLocaleString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {viewType === 'source' ? formatBytes(ip.bytesSent) :
                           viewType === 'destination' ? formatBytes(ip.bytesReceived) :
                           formatBytes(ip.totalBytes)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {ip.protocols.join(', ')}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          <div className="space-y-1">
                            <div className="text-xs">
                              Sent: {ip.packetsSent.toLocaleString()} packets ({formatBytes(ip.bytesSent)})
                            </div>
                            <div className="text-xs">
                              Received: {ip.packetsReceived.toLocaleString()} packets ({formatBytes(ip.bytesReceived)})
                            </div>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="flex justify-between items-center mt-4">
                <div className="text-sm text-gray-500">
                  Showing IPs {startIndex + 1} to {Math.min(endIndex, filteredIPs.length)} of {filteredIPs.length}
                </div>
                <div className="flex items-center space-x-4">
                  <Button
                    variant="outline"
                    onClick={handleTopTalkersPrevious}
                    disabled={topTalkersPage === 0}
                  >
                    Previous
                  </Button>
                  <span className="text-sm text-gray-500">
                    Page {topTalkersPage + 1} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    onClick={() => handleTopTalkersNext(filteredIPs.length)}
                    disabled={topTalkersPage >= totalPages - 1}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* Data Usage Chart */}
        <Card className="p-4">
          <h4 className="text-md font-semibold mb-4">
            {viewType === 'source' ? 'Top 10 Source IPs by Data Sent' :
             viewType === 'destination' ? 'Top 10 Destination IPs by Data Received' :
             'Top 10 IPs by Total Data Usage'}
          </h4>
          <div className="h-64">
            {chartData.length > 0 ? (
              <ResponsiveBar
                data={chartData}
                keys={['bytes']}
                indexBy="ip"
                margin={{ top: 10, right: 30, bottom: 40, left: 150 }}
                padding={0.3}
                valueScale={{ type: 'linear' }}
                indexScale={{ type: 'band', round: true }}
                colors={{ scheme: 'nivo' }}
                axisBottom={{
                  tickRotation: -45,
                  truncateTickAt: 20
                }}
                axisLeft={{
                  tickSize: 5,
                  tickPadding: 15,
                  tickRotation: 0,
                  legend: 'Data Volume (bytes)',
                  legendPosition: 'middle',
                  legendOffset: -100,
                  format: value => formatBytes(value)
                }}
                valueFormat={value => formatBytes(value)}
                tooltip={({ data }: BarTooltipProps<{ ip: string; bytes: number }>) => (
                  <div className="bg-white p-2 shadow rounded border">
                    <strong>{data.ip}</strong>: {formatBytes(data.bytes)}
                  </div>
                )}
                theme={{
                  axis: {
                    legend: {
                      text: {
                        fontSize: 12,
                        fontWeight: 600
                      }
                    },
                    ticks: {
                      text: {
                        fontSize: 11
                      }
                    }
                  }
                }}
              />
            ) : (
              <div className="h-full flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>
        </Card>
      </div>
    );
  };

  const renderBandwidth = () => {
    // Handle loading state
    if (isLoading) {
      return (
        <Card className="p-4">
          <div className="flex flex-col items-center justify-center space-y-4">
            <Loader2 className="h-8 w-8 animate-spin" />
            <p className="text-sm text-gray-500">Analyzing bandwidth usage...</p>
          </div>
        </Card>
      );
    }

    // Handle no file selected
    if (!file) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze bandwidth usage.</p>
          </div>
        </Card>
      );
    }

    // Handle missing analysis results
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">Analysis Results Not Available</h3>
            <p className="text-sm text-gray-500">
              Unable to analyze bandwidth usage. Please try analyzing the file again.
            </p>
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;

    // Process packets for bandwidth calculation
    const timeRanges = {
      '1min': 60,
      '5min': 300,
      'all': Infinity
    };

    // Calculate the start time based on the selected range
    const calculateStartTime = () => {
      if (!summary.packets || summary.packets.length === 0) return 0;
      const lastPacketTime = new Date(summary.packets[summary.packets.length - 1].time || 0).getTime();
      if (selectedTimeRange === 'all') return 0;
      return lastPacketTime - (timeRanges[selectedTimeRange as keyof typeof timeRanges] * 1000);
    };

    // Process packets into time series data
    const processPackets = () => {
      if (!summary.packets || summary.packets.length === 0) {
        return { timeSeriesData: [], protocolData: {}, sourceData: {}, destData: {} };
      }

      const startTime = calculateStartTime();
      const timeSeriesData: { time: string; bytes: number }[] = [];
      const protocolData: { [key: string]: number } = {};
      const sourceData: { [key: string]: number } = {};
      const destData: { [key: string]: number } = {};
      
      let currentSecond = 0;
      let currentBytes = 0;

      // Filter packets based on time range
      const filteredPackets = summary.packets.filter(packet => {
        const packetTime = new Date(packet.time || 0).getTime();
        return packetTime >= startTime;
      });

      // Sort packets by time
      filteredPackets.sort((a, b) => {
        const timeA = new Date(a.time || 0).getTime();
        const timeB = new Date(b.time || 0).getTime();
        return timeA - timeB;
      });

      filteredPackets.forEach(packet => {
        const packetTime = new Date(packet.time || 0).getTime();
        const packetSecond = Math.floor(packetTime / 1000);

        if (currentSecond === 0) {
          currentSecond = packetSecond;
        }

        if (packetSecond > currentSecond) {
          if (currentBytes > 0) {
            timeSeriesData.push({
              time: new Date(currentSecond * 1000).toISOString(),
              bytes: currentBytes
            });
          }
          // Fill in gaps with zero values
          while (currentSecond < packetSecond - 1) {
            currentSecond++;
            timeSeriesData.push({
              time: new Date(currentSecond * 1000).toISOString(),
              bytes: 0
            });
          }
          currentSecond = packetSecond;
          currentBytes = 0;
        }

        currentBytes += packet.length;

        // Process protocol data
        protocolData[packet.protocol] = (protocolData[packet.protocol] || 0) + packet.length;

        // Process source IP data
        sourceData[packet.source] = (sourceData[packet.source] || 0) + packet.length;

        // Process destination IP data
        destData[packet.destination] = (destData[packet.destination] || 0) + packet.length;
      });

      // Add the last second's data
      if (currentBytes > 0) {
        timeSeriesData.push({
          time: new Date(currentSecond * 1000).toISOString(),
          bytes: currentBytes
        });
      }

      return {
        timeSeriesData,
        protocolData,
        sourceData,
        destData
      };
    };

    const { timeSeriesData, protocolData, sourceData, destData } = processPackets();

    // Sort and get top 10 IPs for source and destination
    const getTop10 = (data: { [key: string]: number }) => {
      return Object.entries(data)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([key, value]) => ({ id: key, value }));
    };

    const top10Sources = getTop10(sourceData);
    const top10Destinations = getTop10(destData);

    // Convert protocol data for visualization
    const protocolChartData = Object.entries(protocolData).map(([protocol, bytes]) => ({
      id: protocol,
      value: bytes
    }));

    // Handle time range change
    const handleTimeRangeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSelectedTimeRange(e.target.value);
    };

    // Add this helper function at the component level
    const formatTimeLabel = (timestamp: string): string => {
      const date = new Date(timestamp);
      const hours = date.getHours().toString().padStart(2, '0');
      const minutes = date.getMinutes().toString().padStart(2, '0');
      const seconds = date.getSeconds().toString().padStart(2, '0');
      return `${hours}:${minutes}:${seconds}`;
    };

    return (
      <div className="space-y-6">
        {/* Time Range Filter */}
        <Card className="p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Bandwidth Usage</h3>
            <select
              className="border rounded-md p-2"
              value={selectedTimeRange}
              onChange={handleTimeRangeChange}
            >
              <option value="1min">Last 1 Minute</option>
              <option value="5min">Last 5 Minutes</option>
              <option value="all">Entire Capture</option>
            </select>
          </div>

          {/* Bandwidth Over Time Chart */}
          <div className="h-64">
            {timeSeriesData.length > 0 ? (
              <ResponsiveLine
                data={[
                  {
                    id: "bandwidth",
                    data: timeSeriesData.map(d => ({
                      x: formatTimeLabel(d.time),
                      y: d.bytes
                    }))
                  }
                ]}
                margin={{ top: 20, right: 30, bottom: 70, left: 100 }}
                xScale={{ 
                  type: 'point'
                }}
                yScale={{ 
                  type: 'linear',
                  min: 0,
                  max: 'auto',
                  stacked: true,
                  reverse: false
                }}
                axisBottom={{
                  tickSize: 5,
                  tickPadding: 5,
                  tickRotation: -45,
                  legend: 'Time',
                  legendOffset: 55,
                  legendPosition: 'middle',
                  format: (value) => {
                    const index = timeSeriesData.findIndex(d => formatTimeLabel(d.time) === value);
                    return index % Math.max(1, Math.floor(timeSeriesData.length / 10)) === 0 ? value : '';
                  }
                }}
                axisLeft={{
                  tickSize: 5,
                  tickPadding: 8,
                  tickRotation: 0,
                  legend: 'Bytes/Second',
                  legendOffset: -85,
                  legendPosition: 'middle',
                  format: value => formatBytes(Number(value))
                }}
                enablePoints={false}
                enableArea={true}
                areaOpacity={0.1}
                enableGridX={false}
                enableGridY={true}
                curve="monotoneX"
                useMesh={true}
                tooltip={({ point }) => (
                  <div className="bg-white p-2 shadow rounded border">
                    <strong>{point.data.xFormatted}</strong>: {point.data.yFormatted}ms
                  </div>
                )}
              />
            ) : (
              <div className="h-full flex items-center justify-center text-gray-500">
                No bandwidth data available for the selected time range
              </div>
            )}
          </div>
        </Card>

        {/* Protocol Breakdown */}
        <Card className="p-4">
          <h4 className="text-md font-semibold mb-4">Protocol Breakdown</h4>
          <div className="h-64">
            {protocolChartData.length > 0 ? (
              <ResponsivePie
                data={protocolChartData}
                margin={{ top: 20, right: 80, bottom: 20, left: 80 }}
                innerRadius={0.5}
                padAngle={0.7}
                cornerRadius={3}
                activeOuterRadiusOffset={8}
                borderWidth={1}
                borderColor={{ from: 'color', modifiers: [['darker', 0.2]] }}
                arcLinkLabelsSkipAngle={10}
                arcLinkLabelsTextColor="#333333"
                arcLinkLabelsThickness={2}
                arcLinkLabelsColor={{ from: 'color' }}
                arcLabelsSkipAngle={10}
                arcLabelsTextColor={{ from: 'color', modifiers: [['darker', 2]] }}
                tooltip={({ datum }: PieTooltipProps<{ id: string; value: number }>) => (
                  <div className="bg-white p-2 shadow rounded border">
                    <strong>{datum.id}</strong>: {formatBytes(datum.value)}
                  </div>
                )}
              />
            ) : (
              <div className="h-full flex items-center justify-center text-gray-500">
                No protocol data available
              </div>
            )}
          </div>
        </Card>

        {/* Top IPs Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Top Source IPs */}
          <Card className="p-4">
            <h4 className="text-md font-semibold mb-4">Top Source IPs</h4>
            <div className="h-64">
              {top10Sources.length > 0 ? (
                <ResponsiveBar
                  data={top10Sources}
                  keys={['value']}
                  indexBy="id"
                  margin={{ top: 10, right: 10, bottom: 40, left: 60 }}
                  padding={0.3}
                  valueScale={{ type: 'linear' }}
                  indexScale={{ type: 'band', round: true }}
                  colors={{ scheme: 'nivo' }}
                  axisBottom={{
                    tickRotation: -45,
                    truncateTickAt: 20
                  }}
                  axisLeft={{
                    format: value => formatBytes(Number(value))
                  }}
                  tooltip={({ data }: BarTooltipProps<{ id: string; value: number }>) => (
                    <div className="bg-white p-2 shadow rounded border">
                      <strong>{data.id}</strong>: {formatBytes(data.value)}
                    </div>
                  )}
                />
              ) : (
                <div className="h-full flex items-center justify-center text-gray-500">
                  No source IP data available
                </div>
              )}
            </div>
          </Card>

          {/* Top Destination IPs */}
          <Card className="p-4">
            <h4 className="text-md font-semibold mb-4">Top Destination IPs</h4>
            <div className="h-64">
              {top10Destinations.length > 0 ? (
                <ResponsiveBar
                  data={top10Destinations}
                  keys={['value']}
                  indexBy="id"
                  margin={{ top: 10, right: 10, bottom: 40, left: 60 }}
                  padding={0.3}
                  valueScale={{ type: 'linear' }}
                  indexScale={{ type: 'band', round: true }}
                  colors={{ scheme: 'nivo' }}
                  axisBottom={{
                    tickRotation: -45,
                    truncateTickAt: 20
                  }}
                  axisLeft={{
                    format: value => formatBytes(Number(value))
                  }}
                  tooltip={({ data }: BarTooltipProps<{ id: string; value: number }>) => (
                    <div className="bg-white p-2 shadow rounded border">
                      <strong>{data.id}</strong>: {formatBytes(data.value)}
                    </div>
                  )}
                />
              ) : (
                <div className="h-full flex items-center justify-center text-gray-500">
                  No destination IP data available
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>
    );
  };

  const renderAnomalies = () => {
    // Handle loading state
    if (isLoading) {
      return (
        <Card className="p-4">
          <div className="flex flex-col items-center justify-center space-y-4">
            <Loader2 className="h-8 w-8 animate-spin" />
            <p className="text-sm text-gray-500">Analyzing network anomalies...</p>
          </div>
        </Card>
      );
    }

    // Handle no file selected
    if (!file) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze network anomalies.</p>
          </div>
        </Card>
      );
    }

    // Handle missing analysis results
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">Analysis Results Not Available</h3>
            <p className="text-sm text-gray-500">
              Unable to analyze network anomalies. Please try analyzing the file again.
            </p>
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;

    // Process anomalies from the data
    const anomalies: Array<{
      type: string;
      severity: 'critical' | 'warning' | 'info';
      sourceIp: string;
      destinationIp: string;
      timestamp: string;
      details: string;
    }> = [];

    // Check conversations for retransmissions and errors
    if (summary.flowStats) {
      summary.flowStats.forEach(flow => {
        const timestamp = new Date().toISOString(); // Use actual timestamp from the flow if available

        // Check for TCP handshake issues
        if (flow.handshakeStatus) {
          const { syn, synAck, ack } = flow.handshakeStatus;
          if (syn === 'X' || synAck === 'X' || ack === 'X') {
            anomalies.push({
              type: 'TCP Handshake Failure',
              severity: 'critical',
              sourceIp: flow.sourceIp,
              destinationIp: flow.destinationIp,
              timestamp,
              details: `Incomplete handshake: SYN=${syn}, SYN-ACK=${synAck}, ACK=${ack}`
            });
          }
        }

        // Check for retransmissions
        if (flow.retransmissionCount > 0) {
          const severity = flow.retransmissionCount > 5 ? 'critical' : 'warning';
          anomalies.push({
            type: 'Retransmissions',
            severity,
            sourceIp: flow.sourceIp,
            destinationIp: flow.destinationIp,
            timestamp,
            details: `${flow.retransmissionCount} retransmissions detected`
          });
        }

        // Check for high RTT
        if (flow.rttStats && flow.rttStats.average > 500) { // 500ms threshold
          anomalies.push({
            type: 'High Latency',
            severity: 'warning',
            sourceIp: flow.sourceIp,
            destinationIp: flow.destinationIp,
            timestamp,
            details: `Average RTT: ${flow.rttStats.average.toFixed(2)}ms`
          });
        }
      });
    }

    // Check for potential port scans (multiple ports accessed in short time)
    const portAccessMap = new Map<string, Set<number>>();
    summary.packets.forEach(packet => {
      if (packet.source && packet.dstPort) {
        const key = packet.source;
        if (!portAccessMap.has(key)) {
          portAccessMap.set(key, new Set());
        }
        portAccessMap.get(key)?.add(Number(packet.dstPort));
      }
    });

    portAccessMap.forEach((ports, ip) => {
      if (ports.size > 10) { // Threshold for port scan detection
        anomalies.push({
          type: 'Potential Port Scan',
          severity: 'critical',
          sourceIp: ip,
          destinationIp: 'Multiple',
          timestamp: new Date().toISOString(),
          details: `Accessed ${ports.size} different ports`
        });
      }
    });

    // Prepare timeline data
    const timelineData = anomalies.reduce((acc, anomaly) => {
      const hour = new Date(anomaly.timestamp).getHours();
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {} as Record<number, number>);

    const chartData = Object.entries(timelineData).map(([hour, count]) => ({
      hour: `${hour}:00`,
      count
    }));

    // Add the handleAnomaliesSort function in the renderAnomalies function
    const handleAnomaliesSort = (field: 'type' | 'sourceIp' | 'destinationIp' | 'timestamp' | 'details') => {
      setAnomaliesSort(prev => ({
        field,
        direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
      }));
    };

    // Sort anomalies based on current sort settings
    const sortedAnomalies = [...anomalies].sort((a, b) => {
      if (!anomaliesSort.field) return 0;
      
      const direction = anomaliesSort.direction === 'asc' ? 1 : -1;
      
      switch (anomaliesSort.field) {
        case 'type':
          return (a.type.localeCompare(b.type)) * direction;
        case 'sourceIp':
          return (a.sourceIp.localeCompare(b.sourceIp)) * direction;
        case 'destinationIp':
          return (a.destinationIp.localeCompare(b.destinationIp)) * direction;
        case 'timestamp':
          return (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) * direction;
        case 'details':
          return (a.details.localeCompare(b.details)) * direction;
        default:
          return 0;
      }
    });

    // Add pagination handlers near other handlers
    const handleAnomaliesPrevious = () => {
      setAnomaliesPage(prev => Math.max(0, prev - 1));
    };

    const handleAnomaliesNext = () => {
      const totalPages = Math.ceil(sortedAnomalies.length / anomaliesPerPage);
      setAnomaliesPage(prev => Math.min(totalPages - 1, prev + 1));
    };

    // Calculate pagination values
    const startIndex = anomaliesPage * anomaliesPerPage;
    const endIndex = startIndex + anomaliesPerPage;
    const totalPages = Math.ceil(sortedAnomalies.length / anomaliesPerPage);

    return (
      <div className="space-y-6">
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Network Anomalies</h3>
          
          {anomalies.length > 0 ? (
            <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleAnomaliesSort('type')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Type</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${anomaliesSort.field === 'type' ? (anomaliesSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleAnomaliesSort('sourceIp')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Source IP</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${anomaliesSort.field === 'sourceIp' ? (anomaliesSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleAnomaliesSort('destinationIp')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Destination IP</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${anomaliesSort.field === 'destinationIp' ? (anomaliesSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleAnomaliesSort('timestamp')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Timestamp</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${anomaliesSort.field === 'timestamp' ? (anomaliesSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleAnomaliesSort('details')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Details</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${anomaliesSort.field === 'details' ? (anomaliesSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {sortedAnomalies.slice(startIndex, endIndex).map((anomaly, index) => (
                    <tr 
                      key={index} 
                      className={`${
                        anomaly.severity === 'critical' ? 'bg-red-50' :
                        anomaly.severity === 'warning' ? 'bg-yellow-50' :
                        index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
                      } hover:bg-gray-100`}
                    >
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                            ${
                              anomaly.severity === 'critical' ? 'bg-red-100 text-red-800' :
                              anomaly.severity === 'warning' ? 'bg-yellow-100 text-yellow-800' :
                              'bg-blue-100 text-blue-800'
                            }`}
                          >
                            {anomaly.type}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {anomaly.sourceIp}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {anomaly.destinationIp}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(anomaly.timestamp).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {anomaly.details}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
              
              {/* Pagination Controls - Moved here */}
              <div className="flex justify-between items-center mt-4">
                <div className="text-sm text-gray-500">
                  Showing anomalies {startIndex + 1} to {Math.min(endIndex, sortedAnomalies.length)} of {sortedAnomalies.length}
                </div>
                <div className="flex items-center space-x-4">
                  <Button
                    variant="outline"
                    onClick={handleAnomaliesPrevious}
                    disabled={anomaliesPage === 0}
                  >
                    Previous
                  </Button>
                  <span className="text-sm text-gray-500">
                    Page {anomaliesPage + 1} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    onClick={handleAnomaliesNext}
                    disabled={anomaliesPage >= totalPages - 1}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center text-gray-500 py-4">
              No anomalies detected in the network traffic.
            </div>
          )}
        </Card>

        {/* Timeline Chart */}
        {anomalies.length > 0 && (
          <Card className="p-4">
            <h4 className="text-md font-semibold mb-4">Anomaly Frequency Timeline</h4>
            <div className="h-64">
              <ResponsiveBar
                data={chartData}
                keys={['count']}
                indexBy="hour"
                margin={{ top: 10, right: 10, bottom: 40, left: 40 }}
                padding={0.3}
                valueScale={{ type: 'linear' }}
                indexScale={{ type: 'band', round: true }}
                colors={{ scheme: 'red_yellow_blue' }}
                axisBottom={{
                  tickRotation: 0,
                  legend: 'Time',
                  legendPosition: 'middle',
                  legendOffset: 32
                }}
                axisLeft={{
                  tickSize: 5,
                  tickPadding: 5,
                  tickRotation: 0,
                  legend: 'Number of Anomalies',
                  legendPosition: 'middle',
                  legendOffset: -32
                }}
              />
            </div>
          </Card>
        )}
      </div>
    );
  };

  const renderHttpTraffic = () => {
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No HTTP Traffic Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze HTTP traffic.</p>
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;

    // Process HTTP traffic from packets
    const httpTraffic = summary.packets
      .filter(packet => packet.protocol === 'HTTP' || packet.protocol === 'HTTP/1.1' || packet.protocol === 'HTTP/2')
      .map(packet => {
        const info = packet.info;
        const methodMatch = info.match(/(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) /);
        const urlMatch = info.match(/ (https?:\/\/[^\s]+|\/[^\s]+) /);
        const statusMatch = info.match(/ (\d{3}) /);
        const hostMatch = info.match(/Host: ([^\s]+)/);
        const contentTypeMatch = info.match(/Content-Type: ([^\s;]+)/);

        return {
          method: methodMatch ? methodMatch[1] : 'Unknown',
          url: urlMatch ? urlMatch[1] : 'Unknown',
          statusCode: statusMatch ? parseInt(statusMatch[1]) : 0,
          hostname: hostMatch ? hostMatch[1] : 'Unknown',
          contentType: contentTypeMatch ? contentTypeMatch[1] : 'Unknown',
          timestamp: packet.time || new Date().toISOString()
        };
      });

    // Process TLS/HTTPS details
    const tlsDetails = summary.packets
      .filter(packet => packet.protocol === 'TLSv1.2' || packet.protocol === 'TLSv1.3')
      .map(packet => {
        const info = packet.info;
        const versionMatch = info.match(/TLSv\d\.\d/);
        const cipherMatch = info.match(/Cipher Suite: ([^\s]+)/);
        const issuerMatch = info.match(/Issuer: ([^,]+)/);
        const expirationMatch = info.match(/Not After: ([^\s]+)/);
        const serverNameMatch = info.match(/Server Name: ([^\s]+)/);

        return {
          version: versionMatch ? versionMatch[0] : 'Unknown',
          cipherSuite: cipherMatch ? cipherMatch[1] : 'Unknown',
          certIssuer: issuerMatch ? issuerMatch[1] : 'Unknown',
          certExpiration: expirationMatch ? expirationMatch[1] : 'Unknown',
          hostname: serverNameMatch ? serverNameMatch[1] : 'Unknown',
          timestamp: packet.time || new Date().toISOString()
        };
      });

    // Sort HTTP traffic
    const sortedHttpTraffic = [...httpTraffic].sort((a, b) => {
      if (!httpSort.field) return 0;
      
      const direction = httpSort.direction === 'asc' ? 1 : -1;
      
      switch (httpSort.field) {
        case 'method':
          return (a.method.localeCompare(b.method)) * direction;
        case 'url':
          return (a.url.localeCompare(b.url)) * direction;
        case 'statusCode':
          return (a.statusCode - b.statusCode) * direction;
        case 'hostname':
          return (a.hostname.localeCompare(b.hostname)) * direction;
        case 'contentType':
          return (a.contentType.localeCompare(b.contentType)) * direction;
        case 'timestamp':
          return (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) * direction;
        default:
          return 0;
      }
    });

    // Sort TLS details
    const sortedTlsDetails = [...tlsDetails].sort((a, b) => {
      if (!tlsSort.field) return 0;
      
      const direction = tlsSort.direction === 'asc' ? 1 : -1;
      
      switch (tlsSort.field) {
        case 'version':
          return (a.version.localeCompare(b.version)) * direction;
        case 'cipherSuite':
          return (a.cipherSuite.localeCompare(b.cipherSuite)) * direction;
        case 'hostname':
          return (a.hostname.localeCompare(b.hostname)) * direction;
        case 'certIssuer':
          return (a.certIssuer.localeCompare(b.certIssuer)) * direction;
        case 'certExpiration':
          return (new Date(a.certExpiration).getTime() - new Date(b.certExpiration).getTime()) * direction;
        default:
          return 0;
      }
    });

    const handleHttpSort = (field: 'method' | 'url' | 'statusCode' | 'hostname' | 'contentType' | 'timestamp') => {
      if (httpSort.field === field) {
        setHttpSort({
        field,
          direction: httpSort.direction === 'asc' ? 'desc' : 'asc'
        });
      } else {
        setHttpSort({ field, direction: 'asc' });
      }
    };

    const handleTlsSort = (field: 'version' | 'cipherSuite' | 'hostname' | 'certIssuer' | 'certExpiration') => {
      if (tlsSort.field === field) {
        setTlsSort({
        field,
          direction: tlsSort.direction === 'asc' ? 'desc' : 'asc'
        });
      } else {
        setTlsSort({ field, direction: 'asc' });
      }
    };

    // Calculate pagination for HTTP traffic
    const httpStartIndex = httpPage * httpPerPage;
    const httpEndIndex = httpStartIndex + httpPerPage;
    const httpTotalPages = Math.ceil(sortedHttpTraffic.length / httpPerPage);
    const currentHttpTraffic = sortedHttpTraffic.slice(httpStartIndex, httpEndIndex);

    // Calculate pagination for TLS details
    const tlsStartIndex = tlsPage * tlsPerPage;
    const tlsEndIndex = tlsStartIndex + tlsPerPage;
    const tlsTotalPages = Math.ceil(sortedTlsDetails.length / tlsPerPage);
    const currentTlsDetails = sortedTlsDetails.slice(tlsStartIndex, tlsEndIndex);

    return (
      <div className="space-y-6">
        {/* HTTP Traffic Table */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">HTTP Traffic</h3>
          <div className="overflow-x-auto">
            <div className="max-h-[600px] overflow-y-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleHttpSort('method')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Method</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${httpSort.field === 'method' ? (httpSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleHttpSort('url')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>URL</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${httpSort.field === 'url' ? (httpSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleHttpSort('statusCode')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Status</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${httpSort.field === 'statusCode' ? (httpSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleHttpSort('hostname')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Hostname</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${httpSort.field === 'hostname' ? (httpSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleHttpSort('contentType')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Content Type</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${httpSort.field === 'contentType' ? (httpSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleHttpSort('timestamp')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Timestamp</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${httpSort.field === 'timestamp' ? (httpSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                  {currentHttpTraffic.length > 0 ? (
                    currentHttpTraffic.map((request, index) => (
                    <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                          ${request.method === 'GET' ? 'bg-green-100 text-green-800' :
                            request.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                            'bg-gray-100 text-gray-800'}`}>
                          {request.method}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">{request.url}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                          ${request.statusCode >= 200 && request.statusCode < 300 ? 'bg-green-100 text-green-800' :
                            request.statusCode >= 400 ? 'bg-red-100 text-red-800' :
                            'bg-yellow-100 text-yellow-800'}`}>
                          {request.statusCode}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{request.hostname}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{request.contentType}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(request.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="px-6 py-4 text-center text-sm text-gray-500">
                      No HTTP traffic found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            </div>
            <div className="flex justify-between items-center mt-4">
              <div className="text-sm text-gray-500">
                Showing {httpStartIndex + 1} to {Math.min(httpEndIndex, sortedHttpTraffic.length)} of {sortedHttpTraffic.length}
              </div>
              <div className="flex items-center space-x-4">
                <Button
                  variant="outline"
                  onClick={() => handleHttpPrevious()}
                  disabled={httpPage === 0}
                >
                  Previous
                </Button>
                <span className="text-sm text-gray-500">
                  Page {httpPage + 1} of {httpTotalPages}
                </span>
                <Button
                  variant="outline"
                  onClick={() => handleHttpNext(sortedHttpTraffic.length)}
                  disabled={httpPage >= httpTotalPages - 1}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        </Card>

        {/* HTTPS/TLS Details */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">HTTPS/TLS Details</h3>
          <div className="overflow-x-auto">
            <div className="max-h-[600px] overflow-y-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleTlsSort('version')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>TLS Version</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${tlsSort.field === 'version' ? (tlsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleTlsSort('cipherSuite')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Cipher Suite</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${tlsSort.field === 'cipherSuite' ? (tlsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleTlsSort('hostname')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Hostname</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${tlsSort.field === 'hostname' ? (tlsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleTlsSort('certIssuer')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Certificate Issuer</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${tlsSort.field === 'certIssuer' ? (tlsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleTlsSort('certExpiration')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Expiration Date</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${tlsSort.field === 'certExpiration' ? (tlsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                  {currentTlsDetails.length > 0 ? (
                    currentTlsDetails.map((tls, index) => (
                    <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                          ${tls.version.includes('1.3') ? 'bg-green-100 text-green-800' :
                            tls.version.includes('1.2') ? 'bg-blue-100 text-blue-800' :
                            'bg-yellow-100 text-yellow-800'}`}>
                          {tls.version}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900">{tls.cipherSuite}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{tls.hostname}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{tls.certIssuer}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{tls.certExpiration}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-6 py-4 text-center text-sm text-gray-500">
                      No HTTPS/TLS traffic found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            </div>
            <div className="flex justify-between items-center mt-4">
              <div className="text-sm text-gray-500">
                Showing {tlsStartIndex + 1} to {Math.min(tlsEndIndex, sortedTlsDetails.length)} of {sortedTlsDetails.length}
              </div>
              <div className="flex items-center space-x-4">
                <Button
                  variant="outline"
                  onClick={() => handleTlsPrevious()}
                  disabled={tlsPage === 0}
                >
                  Previous
                </Button>
                <span className="text-sm text-gray-500">
                  Page {tlsPage + 1} of {tlsTotalPages}
                </span>
                <Button
                  variant="outline"
                  onClick={() => handleTlsNext(sortedTlsDetails.length)}
                  disabled={tlsPage >= tlsTotalPages - 1}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        </Card>
      </div>
    );
  };

  const renderDnsAnalysis = () => {
    // Handle loading state
    if (isLoading) {
      return (
        <Card className="p-4">
          <div className="flex flex-col items-center justify-center space-y-4">
            <Loader2 className="h-8 w-8 animate-spin" />
            <p className="text-sm text-gray-500">Analyzing DNS traffic...</p>
          </div>
        </Card>
      );
    }

    // Handle no file selected
    if (!file) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze DNS traffic.</p>
          </div>
        </Card>
      );
    }

    // Handle missing analysis results
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">Analysis Results Not Available</h3>
            <p className="text-sm text-gray-500">
              Unable to analyze DNS traffic. Please try analyzing the file again.
            </p>
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;

    // Process DNS queries from packets
    const dnsQueries = summary.packets
      .filter(packet => packet.protocol === 'DNS')
      .map(packet => {
        const info = packet.info;
        const queryMatch = info.match(/query: ([^\s]+)/i);
        const typeMatch = info.match(/type ([A-Z]+)/i);
        const responseMatch = info.match(/response: ([^\s]+)/i);
        const statusMatch = info.match(/status: ([A-Z]+)/i);
        const timeMatch = info.match(/time: (\d+)ms/i);

        return {
          queryName: queryMatch ? queryMatch[1] : 'Unknown',
          queryType: typeMatch ? typeMatch[1] : 'Unknown',
          response: responseMatch ? responseMatch[1] : 'No Response',
          status: statusMatch ? statusMatch[1] : 'Unknown',
          responseTime: timeMatch ? parseInt(timeMatch[1]) : 0,
          timestamp: packet.time || new Date().toISOString(),
          isSuspicious: false
        };
      });

    // Mark suspicious queries
    const domainCounts = new Map();
    const suspiciousTLDs = ['.xyz', '.ru', '.tk', '.ml', '.ga', '.cf'];

    dnsQueries.forEach(query => {
      // Count domain occurrences
      domainCounts.set(query.queryName, (domainCounts.get(query.queryName) || 0) + 1);

      // Mark as suspicious if:
      query.isSuspicious = (
        query.status === 'NXDOMAIN' || // Non-existent domain
        query.responseTime > 500 || // High response time
        domainCounts.get(query.queryName) > 10 || // Multiple queries
        suspiciousTLDs.some(tld => query.queryName.toLowerCase().endsWith(tld)) // Suspicious TLD
      );
    });

    // Apply filters - focus on Query Type filter first
    const filteredQueries = dnsQueries.filter(query => {
      // Filter by Query Type
      const typeMatch = dnsQueryType === 'all' || query.queryType === dnsQueryType;
      
      // Filter by Query Status
      let statusMatch = true;
      if (dnsQueryStatus !== 'all') {
        if (dnsQueryStatus === 'NOERROR') {
          statusMatch = query.status === 'NOERROR';
        } else if (dnsQueryStatus === 'error') {
          statusMatch = ['NXDOMAIN', 'SERVFAIL'].includes(query.status);
        } else {
          statusMatch = query.status === dnsQueryStatus;
        }
      }
      
      return typeMatch && statusMatch;
    });

    // Prepare timeline data
    const timelineData = filteredQueries.reduce<Record<number, { hour: string; success: number; failed: number }>>((acc, query) => {
      const hour = new Date(query.timestamp).getHours();
      if (!acc[hour]) {
        acc[hour] = { hour: `${hour}:00`, success: 0, failed: 0 };
      }
      if (['NXDOMAIN', 'SERVFAIL'].includes(query.status)) {
        acc[hour].failed++;
      } else {
        acc[hour].success++;
      }
      return acc;
    }, {});

    const chartData = Object.values(timelineData);

    // Sort the filtered queries based on current sort settings
    const sortedQueries = [...filteredQueries].sort((a, b) => {
      if (!dnsSort.field) return 0;
      
      const direction = dnsSort.direction === 'asc' ? 1 : -1;
      
      switch (dnsSort.field) {
        case 'queryName':
          return (a.queryName.localeCompare(b.queryName)) * direction;
        case 'queryType':
          return (a.queryType.localeCompare(b.queryType)) * direction;
        case 'response':
          return (a.response.localeCompare(b.response)) * direction;
        case 'status':
          return (a.status.localeCompare(b.status)) * direction;
        case 'responseTime':
          return (a.responseTime - b.responseTime) * direction;
        case 'timestamp':
          return (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()) * direction;
        default:
          return 0;
      }
    });

    // Update pagination to use sorted queries
    const startIndex = (dnsPage - 1) * dnsPerPage;
    const endIndex = startIndex + dnsPerPage;
    const totalPages = Math.ceil(sortedQueries.length / dnsPerPage);
    const currentPageQueries = sortedQueries.slice(startIndex, endIndex);

    const handleDnsSort = (field: typeof dnsSort.field) => {
      setDnsSort(prev => ({
        field,
        direction: prev.field === field && prev.direction === 'asc' ? 'desc' : 'asc'
      }));
    };

    return (
      <div className="space-y-6">
        {/* Filters */}
        <Card className="p-4">
          <div className="flex flex-wrap gap-4">
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Query Type
              </label>
              <select
                className="w-full rounded-md border border-gray-300 p-2"
                value={dnsQueryType}
                onChange={(e) => {
                  console.log('Selected Query Type:', e.target.value); // Debug log
                  setDnsQueryType(e.target.value);
                }}
              >
                <option value="all">All Types</option>
                <option value="A">A Records</option>
                <option value="AAAA">AAAA Records</option>
                <option value="MX">MX Records</option>
                <option value="TXT">TXT Records</option>
                <option value="CNAME">CNAME Records</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Query Status
              </label>
              <select
                className="w-full rounded-md border border-gray-300 p-2"
                value={dnsQueryStatus}
                onChange={(e) => setDnsQueryStatus(e.target.value)}
              >
                <option value="all">All Statuses</option>
                <option value="NOERROR">Successful</option>
                <option value="error">Errors Only</option>
                <option value="NXDOMAIN">NXDOMAIN</option>
                <option value="SERVFAIL">SERVFAIL</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Response Time
              </label>
              <select
                className="w-full rounded-md border border-gray-300 p-2"
                value={dnsResponseTime}
                onChange={(e) => setDnsResponseTime(e.target.value)}
              >
                <option value="all">All Times</option>
                <option value="normal">Normal (&lt;500ms)</option>
                <option value="slow">Slow (&gt;500ms)</option>
              </select>
            </div>
          </div>
        </Card>

        {/* DNS Timeline */}
        <Card className="p-4">
          <h4 className="text-md font-semibold mb-4">DNS Query Timeline</h4>
          <div className="h-64">
            {chartData.length > 0 ? (
              <ResponsiveBar
                data={chartData}
                keys={['success', 'failed']}
                indexBy="hour"
                margin={{ top: 50, right: 50, bottom: 40, left: 80 }}
                padding={0.3}
                valueScale={{ type: 'linear' }}
                indexScale={{ type: 'band', round: true }}
                colors={['#22c55e', '#ef4444']}
                axisBottom={{
                  tickSize: 5,
                  tickPadding: 5,
                  tickRotation: 0,
                  legend: 'Time',
                  legendPosition: 'middle',
                  legendOffset: 32
                }}
                axisLeft={{
                  tickSize: 5,
                  tickPadding: 5,
                  tickRotation: 0,
                  legend: 'Number of Queries',
                  legendPosition: 'middle',
                  legendOffset: -60
                }}
                legends={[
                  {
                    dataFrom: 'keys',
                    anchor: 'top',
                    direction: 'row',
                    justify: false,
                    translateX: 0,
                    translateY: -30,
                    itemsSpacing: 10,
                    itemWidth: 100,
                    itemHeight: 20,
                    itemDirection: 'left-to-right',
                    itemOpacity: 0.85,
                    symbolSize: 12,
                    effects: [
                      {
                        on: 'hover',
                        style: {
                          itemOpacity: 1
                        }
                      }
                    ],
                    data: [
                      {
                        id: 'success',
                        label: 'Successful',
                        color: '#22c55e'
                      },
                      {
                        id: 'failed',
                        label: 'Failed',
                        color: '#ef4444'
                      }
                    ]
                  }
                ]}
              />
            ) : (
              <div className="h-full flex items-center justify-center text-gray-500">
                No DNS traffic data available
              </div>
            )}
          </div>
        </Card>

        {/* DNS Queries Table */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">DNS Queries</h3>
          <div className="overflow-x-auto">
            <div className="max-h-[600px] overflow-y-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleDnsSort('queryName')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Query Name</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${dnsSort.field === 'queryName' ? (dnsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleDnsSort('queryType')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Type</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${dnsSort.field === 'queryType' ? (dnsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleDnsSort('response')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Response</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${dnsSort.field === 'response' ? (dnsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleDnsSort('status')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Status</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${dnsSort.field === 'status' ? (dnsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleDnsSort('responseTime')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Response Time</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${dnsSort.field === 'responseTime' ? (dnsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleDnsSort('timestamp')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Timestamp</span>
                        <ChevronUpIcon 
                          className={`h-4 w-4 ${dnsSort.field === 'timestamp' ? (dnsSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                        />
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {currentPageQueries.length > 0 ? (
                    currentPageQueries.map((query, index) => (
                      <tr 
                        key={index} 
                        className={`${
                          query.isSuspicious ? 'bg-red-50' :
                          index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
                        } hover:bg-gray-100`}
                      >
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {query.queryName}
                          {query.isSuspicious && (
                            <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                              Suspicious
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                            {query.queryType}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {query.response}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                            ${query.status === 'NOERROR' ? 'bg-green-100 text-green-800' :
                              ['NXDOMAIN', 'SERVFAIL'].includes(query.status) ? 'bg-red-100 text-red-800' :
                              'bg-yellow-100 text-yellow-800'}`}
                          >
                            {query.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <span className={`${query.responseTime > 500 ? 'text-red-600 font-medium' : 'text-gray-900'}`}>
                            {query.responseTime}ms
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(query.timestamp).toLocaleString()}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-6 py-4 text-center text-sm text-gray-500">
                        No DNS queries found matching the selected filters
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="flex justify-between items-center mt-4">
              <div className="text-sm text-gray-500">
                Showing queries {startIndex + 1} to {Math.min(endIndex, sortedQueries.length)} of {sortedQueries.length}
              </div>
              <div className="flex items-center space-x-4">
                <Button
                  variant="outline"
                  onClick={() => handleDnsPrevious()}
                  disabled={dnsPage === 1}
                >
                  Previous
                </Button>
                <span className="text-sm text-gray-500">
                  Page {dnsPage} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  onClick={() => handleDnsNext(sortedQueries.length)}
                  disabled={dnsPage >= totalPages}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        </Card>
      </div>
    );
  };

  const renderIcmpArp = () => {
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No ICMP/ARP Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze ICMP/ARP traffic.</p>
          </div>
        </Card>
      );
    }

    const summary = analysisResults.trafficSummary;
    
    // Process ICMP statistics with enhanced metrics
    const icmpStats = {
      totalPackets: 0,
      totalBytes: 0,
      types: {} as { [key: string]: number },
      errors: {} as { [key: string]: number },
      rttStats: {
        min: Number.MAX_VALUE,
        max: 0,
        avg: 0,
        total: 0,
        count: 0,
      },
      malformedPackets: [] as ICMPPacket[],
      tunneling: [] as any[],
      highFrequencyPings: new Map<string, number>()
    };

    // Process ARP statistics with enhanced metrics
    const arpStats = {
      totalPackets: 0,
      totalBytes: 0,
      requests: 0,
      replies: 0,
      unresolvedRequests: new Set<string>(),
      gratuitousArp: [] as any[],
      duplicateMappings: new Map<string, Set<string>>(),
      addressConflicts: [] as any[],
      uniqueIPs: new Set<string>(),
      uniqueMACs: new Set<string>()
    };

    // Track ICMP Echo pairs for RTT calculation
    const icmpEchoPairs = new Map<string, number>();

    summary.packets.forEach((packet, index) => {
      if (packet.protocol === 'ICMP') {
        icmpStats.totalPackets++;
        icmpStats.totalBytes += packet.length;

        // Extract ICMP type and code
        const typeMatch = packet.info?.match(/Type: (\d+)/);
        const codeMatch = packet.info?.match(/Code: (\d+)/);
        const type = typeMatch ? parseInt(typeMatch[1]) : -1;
        const code = codeMatch ? parseInt(codeMatch[1]) : -1;

        // Categorize ICMP types
        let typeStr = 'Unknown';
        switch (type) {
          case 0: typeStr = 'Echo Reply'; break;
          case 3: 
            typeStr = 'Destination Unreachable';
            // Track error subtypes
            let errorType = 'Unknown';
            switch (code) {
              case 0: errorType = 'Net Unreachable'; break;
              case 1: errorType = 'Host Unreachable'; break;
              case 3: errorType = 'Port Unreachable'; break;
              case 4: errorType = 'Fragmentation Needed'; break;
              default: errorType = `Code ${code}`; break;
            }
            icmpStats.errors[errorType] = (icmpStats.errors[errorType] || 0) + 1;
            break;
          case 5: typeStr = 'Redirect'; break;
          case 8: typeStr = 'Echo Request'; break;
          case 11: typeStr = 'TTL Expired'; break;
          default: typeStr = `Type ${type}`; break;
        }
        icmpStats.types[typeStr] = (icmpStats.types[typeStr] || 0) + 1;

        // Calculate RTT for Echo Request/Reply pairs
        if (type === 8) { // Echo Request
          const key = `${packet.source}-${packet.destination}-${packet.info?.match(/id=(\d+)/)?.[1]}`;
          icmpEchoPairs.set(key, new Date(packet.time || 0).getTime());
        } else if (type === 0) { // Echo Reply
          const key = `${packet.destination}-${packet.source}-${packet.info?.match(/id=(\d+)/)?.[1]}`;
          const requestTime = icmpEchoPairs.get(key);
          if (requestTime) {
            const rtt = new Date(packet.time || 0).getTime() - requestTime;
            icmpStats.rttStats.min = Math.min(icmpStats.rttStats.min, rtt);
            icmpStats.rttStats.max = Math.max(icmpStats.rttStats.max, rtt);
            icmpStats.rttStats.total += rtt;
            icmpStats.rttStats.count++;
            icmpEchoPairs.delete(key);
          }
        }

        // Detect high-frequency pings
        if (type === 8) {
          const key = `${packet.source}-${packet.destination}`;
          icmpStats.highFrequencyPings.set(key, (icmpStats.highFrequencyPings.get(key) || 0) + 1);
        }

        // Detect malformed packets
        if (packet.length < 28 || !typeMatch || !codeMatch) {
          icmpStats.malformedPackets.push({
            number: packet.number,
            source: packet.source,
            destination: packet.destination,
            size: packet.length,
          });
        }

        // Detect potential ICMP tunneling
        if (packet.length > 1000) {
          icmpStats.tunneling.push({
            number: packet.number,
            time: packet.time,
            source: packet.source,
            destination: packet.destination,
            length: packet.length
          });
        }
      }
      else if (packet.protocol === 'ARP') {
        arpStats.totalPackets++;
        arpStats.totalBytes += packet.length;

        const isRequest = packet.info?.includes('request');
        const isReply = packet.info?.includes('reply');
        const ip = packet.info?.match(/IP: ([^\s,]+)/)?.[1];
        const mac = packet.info?.match(/MAC: ([0-9A-Fa-f:]+)/)?.[1];

        if (isRequest) {
          arpStats.requests++;
          if (ip) arpStats.unresolvedRequests.add(ip);
        } else if (isReply) {
          arpStats.replies++;
          if (ip) arpStats.unresolvedRequests.delete(ip);
        }

        // Track IP-MAC mappings for duplicate detection
        if (ip && mac) {
          if (!arpStats.duplicateMappings.has(ip)) {
            arpStats.duplicateMappings.set(ip, new Set());
          }
          arpStats.duplicateMappings.get(ip)?.add(mac);

          // Check for address conflicts
          const duplicateCount = arpStats.duplicateMappings.get(ip)?.size ?? 0;
          if (duplicateCount > 1) {
            arpStats.addressConflicts.push({
              time: packet.time,
              ip: ip,
              macs: Array.from(arpStats.duplicateMappings.get(ip) ?? new Set()),
              type: isRequest ? 'Request' : 'Reply'
            });
          }
        }

        // Detect gratuitous ARP
        if (packet.info?.includes('Gratuitous') || 
            (ip && packet.source === ip) || 
            (packet.info?.includes('request') && packet.source === packet.destination)) {
          arpStats.gratuitousArp.push({
            time: packet.time,
            ip: ip,
            mac: mac,
            info: packet.info
          });
        }

        if (ip) arpStats.uniqueIPs.add(ip);
        if (mac) arpStats.uniqueMACs.add(mac);
      }
    });

    // Calculate average RTT
    if (icmpStats.rttStats.count > 0) {
      icmpStats.rttStats.avg = icmpStats.rttStats.total / icmpStats.rttStats.count;
    }

    const unusualICMPData: UnusualICMPData[] = [
      ...icmpStats.malformedPackets.map(packet => ({
        number: packet.number,
        time: packet.time || 'N/A',
        source: packet.source,
        destination: packet.destination,
        size: packet.size,
        type: 'Malformed' as const,
        details: 'Invalid ICMP packet structure'
      })),
      ...icmpStats.tunneling.map(packet => ({
        number: packet.number,
        time: packet.time || 'N/A',
        source: packet.source,
        destination: packet.destination,
        size: packet.length || 0,
        type: 'Tunneling' as const,
        details: 'Unusually large ICMP packet'
      })),
      ...Array.from(icmpStats.highFrequencyPings.entries())
        .filter(([_, count]) => count > 100)
        .map(([addr, count]) => {
          const [source, destination] = addr.split('-')
          return {
            number: -1,
            time: 'Multiple',
            source,
            destination,
            size: count,
            type: 'High Frequency' as const,
            details: 'Excessive ICMP echo requests'
          }
        })
    ];

    // Calculate pagination values
    const totalPages = Math.ceil(unusualICMPData.length / packetsPerPage);
    const startIndex = (currentPage - 1) * packetsPerPage;
    const endIndex = startIndex + packetsPerPage;
    const currentPackets = unusualICMPData.slice(startIndex, endIndex);

    return (
      <div className="space-y-6">
        {/* ICMP Analysis */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">ICMP Analysis</h3>
          {icmpStats.totalPackets === 0 ? (
            <div className="text-center text-sm text-gray-500">
              No ICMP traffic found in the capture
            </div>
          ) : (
            <div className="space-y-6">
              {/* ICMP Overview */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Total ICMP Packets</p>
                  <p className="text-lg font-semibold">{icmpStats.totalPackets}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Total ICMP Bytes</p>
                  <p className="text-lg font-semibold">{icmpStats.totalBytes}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Unique ICMP Types</p>
                  <p className="text-lg font-semibold">{Object.keys(icmpStats.types).length}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Error Messages</p>
                  <p className="text-lg font-semibold">{Object.keys(icmpStats.errors).length}</p>
                </div>
              </div>

              {/* ICMP Types Breakdown */}
              <div>
                <h4 className="text-md font-semibold mb-2">ICMP Packet Types</h4>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Count</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Percentage</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {Object.entries(icmpStats.types).map(([type, count]) => (
                        <tr key={type}>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{type}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{count}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {((count / (icmpStats.totalPackets || 1)) * 100).toFixed(1)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* ICMP Error Messages */}
              {Object.keys(icmpStats.errors).length > 0 && (
                <div>
                  <h4 className="text-md font-semibold mb-2">ICMP Error Messages</h4>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Error Type</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Count</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {Object.entries(icmpStats.errors).map(([error, count]) => (
                          <tr key={error}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{error}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* RTT Statistics */}
              {icmpStats.rttStats.count > 0 && (
                <div>
                  <h4 className="text-md font-semibold mb-2">Round-Trip Time Statistics</h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-gray-50 p-4 rounded-lg">
                      <p className="text-sm text-gray-500">Minimum RTT</p>
                      <p className="text-lg font-semibold">{icmpStats.rttStats.min.toFixed(2)}ms</p>
                    </div>
                    <div className="bg-gray-50 p-4 rounded-lg">
                      <p className="text-sm text-gray-500">Maximum RTT</p>
                      <p className="text-lg font-semibold">{icmpStats.rttStats.max.toFixed(2)}ms</p>
                    </div>
                    <div className="bg-gray-50 p-4 rounded-lg">
                      <p className="text-sm text-gray-500">Average RTT</p>
                      <p className="text-lg font-semibold">{icmpStats.rttStats.avg.toFixed(2)}ms</p>
                    </div>
                    <div className="bg-gray-50 p-4 rounded-lg">
                      <p className="text-sm text-gray-500">Echo Pairs</p>
                      <p className="text-lg font-semibold">{icmpStats.rttStats.count}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Unusual ICMP Activity */}
              {(icmpStats.malformedPackets.length > 0 || 
                icmpStats.tunneling.length > 0 || 
                Array.from(icmpStats.highFrequencyPings.values()).some(count => count > 100)) && (
                <div>
                  <h4 className="text-md font-semibold mb-2">Unusual ICMP Activity</h4>
                  <div className="overflow-x-auto">
                    <div className="max-h-[600px] overflow-y-auto">
                      <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                          <tr>
                            <ResizableHeader
                              width={columnWidths.packetNum}
                              onResize={(width) => setColumnWidths(prev => ({ ...prev, packetNum: width }))}
                              className="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10"
                            >
                              Packet #
                            </ResizableHeader>
                            <ResizableHeader
                              width={columnWidths.time}
                              onResize={(width) => setColumnWidths(prev => ({ ...prev, time: width }))}
                              className="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10"
                            >
                              Time
                            </ResizableHeader>
                            <ResizableHeader
                              width={columnWidths.source}
                              onResize={(width) => setColumnWidths(prev => ({ ...prev, source: width }))}
                              className="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10"
                            >
                              Source
                            </ResizableHeader>
                            <ResizableHeader
                              width={columnWidths.destination}
                              onResize={(width) => setColumnWidths(prev => ({ ...prev, destination: width }))}
                              className="pl-0 pr-2 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10"
                            >
                              Destination
                            </ResizableHeader>
                            <ResizableHeader
                              width={columnWidths.size}
                              onResize={(width) => setColumnWidths(prev => ({ ...prev, size: width }))}
                              className="pl-0 pr-2 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10"
                            >
                              Size
                            </ResizableHeader>
                            <ResizableHeader
                              width={columnWidths.type}
                              onResize={(width) => setColumnWidths(prev => ({ ...prev, type: width }))}
                              className="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10"
                            >
                              Type
                            </ResizableHeader>
                            <ResizableHeader
                              width={columnWidths.details}
                              onResize={(width) => setColumnWidths(prev => ({ ...prev, details: width }))}
                              className="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10"
                            >
                              Details
                            </ResizableHeader>
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                          {currentPackets.map((packet) => (
                            <tr key={`${packet.type}-${packet.number}`} className="hover:bg-gray-50">
                              <td className="px-2 py-4 whitespace-nowrap text-sm text-gray-900" style={{ width: columnWidths.packetNum }}>
                                {packet.number}
                              </td>
                              <td className="px-2 py-4 whitespace-nowrap text-sm text-gray-900" style={{ width: columnWidths.time }}>
                                {typeof packet.time === 'string' ? packet.time : new Date(packet.time).toLocaleTimeString()}
                              </td>
                              <td className="px-2 py-4 whitespace-nowrap text-sm text-gray-900" style={{ width: columnWidths.source }}>
                                {packet.source}
                              </td>
                              <td className="pl-0 pr-2 py-4 whitespace-nowrap text-sm text-gray-900" style={{ width: columnWidths.destination }}>
                                {packet.destination}
                              </td>
                              <td className="pl-0 pr-2 py-4 whitespace-nowrap text-sm text-gray-900" style={{ width: columnWidths.size }}>
                                {packet.size} {typeof packet.size === 'number' && packet.size > 100 ? 'packets' : 'bytes'}
                              </td>
                              <td className="px-2 py-4 whitespace-nowrap" style={{ width: columnWidths.type }}>
                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                  packet.type === 'Malformed' ? 'bg-red-100 text-red-800' :
                                  packet.type === 'Tunneling' ? 'bg-orange-100 text-orange-800' :
                                  'bg-yellow-100 text-yellow-800'
                                }`}>
                                  {packet.type}
                                </span>
                              </td>
                              <td className="px-2 py-4 whitespace-nowrap text-sm text-gray-500" style={{ width: columnWidths.details }}>
                                {packet.details}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="mt-4 flex justify-between items-center">
                      <div className="text-sm text-gray-500">
                        Showing {startIndex + 1} to {Math.min(endIndex, unusualICMPData.length)} of {unusualICMPData.length} packets
                      </div>
                      <div className="flex gap-2 items-center">
                        <button
                          onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                          disabled={currentPage === 1}
                          className={`px-4 py-2 text-sm font-medium rounded-md ${
                            currentPage === 1
                              ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                              : 'bg-white text-gray-700 hover:bg-gray-50 border border-gray-300'
                          }`}
                        >
                          Previous
                        </button>
                        <span className="text-sm text-gray-700">
                          Page {currentPage} of {totalPages}
                        </span>
                        <button
                          onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                          disabled={currentPage === totalPages}
                          className={`px-4 py-2 text-sm font-medium rounded-md ${
                            currentPage === totalPages
                              ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                              : 'bg-white text-gray-700 hover:bg-gray-50 border border-gray-300'
                          }`}
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </Card>

        {/* ARP Analysis */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">ARP Analysis</h3>
          {arpStats.totalPackets === 0 ? (
            <div className="text-center text-sm text-gray-500">
              No ARP traffic found in the capture
            </div>
          ) : (
            <div className="space-y-6">
              {/* ARP Overview */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Total ARP Packets</p>
                  <p className="text-lg font-semibold">{arpStats.totalPackets}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Total ARP Bytes</p>
                  <p className="text-lg font-semibold">{arpStats.totalBytes}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">ARP Requests</p>
                  <p className="text-lg font-semibold">{arpStats.requests}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">ARP Replies</p>
                  <p className="text-lg font-semibold">{arpStats.replies}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Unresolved Requests</p>
                  <p className="text-lg font-semibold">{arpStats.unresolvedRequests.size}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Unique IPs</p>
                  <p className="text-lg font-semibold">{arpStats.uniqueIPs.size}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Unique MACs</p>
                  <p className="text-lg font-semibold">{arpStats.uniqueMACs.size}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Gratuitous ARPs</p>
                  <p className="text-lg font-semibold">{arpStats.gratuitousArp.length}</p>
                </div>
              </div>

              {/* Unresolved ARP Requests */}
              {arpStats.unresolvedRequests.size > 0 && (
                <div>
                  <h4 className="text-md font-semibold mb-2">Unresolved ARP Requests</h4>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Address</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {Array.from(arpStats.unresolvedRequests).map((ip) => (
                          <tr key={ip}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{ip}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Gratuitous ARP */}
              {arpStats.gratuitousArp.length > 0 && (
                <div>
                  <h4 className="text-md font-semibold mb-2">Gratuitous ARP Activity</h4>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Address</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">MAC Address</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {arpStats.gratuitousArp.map((arp, index) => (
                          <tr key={index} className="bg-yellow-50">
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              {new Date(arp.time).toLocaleString()}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{arp.ip}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{arp.mac}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{arp.info}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ARP Address Conflicts */}
              {arpStats.addressConflicts.length > 0 && (
                <div>
                  <h4 className="text-md font-semibold mb-2">ARP Address Conflicts</h4>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Address</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">MAC Addresses</th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {arpStats.addressConflicts.map((conflict, index) => (
                          <tr key={index} className="bg-red-50">
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              {new Date(conflict.time).toLocaleString()}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{conflict.ip}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              {conflict.macs.join(', ')}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{conflict.type}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    );
  };

  const renderTiming = () => {
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Timing Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze packet timing.</p>
          </div>
        </Card>
      );
    }

    const { packets, time_range } = analysisResults.trafficSummary;
    const startIndex = currentPage * packetsPerPage;
    const endIndex = Math.min(startIndex + packetsPerPage, packets.length);
    const totalPages = Math.ceil(packets.length / packetsPerPage);

    const handleSort = (field: 'number' | 'time' | 'delta' | 'protocol') => {
      if (timingSort.field === field) {
        setTimingSort({
          field,
          direction: timingSort.direction === 'asc' ? 'desc' : 'asc'
        });
      } else {
        setTimingSort({ field, direction: 'asc' });
      }
    };

    // Get the current page packets first
    const currentPagePackets = packets.slice(startIndex, endIndex);
      
    // Calculate deltas only for the current page
      const deltas = new Map();
    currentPagePackets.forEach((packet, index) => {
        if (index === 0 && startIndex === 0) {
          deltas.set(packet.number, 0);
        } else {
        const prevPacket = index === 0 ? packets[startIndex - 1] : currentPagePackets[index - 1];
          const currentTime = new Date(packet.time || 0).getTime();
        const prevTime = new Date(prevPacket?.time || 0).getTime();
          deltas.set(packet.number, currentTime - prevTime);
        }
      });

    // Sort only the current page packets
    const sortedPackets = [...currentPagePackets].sort((a, b) => {
      if (!timingSort.field) return 0;
      
      const direction = timingSort.direction === 'asc' ? 1 : -1;
      
        switch (timingSort.field) {
          case 'number':
            return (a.number - b.number) * direction;
          case 'time':
            return ((new Date(a.time || 0).getTime() - new Date(b.time || 0).getTime())) * direction;
          case 'protocol':
            return ((a.protocol || '').localeCompare(b.protocol || '')) * direction;
          case 'delta':
            const deltaA = deltas.get(a.number) || 0;
            const deltaB = deltas.get(b.number) || 0;
            return (deltaA - deltaB) * direction;
          default:
            return 0;
        }
      });

    return (
      <div className="space-y-6">
        {/* Basic Timing Overview */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Timing Overview</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Capture Duration</p>
              <p className="text-lg font-semibold">
                {(time_range.duration / 1000).toFixed(2)}s
              </p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Total Packets</p>
              <p className="text-lg font-semibold">{packets.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Start Time</p>
              <p className="text-lg font-semibold">
                {new Date(time_range.start).toLocaleTimeString()}
              </p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">End Time</p>
              <p className="text-lg font-semibold">
                {new Date(time_range.end).toLocaleTimeString()}
              </p>
            </div>
          </div>
        </Card>

        {/* Packet Timing Details */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Packet Timing Details</h3>
          <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                  <th 
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                    onClick={() => handleSort('number')}
                  >
                    <div className="flex items-center space-x-1">
                      <span>Packet #</span>
                      <ChevronUpIcon 
                        className={`h-4 w-4 ${timingSort.field === 'number' ? (timingSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                      />
                    </div>
                  </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleSort('time')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Time</span>
                          <ChevronUpIcon 
                          className={`h-4 w-4 ${timingSort.field === 'time' ? (timingSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                          />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleSort('delta')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Delta</span>
                          <ChevronUpIcon 
                          className={`h-4 w-4 ${timingSort.field === 'delta' ? (timingSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                          />
                      </div>
                    </th>
                    <th 
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100"
                      onClick={() => handleSort('protocol')}
                    >
                      <div className="flex items-center space-x-1">
                        <span>Protocol</span>
                          <ChevronUpIcon 
                          className={`h-4 w-4 ${timingSort.field === 'protocol' ? (timingSort.direction === 'desc' ? 'transform rotate-180' : '') : 'opacity-0'}`}
                          />
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {sortedPackets.map((packet) => {
                    const delta = deltas.get(packet.number);
                    return (
                      <tr key={packet.number}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {packet.number}
                      </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {packet.time ? new Date(packet.time).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {delta.toFixed(2)}ms
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {packet.protocol}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="flex justify-between items-center mt-4">
              <div className="text-sm text-gray-500">
                Showing packets {startIndex + 1} to {endIndex} of {packets.length}
              </div>
              <div className="flex items-center space-x-4">
                <Button
                  variant="outline"
                  onClick={handlePrevious}
                  disabled={currentPage === 0}
                >
                  Previous
                </Button>
                <span className="text-sm text-gray-500">
                  Page {currentPage + 1} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  onClick={handleNext}
                  disabled={currentPage >= totalPages - 1}
                >
                  Next
                </Button>
            </div>
          </div>
        </Card>
      </div>
    );
  };

  // Add this useEffect near the top of the component with other hooks
  useEffect(() => {
    if (analysisResults?.trafficSummary) {
    const metrics = {
      maliciousIPs: [] as any[],
        portScans: [] as any[],
        highRiskPorts: [] as any[],
        protocolMisuse: [] as any[],
        authFailures: [] as any[],
        encryptionIssues: [] as any[],
        c2Patterns: [] as any[],
        trafficSpikes: [] as any[]
      };

      const packets = analysisResults.trafficSummary.packets;
      const portActivity = new Map<string, Map<number, { timestamp: number, type: string }>>();
      const highRiskPortMap = new Map<number, { count: number, sources: Set<string> }>();
      const connectionMap = new Map<string, { count: number, bytes: number, timestamps: number[], patterns: Set<string> }>();
      const packetRates = new Map<string, { count: number, bytes: number, protocols: Map<string, number> }>();
      const dnsQueries = new Map<string, { count: number, sizes: number[], patterns: Set<string> }>();
      const authAttempts = new Map<string, { failures: number, timestamps: number[], protocols: Set<string> }>();
      const tlsVersions = new Map<string, { count: number, ciphers: Set<string>, issues: Set<string> }>();

      // Enhanced high-risk ports with severity
      const HIGH_RISK_PORTS = new Map([
        [21, { service: "FTP", severity: "High", reason: "Clear text file transfer" }],
        [22, { service: "SSH", severity: "Medium", reason: "Remote access" }],
        [23, { service: "Telnet", severity: "Critical", reason: "Insecure remote access" }],
        [25, { service: "SMTP", severity: "Medium", reason: "Mail transfer" }],
        [135, { service: "MSRPC", severity: "High", reason: "Windows RPC" }],
        [137, { service: "NetBIOS", severity: "High", reason: "Name service" }],
        [138, { service: "NetBIOS", severity: "High", reason: "Datagram service" }],
        [139, { service: "NetBIOS", severity: "High", reason: "Session service" }],
        [445, { service: "SMB", severity: "Critical", reason: "File sharing" }],
        [3389, { service: "RDP", severity: "High", reason: "Remote desktop" }]
      ]);

      // Enhanced suspicious countries with threat levels
      const SUSPICIOUS_COUNTRIES = new Map([
        ['KP', { threat: 'Critical', reason: 'Known cyber threat actor' }],
        ['IR', { threat: 'High', reason: 'Known cyber threat actor' }],
        ['RU', { threat: 'High', reason: 'Known cyber threat actor' }],
        ['CN', { threat: 'High', reason: 'Known cyber threat actor' }]
      ]);

      // Track sequential port access with enhanced pattern detection
      const trackPortSequence = (source: string, destination: string, port: number, timestamp: number, flags: string) => {
        const key = `${source}-${destination}`;
        if (!portActivity.has(key)) {
          portActivity.set(key, new Map());
        }
        const portMap = portActivity.get(key);
        if (portMap) {
          portMap.set(port, { timestamp, type: flags });

        // Check for sequential scanning
          const ports = Array.from(portMap.entries())
            .sort(([,a], [,b]) => a.timestamp - b.timestamp)
            .map(([p]) => p);

        if (ports.length >= 5) {
            // Sequential port sweep detection
          let sequential = 0;
          for (let i = 1; i < ports.length; i++) {
            if (ports[i] - ports[i-1] === 1) sequential++;
            else sequential = 0;
            
            if (sequential >= 4) {
              metrics.portScans.push({
                source,
                target: destination,
                type: 'Sequential Port Scan',
                timestamp: new Date(timestamp).toISOString(),
                details: `Sequential scan detected: ${ports.slice(i-4, i+1).join(', ')}`
              });
              break;
              }
            }

            // SYN flood detection
            const synCount = Array.from(portMap.values())
              .filter(p => p.type.includes('SYN'))
              .length;
            if (synCount > 50) {
              metrics.portScans.push({
                source,
                target: destination,
                type: 'SYN Flood',
                timestamp: new Date(timestamp).toISOString(),
                details: `${synCount} SYN packets detected in scan window`
              });
            }

            // NULL scan detection
            const nullCount = Array.from(portMap.values())
              .filter(p => p.type.includes('NULL'))
              .length;
            if (nullCount > 10) {
              metrics.portScans.push({
                source,
                target: destination,
                type: 'NULL Scan',
                timestamp: new Date(timestamp).toISOString(),
                details: `${nullCount} NULL packets detected in scan window`
              });
            }
          }
        }
      };

      packets.forEach((packet, index) => {
        const timestamp = new Date(packet.time || 0).getTime();
        const srcPort = parseInt(packet.srcPort);
        const dstPort = parseInt(packet.dstPort);
        const key = `${packet.source}-${packet.destination}`;
        const timeKey = Math.floor(timestamp / 60000).toString();

        // Enhanced port activity tracking
        trackPortSequence(packet.source, packet.destination, dstPort, timestamp, packet.info || '');

        // Enhanced high-risk port tracking
        if (HIGH_RISK_PORTS.has(dstPort)) {
          const portInfo = HIGH_RISK_PORTS.get(dstPort);
          if (!highRiskPortMap.has(dstPort)) {
            highRiskPortMap.set(dstPort, { count: 0, sources: new Set() });
          }
          const portStats = highRiskPortMap.get(dstPort);
          if (portStats) {
            portStats.count++;
            portStats.sources.add(packet.source);
          metrics.highRiskPorts.push({
            port: dstPort,
            protocol: packet.protocol,
              count: portStats.count,
              severity: portInfo?.severity,
              service: portInfo?.service,
              details: `${portInfo?.service} (${portInfo?.reason}) - Access from ${packet.source}`
            });
          }
        }

        // Enhanced connection pattern tracking
        if (!connectionMap.has(key)) {
          connectionMap.set(key, { count: 0, bytes: 0, timestamps: [], patterns: new Set() });
        }
        const conn = connectionMap.get(key);
        if (conn) {
          conn.count++;
          conn.bytes += packet.length;
          conn.timestamps.push(timestamp);

          // Enhanced C2 detection
          if (conn.timestamps.length >= 5) {
            const intervals = [];
            for (let i = 1; i < conn.timestamps.length; i++) {
              intervals.push(conn.timestamps[i] - conn.timestamps[i-1]);
            }
            const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
            const isRegular = intervals.every(interval => 
              Math.abs(interval - avgInterval) < avgInterval * 0.1
            );

            if (isRegular && conn.count > 10) {
              conn.patterns.add('beaconing');
              metrics.c2Patterns.push({
                source: packet.source,
                target: packet.destination,
                pattern: 'Regular Beaconing',
                timestamp: packet.time || '',
                details: `Regular communication every ${(avgInterval/1000).toFixed(2)}s`
              });
            }
          }

          // Enhanced data exfiltration detection
          if (conn.bytes > 1000000) {
            conn.patterns.add('large_transfer');
            metrics.c2Patterns.push({
              source: packet.source,
              target: packet.destination,
              pattern: 'Large Data Transfer',
              timestamp: packet.time || '',
              details: `${(conn.bytes/1024/1024).toFixed(2)}MB transferred`
            });
          }
        }

        // Enhanced DDoS detection
        if (!packetRates.has(timeKey)) {
          packetRates.set(timeKey, { count: 0, bytes: 0, protocols: new Map() });
        }
        const rate = packetRates.get(timeKey);
        if (rate) {
          rate.count++;
          rate.bytes += packet.length;
          rate.protocols.set(packet.protocol, (rate.protocols.get(packet.protocol) || 0) + 1);
        }

        // Enhanced DNS tunneling detection
        if (packet.protocol === 'DNS') {
          const queryKey = `${packet.source}-${packet.destination}`;
          if (!dnsQueries.has(queryKey)) {
            dnsQueries.set(queryKey, { count: 0, sizes: [], patterns: new Set() });
          }
          const query = dnsQueries.get(queryKey);
          if (query) {
            query.count++;
            query.sizes.push(packet.length);

            if (query.count > 100 && query.sizes.every(size => size < 100)) {
              query.patterns.add('tunneling');
              metrics.protocolMisuse.push({
                type: 'DNS Tunneling',
                source: packet.source,
                details: 'High-frequency small DNS queries detected',
                timestamp: packet.time || ''
              });
            }
          }
        }

        // Enhanced protocol misuse detection
        if (packet.protocol === 'ICMP') {
          const icmpKey = `${packet.source}-ICMP`;
          if (!packetRates.has(icmpKey)) {
            packetRates.set(icmpKey, { count: 0, bytes: 0, protocols: new Map() });
          }
          const icmpRate = packetRates.get(icmpKey);
          if (icmpRate && icmpRate.count > 100) {
            metrics.protocolMisuse.push({
              type: 'ICMP Flood',
              source: packet.source,
              details: `${icmpRate.count} ICMP packets in 1 minute`,
              timestamp: packet.time || ''
            });
          }

          if (packet.length > 1000) {
          metrics.protocolMisuse.push({
            type: 'ICMP Tunneling',
            source: packet.source,
            details: `Large ICMP packet detected (${packet.length} bytes)`,
            timestamp: packet.time || ''
          });
          }
        }

        // Enhanced authentication failure detection
        if (packet.info?.toLowerCase().includes('auth fail') || 
            packet.info?.toLowerCase().includes('login failed')) {
          const authKey = `${packet.source}-${packet.protocol}`;
          if (!authAttempts.has(authKey)) {
            authAttempts.set(authKey, { failures: 0, timestamps: [], protocols: new Set() });
          }
          const attempts = authAttempts.get(authKey);
          if (attempts) {
            attempts.failures++;
            attempts.timestamps.push(timestamp);
            attempts.protocols.add(packet.protocol);

            if (attempts.failures >= 5) {
          metrics.authFailures.push({
            protocol: packet.protocol,
            source: packet.source,
            target: packet.destination,
                timestamp: packet.time || '',
                details: `${attempts.failures} failed attempts in ${(timestamp - attempts.timestamps[0])/1000}s across ${attempts.protocols.size} protocols`
              });
            }
          }
        }

        // Enhanced encryption analysis
        if (packet.info?.includes('TLS') || packet.info?.includes('SSL')) {
          const match = packet.info.match(/TLS(?:v1\.?(\d))?|SSL(?:v\d)?/);
          if (match) {
            const version = match[0];
            if (!tlsVersions.has(version)) {
              tlsVersions.set(version, { count: 0, ciphers: new Set(), issues: new Set() });
            }
            const versionStats = tlsVersions.get(version);
            if (versionStats) {
              versionStats.count++;
              
              // Extract cipher information
              const cipherMatch = packet.info.match(/Cipher: ([^\s,]+)/);
              if (cipherMatch) {
                versionStats.ciphers.add(cipherMatch[1]);
              }

            if (version.includes('SSLv3') || version.includes('TLSv1.0')) {
                versionStats.issues.add('outdated_protocol');
          metrics.encryptionIssues.push({
                type: 'Weak Protocol',
                details: `Outdated protocol detected: ${version}`,
            timestamp: packet.time || ''
          });
            }

              // Check for weak ciphers
              if (packet.info.includes('RC4') || packet.info.includes('DES') || 
                  packet.info.includes('MD5')) {
                versionStats.issues.add('weak_cipher');
                metrics.encryptionIssues.push({
                  type: 'Weak Cipher',
                  details: `Weak cipher detected in ${version}`,
                  timestamp: packet.time || ''
                });
              }

              // Check for certificate issues
              if (packet.info.includes('self signed') || 
                  packet.info.includes('expired') || 
                  packet.info.includes('invalid')) {
                versionStats.issues.add('cert_issue');
                metrics.encryptionIssues.push({
                  type: 'Certificate Issue',
                  details: `Certificate problem detected: ${packet.info}`,
                  timestamp: packet.time || ''
                });
              }
            }
          }
        }

        // Enhanced geographic analysis
        if (packet.info?.includes('Country: ')) {
          const countryMatch = packet.info.match(/Country: (\w+)/);
          const country = countryMatch?.[1];
          if (country && SUSPICIOUS_COUNTRIES.has(country)) {
            const countryInfo = SUSPICIOUS_COUNTRIES.get(country);
        metrics.maliciousIPs.push({
          ip: packet.source,
              risk: countryInfo?.threat || 'High',
              country: country,
            timestamp: packet.time || '',
              details: `Traffic from ${country} (${countryInfo?.reason})`
        });
          }
      }
    });

      // Enhanced traffic spike analysis
      packetRates.forEach((rate, timeKey) => {
        const timestamp = new Date(parseInt(timeKey) * 60000);
        const pps = rate.count / 60; // packets per second
        const baseline = 100; // Example baseline

        if (pps > baseline * 2) {
          // Analyze protocol distribution
          const dominantProtocol = Array.from(rate.protocols.entries())
            .reduce((a, b) => a[1] > b[1] ? a : b)[0];
          
          metrics.trafficSpikes.push({
            timestamp: timestamp.toISOString(),
            protocol: dominantProtocol,
            rate: pps,
            baseline,
            details: `${pps.toFixed(2)} packets/sec exceeds baseline of ${baseline} packets/sec (dominant protocol: ${dominantProtocol})`
          });
        }
      });

    setSecurityMetrics(metrics);
    }
  }, [analysisResults]);

  const renderSecurity = () => {
    if (!analysisResults?.trafficSummary) {
      return (
        <Card className="p-4">
          <div className="text-center">
            <h3 className="text-lg font-semibold mb-2">No Security Data Available</h3>
            <p className="text-sm text-gray-500">Please upload a PCAP file to analyze security metrics.</p>
          </div>
        </Card>
      );
    }

    return (
      <div className="space-y-6">
        {/* Security Overview */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Security Overview</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Port Scans</p>
              <p className="text-lg font-semibold">{securityMetrics.portScans.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">High-Risk Port Activity</p>
              <p className="text-lg font-semibold">{securityMetrics.highRiskPorts.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Protocol Misuse</p>
              <p className="text-lg font-semibold">{securityMetrics.protocolMisuse.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Auth Failures</p>
              <p className="text-lg font-semibold">{securityMetrics.authFailures.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Malicious IPs</p>
              <p className="text-lg font-semibold">{securityMetrics.maliciousIPs.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Encryption Issues</p>
              <p className="text-lg font-semibold">{securityMetrics.encryptionIssues.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">C2 Patterns</p>
              <p className="text-lg font-semibold">{securityMetrics.c2Patterns.length}</p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg">
              <p className="text-sm text-gray-500">Traffic Spikes</p>
              <p className="text-lg font-semibold">{securityMetrics.trafficSpikes.length}</p>
            </div>
          </div>
        </Card>

        {/* Port Scans */}
        {securityMetrics.portScans.length > 0 && (
          <Card className="p-4">
            <h3 className="text-lg font-semibold mb-4">Port Scan Detection</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {securityMetrics.portScans.map((scan, index) => (
                    <tr key={index} className="bg-red-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{scan.source}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{scan.target}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{scan.type}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{scan.details}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {new Date(scan.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* High-Risk Port Activity */}
        {securityMetrics.highRiskPorts.length > 0 && (
          <Card className="p-4">
            <h3 className="text-lg font-semibold mb-4">High-Risk Port Activity</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Port</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Count</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {securityMetrics.highRiskPorts.map((port, index) => (
                    <tr key={index} className="bg-yellow-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{port.port}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{port.protocol}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{port.count}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{port.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* Protocol Misuse */}
        {securityMetrics.protocolMisuse.length > 0 && (
          <Card className="p-4">
            <h3 className="text-lg font-semibold mb-4">Protocol Misuse Detection</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {securityMetrics.protocolMisuse.map((misuse, index) => (
                    <tr key={index} className="bg-red-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{misuse.type}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{misuse.source}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{misuse.details}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {new Date(misuse.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* Authentication Failures */}
        {securityMetrics.authFailures.length > 0 && (
          <Card className="p-4">
            <h3 className="text-lg font-semibold mb-4">Authentication Failures</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {securityMetrics.authFailures.map((failure, index) => (
                    <tr key={index} className="bg-yellow-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{failure.protocol}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{failure.source}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{failure.target}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {new Date(failure.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* Malicious IP Detection */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Malicious IP Detection</h3>
          <div className="overflow-x-auto">
            <div className="max-h-[600px] overflow-y-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100">
                      <div className="flex items-center space-x-1">
                        <span>IP Address</span>
                        <ChevronUpIcon className="h-4 w-4 opacity-0" />
                      </div>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100">
                      <div className="flex items-center space-x-1">
                        <span>Risk Level</span>
                        <ChevronUpIcon className="h-4 w-4 opacity-0" />
                      </div>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100">
                      <div className="flex items-center space-x-1">
                        <span>Country</span>
                        <ChevronUpIcon className="h-4 w-4 opacity-0" />
                      </div>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100">
                      <div className="flex items-center space-x-1">
                        <span>Details</span>
                        <ChevronUpIcon className="h-4 w-4 opacity-0" />
                      </div>
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer sticky top-0 bg-gray-50 z-10 hover:bg-gray-100">
                      <div className="flex items-center space-x-1">
                        <span>Timestamp</span>
                        <ChevronUpIcon className="h-4 w-4 opacity-0" />
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {securityMetrics.maliciousIPs
                    .slice(
                      securityPage * securityItemsPerPage,
                      (securityPage + 1) * securityItemsPerPage
                    )
                    .map((ip, index) => (
                        <tr key={index} className="bg-red-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{ip.ip}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                              {ip.risk}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{ip.country}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{ip.details}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {new Date(ip.timestamp).toLocaleString()}
                          </td>
                        </tr>
                    ))}
                </tbody>
              </table>
            </div>
            <div className="flex justify-between items-center mt-4">
              <div className="text-sm text-gray-500">
                Showing IPs {securityPage * securityItemsPerPage + 1} to{' '}
                {Math.min((securityPage + 1) * securityItemsPerPage, securityMetrics.maliciousIPs.length)}{' '}
                of {securityMetrics.maliciousIPs.length}
              </div>
              <div className="flex items-center space-x-4">
                <Button
                  variant="outline"
                  onClick={handleSecurityPrevious}
                  disabled={securityPage === 0}
                >
                  Previous
                </Button>
                <span className="text-sm text-gray-500">
                  Page {securityPage + 1} of{' '}
                  {Math.ceil(securityMetrics.maliciousIPs.length / securityItemsPerPage)}
                </span>
                <Button
                  variant="outline"
                  onClick={handleSecurityNext}
                  disabled={
                    securityPage >=
                    Math.ceil(securityMetrics.maliciousIPs.length / securityItemsPerPage) - 1
                  }
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        </Card>

        {/* C2 Patterns */}
        {securityMetrics.c2Patterns.length > 0 && (
          <Card className="p-4">
            <h3 className="text-lg font-semibold mb-4">Command & Control Patterns</h3>
            <div className="overflow-x-auto">
              <div className="max-h-[600px] overflow-y-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Source</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Target</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Pattern</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                    {securityMetrics.c2Patterns
                      .slice(
                        c2Page * c2ItemsPerPage,
                        (c2Page + 1) * c2ItemsPerPage
                      )
                      .map((pattern, index) => (
                    <tr key={index} className="bg-red-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{pattern.source}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{pattern.target}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{pattern.pattern}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {new Date(pattern.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
              <div className="flex justify-between items-center mt-4">
                <div className="text-sm text-gray-500">
                  Showing patterns {c2Page * c2ItemsPerPage + 1} to{' '}
                  {Math.min((c2Page + 1) * c2ItemsPerPage, securityMetrics.c2Patterns.length)}{' '}
                  of {securityMetrics.c2Patterns.length}
                </div>
                <div className="flex items-center space-x-4">
                  <Button
                    variant="outline"
                    onClick={handleC2Previous}
                    disabled={c2Page === 0}
                  >
                    Previous
                  </Button>
                  <span className="text-sm text-gray-500">
                    Page {c2Page + 1} of{' '}
                    {Math.ceil(securityMetrics.c2Patterns.length / c2ItemsPerPage)}
                  </span>
                  <Button
                    variant="outline"
                    onClick={handleC2Next}
                    disabled={
                      c2Page >=
                      Math.ceil(securityMetrics.c2Patterns.length / c2ItemsPerPage) - 1
                    }
                  >
                    Next
                  </Button>
                </div>
              </div>
            </div>
          </Card>
        )}

        {/* Traffic Spikes */}
        {securityMetrics.trafficSpikes.length > 0 && (
          <Card className="p-4">
            <h3 className="text-lg font-semibold mb-4">Traffic Spikes</h3>
            <div className="overflow-x-auto">
              <div className="max-h-[600px] overflow-y-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Timestamp</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Protocol</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Rate</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider sticky top-0 bg-gray-50 z-10">Baseline</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {securityMetrics.trafficSpikes
                      .slice(
                        spikesPage * spikesItemsPerPage,
                        (spikesPage + 1) * spikesItemsPerPage
                      )
                      .map((spike, index) => (
                        <tr key={index} className="bg-yellow-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {new Date(spike.timestamp).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{spike.protocol}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{spike.rate.toFixed(2)} pps</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{spike.baseline.toFixed(2)} pps</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
              <div className="flex justify-between items-center mt-4">
                <div className="text-sm text-gray-500">
                  Showing spikes {spikesPage * spikesItemsPerPage + 1} to{' '}
                  {Math.min((spikesPage + 1) * spikesItemsPerPage, securityMetrics.trafficSpikes.length)}{' '}
                  of {securityMetrics.trafficSpikes.length}
                </div>
                <div className="flex items-center space-x-4">
                  <Button
                    variant="outline"
                    onClick={handleSpikesPrevious}
                    disabled={spikesPage === 0}
                  >
                    Previous
                  </Button>
                  <span className="text-sm text-gray-500">
                    Page {spikesPage + 1} of{' '}
                    {Math.ceil(securityMetrics.trafficSpikes.length / spikesItemsPerPage)}
                  </span>
                  <Button
                    variant="outline"
                    onClick={handleSpikesNext}
                    disabled={
                      spikesPage >=
                      Math.ceil(securityMetrics.trafficSpikes.length / spikesItemsPerPage) - 1
                    }
                  >
                    Next
                  </Button>
                </div>
              </div>
            </div>
          </Card>
        )}
      </div>
    );
  };

  // Add these data processing functions after the isInternalIP function

  const processProtocolData = (packets: Packet[]) => {
    const protocolCounts = new Map();
    
    packets.forEach(packet => {
      if (!packet.protocol) return;
      protocolCounts.set(
        packet.protocol, 
        (protocolCounts.get(packet.protocol) || 0) + 1
      );
    });

    return Array.from(protocolCounts.entries()).map(([id, value]) => ({
      id,
      label: id,
      value
    }));
  };

  const processTimelineData = (packets: Packet[]) => {
    if (!packets || packets.length === 0) {
      // Return default data structure if no packets
      return [{
        id: "traffic",
        data: [{
          x: new Date().toISOString().slice(0, 16),
          y: 0
        }]
      }];
    }

    const timeData = new Map();
    
    // Find the time range
    let minTime = new Date(packets[0].time || Date.now()).getTime();
    let maxTime = minTime;
    
    packets.forEach(packet => {
      if (!packet.time) return;
      const timestamp = new Date(packet.time).getTime();
      minTime = Math.min(minTime, timestamp);
      maxTime = Math.max(maxTime, timestamp);
      
      const minute = new Date(timestamp).toISOString().slice(0, 16);
      timeData.set(
        minute, 
        (timeData.get(minute) || 0) + packet.length
      );
    });

    // Ensure we have at least two data points
    if (timeData.size < 2) {
      const startTime = new Date(minTime);
      const endTime = new Date(maxTime + 60000); // Add one minute if only one point

    return [{
      id: "traffic",
        data: [
          {
            x: startTime.toISOString().slice(0, 16),
            y: Array.from(timeData.values())[0] || 0
          },
          {
            x: endTime.toISOString().slice(0, 16),
            y: 0
          }
        ]
      }];
    }

    return [{
      id: "traffic",
      data: Array.from(timeData.entries())
        .map(([x, y]) => ({
          x,
          y
        }))
        .sort((a, b) => a.x.localeCompare(b.x))
    }];
  };

  const processTopTalkersData = (packets: Packet[]) => {
    const ipStats = new Map();
    
    packets.forEach(packet => {
      if (!packet.source) return;
      
      if (!ipStats.has(packet.source)) {
        ipStats.set(packet.source, { packets: 0, bytes: 0 });
      }
      const stats = ipStats.get(packet.source);
      stats.packets++;
      stats.bytes += packet.length;
    });

    return Array.from(ipStats.entries())
      .map(([ip, stats]) => ({
        ip,
        ...stats
      }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 10);
  };

  const processPacketSizeData = (packets: Packet[]) => {
    const sizeBuckets = {
      '0-64': 0,
      '65-128': 0,
      '129-256': 0,
      '257-512': 0,
      '513-1024': 0,
      '1025+': 0
    };

    packets.forEach(packet => {
      const size = packet.length;
      if (size <= 64) sizeBuckets['0-64']++;
      else if (size <= 128) sizeBuckets['65-128']++;
      else if (size <= 256) sizeBuckets['129-256']++;
      else if (size <= 512) sizeBuckets['257-512']++;
      else if (size <= 1024) sizeBuckets['513-1024']++;
      else sizeBuckets['1025+']++;
    });

    return Object.entries(sizeBuckets).map(([size, count]) => ({
      size,
      count
    }));
  };

  const renderAnomalyCards = () => {
    // This is a placeholder - implement actual anomaly detection logic
    const anomalies = [
      {
        title: 'High Retransmission Rate',
        description: 'TCP retransmission rate above normal threshold',
        severity: 'warning'
      },
      {
        title: 'Port Scan Detected',
        description: 'Multiple ports accessed in rapid succession',
        severity: 'critical'
      },
      {
        title: 'Unusual Protocol',
        description: 'Detected uncommon protocol usage',
        severity: 'info'
      }
    ];

    return anomalies.map((anomaly, index) => (
      <div 
        key={index}
        className={`p-4 rounded-lg border ${
          anomaly.severity === 'critical' 
            ? 'border-red-200 bg-red-50' 
            : anomaly.severity === 'warning'
            ? 'border-yellow-200 bg-yellow-50'
            : 'border-blue-200 bg-blue-50'
        }`}
      >
        <h5 className="font-medium mb-1">{anomaly.title}</h5>
        <p className="text-sm text-gray-600">{anomaly.description}</p>
      </div>
    ));
  };

  // Add useEffect for auto-scrolling
  useEffect(() => {
    if (scrollAreaRef.current) {
      const scrollContainer = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]')
      if (scrollContainer) {
        const smoothScroll = () => {
          scrollContainer.scrollTo({
            top: scrollContainer.scrollHeight,
            behavior: 'smooth'
          });
        };
        smoothScroll();
        // Ensure scroll happens after content is rendered
        setTimeout(smoothScroll, 100);
      }
    }
  }, [messages, isLoading]);

  return (
    <div className="flex h-screen">
      {/* Left Sidebar with Functions */}
      <div className="w-1/4 min-w-[300px] border-r p-4 bg-gray-50 flex flex-col">
        <h1 className="text-2xl font-bold mb-4 text-center">PcapLyzer</h1>
        <Card className="p-4 mb-4">
          <FileUpload 
            onFileUpload={handleFileUpload}
            onError={handleUploadError}
            onSuccess={handleUploadSuccess}
          />
          <Button 
            onClick={handleAnalysis} 
            disabled={!file || isLoading}
            className="mt-4 w-full"
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              'Analyze'
            )}
          </Button>
        </Card>

        {/* Chat Section */}
        <Card className="p-4 flex-1 flex flex-col h-0">
          <h2 className="text-lg font-semibold mb-4">Chat Assistant</h2>
          <div className="flex-1 overflow-hidden flex flex-col">
            <ScrollArea ref={scrollAreaRef} className="flex-1 pr-4 overflow-y-auto">
              <div className="space-y-4">
                {messages.map((message, index) => (
                  <div
                    key={message.id}
                    className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div className="flex flex-col max-w-[80%]">
                      <div
                        className={`rounded-lg p-3 ${
                          message.role === 'user'
                            ? 'bg-blue-500 text-white'
                            : 'bg-gray-100 text-gray-900'
                        }`}
                      >
                        {message.content}
                        {message.role === 'assistant' && (
                          <div className="mt-2 pt-2 border-t border-gray-200">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleSaveChat(message.id)}
                              className="text-xs text-gray-500 hover:text-gray-700"
                            >
                              Save conversation up to this point
                            </Button>
                          </div>
                        )}
                      </div>
                      <span 
                        className={`text-xs mt-1 ${
                          message.role === 'user' ? 'text-right' : 'text-left'
                        } text-gray-500`}
                      >
                        {new Date(message.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                ))}
                {isLoading && (
                  <div className="flex justify-start">
                    <div className="bg-gray-100 rounded-lg p-3">
                      <Loader2 className="h-5 w-5 animate-spin" />
                    </div>
                  </div>
                )}
              </div>
            </ScrollArea>
          </div>
          <form onSubmit={handleSendMessage} className="flex gap-2 mt-4">
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder={file ? "Ask about your PCAP analysis..." : "Upload a PCAP file first"}
              className="flex-1 px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={isLoading || !file}
            />
            <Button 
              type="submit" 
              disabled={isLoading || !inputMessage.trim() || !file}
              className="transition-all duration-200 hover:bg-blue-600"
            >
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Send'}
            </Button>
          </form>
        </Card>
      </div>

      {/* Right Content Area */}
      <div className="flex-1 p-4 overflow-auto">
        <div className="max-w-4xl mx-auto">
          {/* Toast-like messages */}
          <div className="fixed top-4 right-4 z-50 space-y-2">
            {error && (
              <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-2 rounded shadow-lg">
                {error}
              </div>
            )}
            {success && (
              <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-2 rounded shadow-lg">
                {success}
              </div>
            )}
          </div>

          {!file ? (
            <div className="text-center text-gray-500 mt-20">
              <h2 className="text-3xl font-semibold mb-4 tracking-wide">Welcome to PcapLyzer</h2>
              <p className="text-xl">Upload your PCAP file and let the magic of packet analysis begin!</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h2 className="text-2xl font-bold">Analysis Results: {file.name}</h2>
              </div>
              
              {analysisResults && (
                <div>
                  <div className="flex flex-wrap gap-2 border-b pb-2">
                    <Button
                      variant={activeTab === 'overview' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('overview')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Overview
                    </Button>
                    <Button
                      variant={activeTab === 'protocols' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('protocols')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Protocols
                    </Button>
                    <Button
                      variant={activeTab === 'ports' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('ports')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Ports
                    </Button>
                    <Button
                      variant={activeTab === 'conversation' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('conversation')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Conversation
                    </Button>
                    <Button
                      variant={activeTab === 'flow-stats' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('flow-stats')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Flow Stats
                    </Button>
                    <Button
                      variant={activeTab === 'top-talkers' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('top-talkers')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Top Talkers
                    </Button>
                    <Button
                      variant={activeTab === 'bandwidth' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('bandwidth')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Bandwidth
                    </Button>
                    <Button
                      variant={activeTab === 'anomalies' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('anomalies')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Anomalies
                    </Button>
                    <Button
                      variant={activeTab === 'http-traffic' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('http-traffic')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      HTTP/HTTPS
                    </Button>
                    <Button
                      variant={activeTab === 'dns-analysis' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('dns-analysis')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      DNS
                    </Button>
                    <Button
                      variant={activeTab === 'icmp-arp' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('icmp-arp')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      ICMP/ARP
                    </Button>
                    <Button
                      variant={activeTab === 'timing' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('timing')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Timing
                    </Button>
                    <Button
                      variant={activeTab === 'security' ? 'default' : 'ghost'}
                      onClick={() => setActiveTab('security')}
                      className="px-3 py-1 text-sm h-9"
                    >
                      Security
                    </Button>
                  </div>

                  <div className="mt-4">
                    {activeTab === 'overview' && renderOverview()}
                    {activeTab === 'protocols' && renderProtocols()}
                    {activeTab === 'ports' && renderPorts()}
                    {activeTab === 'dns' && renderDNS()}
                    {activeTab === 'packets' && renderPackets()}
                    {activeTab === 'conversation' && renderConversation()}
                    {activeTab === 'flow-stats' && renderFlowStats()}
                    {activeTab === 'top-talkers' && renderTopTalkers()}
                    {activeTab === 'bandwidth' && renderBandwidth()}
                    {activeTab === 'anomalies' && renderAnomalies()}
                    {activeTab === 'http-traffic' && renderHttpTraffic()}
                    {activeTab === 'dns-analysis' && renderDnsAnalysis()}
                    {activeTab === 'icmp-arp' && renderIcmpArp()}
                    {activeTab === 'timing' && renderTiming()}
                    {activeTab === 'security' && renderSecurity()}
                  </div>
                </div>
              )}
              
              {isLoading && (
                <div className="flex justify-center items-center p-8">
                  <div className="flex items-center space-x-2">
                    <Loader2 className="h-6 w-6 animate-spin" />
                    <span>Analyzing file...</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

