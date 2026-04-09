import { execFile } from 'child_process'
import fs from 'fs'
import { promisify } from 'util'
import { NextResponse } from 'next/server'
import { enforceApiGuard } from '@/lib/api-guard'
import { resolveUploadedFilePath } from '@/lib/upload-storage'

const execFileAsync = promisify(execFile)
const maxBufferMb = Number(process.env.TSHARK_MAX_BUFFER_MB || 100)
const EXEC_OPTIONS = { maxBuffer: maxBufferMb * 1024 * 1024 }

function sanitizeErrorMessage(error: unknown, fallback: string) {
  if (error instanceof Error && error.message) {
    return error.message.replace(/([A-Za-z]:\\[^\s]+|\/[^\s]+)/g, '[path]')
  }

  return fallback
}

function getTsharkCandidates() {
  return [
    process.env.TSHARK_PATH,
    'tshark',
    'C:\\Program Files\\Wireshark\\tshark.exe',
    'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
    process.env.WIRESHARK_PATH
  ].filter((value): value is string => Boolean(value))
}

async function runCommand(command: string, args: string[]) {
  return execFileAsync(command, args, EXEC_OPTIONS)
}

async function findTsharkExecutable() {
  for (const candidate of getTsharkCandidates()) {
    try {
      await runCommand(candidate, ['-v'])
      return candidate
    } catch {
      // try next candidate
    }
  }

  throw new Error('Tshark is not available. Please install Wireshark and ensure tshark is on PATH.')
}

export async function POST(request: Request) {
  try {
    const guard = enforceApiGuard(request.headers)
    if (!guard.ok) {
      return NextResponse.json(
        { error: guard.message },
        {
          status: guard.status || 429,
          headers: guard.headers
        }
      )
    }

    const { fileName } = await request.json()
    if (!fileName || typeof fileName !== 'string') {
      return NextResponse.json({ error: 'No file name provided' }, { status: 400 })
    }

    const filePath = await resolveUploadedFilePath(fileName)

    try {
      await fs.promises.access(filePath, fs.constants.R_OK)
    } catch {
      return NextResponse.json({ error: 'File not found or not readable' }, { status: 404 })
    }

    const fileStats = fs.statSync(filePath)
    const fileSize = fileStats.size
    const tsharkPath = await findTsharkExecutable()

    try {
      await runCommand(tsharkPath, ['-r', filePath, '-c', '1'])
    } catch (error) {
      return NextResponse.json(
        {
          error: 'Invalid PCAP file. Please ensure the file is a valid PCAP/PCAPNG file.',
          details: sanitizeErrorMessage(error, 'Failed to validate capture file')
        },
        { status: 400 }
      )
    }

    try {
      const { stdout: packetInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'frame.time_epoch'])
      const timestamps = packetInfo.split('\n').filter(Boolean).map(Number)
      const packetCount = timestamps.length

      if (packetCount === 0) {
        return NextResponse.json({
          trafficSummary: {
            file_size: fileSize,
            total_bytes: 0,
            packet_count: 0,
            time_range: {
              start: null,
              end: null,
              duration: 0,
              file_created: fileStats.birthtime.toISOString(),
              file_modified: fileStats.mtime.toISOString()
            },
            protocol_counts: {},
            packet_sizes: { min: 0, max: 0, average: 0 },
            ip_addresses: { source: [], destination: [] },
            protocols: [],
            tcp_ports: [],
            udp_ports: [],
            dns_queries: [],
            packets: [],
            conversations: [],
            flowStats: []
          }
        })
      }

      const firstEpoch = Math.min(...timestamps)
      const lastEpoch = Math.max(...timestamps)

      const { stdout: protocolInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'frame.protocols'])
      const protocols = protocolInfo
        .split('\n')
        .filter(Boolean)
        .flatMap((line) => line.split(':'))
        .filter((protocol) => protocol.length > 0)

      const protocolCounts = protocols.reduce<Record<string, number>>((counts, protocol) => {
        counts[protocol] = (counts[protocol] || 0) + 1
        return counts
      }, {})

      const { stdout: ipInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'])
      const sourceIPs = new Set<string>()
      const destIPs = new Set<string>()
      ipInfo.split('\n').filter(Boolean).forEach((line) => {
        const [src, dst] = line.split('\t')
        if (src) sourceIPs.add(src)
        if (dst) destIPs.add(dst)
      })

      const { stdout: tcpInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'tcp.srcport', '-e', 'tcp.dstport'])
      const { stdout: udpInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'udp.srcport', '-e', 'udp.dstport'])

      const tcpPorts = new Set<number>()
      const udpPorts = new Set<number>()

      tcpInfo.split('\n').filter(Boolean).forEach((line) => {
        line.split('\t').forEach((port) => {
          if (port) tcpPorts.add(Number(port))
        })
      })

      udpInfo.split('\n').filter(Boolean).forEach((line) => {
        line.split('\t').forEach((port) => {
          if (port) udpPorts.add(Number(port))
        })
      })

      const { stdout: packetDetails } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst', '-e', '_ws.col.Protocol', '-e', 'frame.len', '-e', '_ws.col.Info'])
      const packets = packetDetails
        .split('\n')
        .filter(Boolean)
        .map((line) => {
          const [number, timeEpoch, src, dst, protocol, length, info] = line.split('\t')
          return {
            number: Number(number),
            time: timeEpoch ? new Date(Number(timeEpoch) * 1000).toISOString() : null,
            source: src || '',
            destination: dst || '',
            protocol: protocol || '',
            length: Number(length) || 0,
            info: info || ''
          }
        })

      const { stdout: dnsInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'dns.qry.name', '-e', 'dns.qry.type', '-e', 'dns.resp.name', '-e', 'dns.a', '-e', 'dns.aaaa', '-e', 'dns.cname', '-e', 'dns.txt', '-Y', 'dns.flags.response eq 0 or dns.flags.response eq 1'])
      const dnsQueries = dnsInfo
        .split('\n')
        .filter(Boolean)
        .map((line) => {
          const [qname, qtype, , a, aaaa, cname, txt] = line.split('\t')
          return {
            query: qname,
            type: getDnsType(qtype || ''),
            responses: [a, aaaa, cname, txt].filter(Boolean)
          }
        })
        .filter((query) => query.query)

      const { stdout: convInfo } = await runCommand(tsharkPath, ['-r', filePath, '-q', '-z', 'conv,ip'])
      const conversations = convInfo
        .split('\n')
        .filter((line) => !line.includes('Filter:') && !line.includes('=======') && line.trim() !== '')
        .map((line) => {
          const parts = line.trim().split(/\s+/)
          if (parts.length >= 7) {
            const sourceIp = parts[0]
            const destinationIp = parts[2]
            const totals = parts[5]
            const timing = parts[6]

            if (!sourceIp || !destinationIp || !totals || !timing) {
              return null
            }

            const [totalFrames, totalBytes] = totals.split(':').map(Number)
            const [, duration] = timing.split(':').map(Number)

            return {
              sourceIp,
              destinationIp,
              protocol: 'IP',
              packetCount: totalFrames,
              dataVolume: totalBytes,
              duration,
              hasErrors: false,
              hasRetransmissions: false
            }
          }
          return null
        })
        .filter(Boolean)

      const { stdout: retransInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-Y', 'tcp.analysis.retransmission'])
      const retransmissions = new Set<string>()
      retransInfo.split('\n').filter(Boolean).forEach((line) => {
        const [src, dst] = line.split('\t')
        if (src && dst) retransmissions.add(`${src}-${dst}`)
      })

      conversations.forEach((conv) => {
        if (conv && retransmissions.has(`${conv.sourceIp}-${conv.destinationIp}`)) {
          conv.hasRetransmissions = true
        }
      })

      const { stdout: tcpFlowInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.flags', '-e', 'tcp.analysis.ack_rtt', '-e', 'tcp.analysis.retransmission', '-e', 'frame.len', '-Y', 'tcp'])
      const tcpFlows = new Map<string, {
        sourceIp: string
        destinationIp: string
        protocol: string
        handshakeStatus: { syn: string; synAck: string; ack: string }
        rttStats: { min: number; max: number; total: number; count: number }
        retransmissionCount: number
        rstCount: number
        totalBytes: number
        startTime: number
        endTime: number
      }>()

      tcpFlowInfo.split('\n').filter(Boolean).forEach((line) => {
        const [timeEpoch, src, dst, flags, rtt, retrans, len] = line.split('\t')
        if (!timeEpoch || !src || !dst) {
          return
        }
        const key = `${src}-${dst}`

        if (!tcpFlows.has(key)) {
          tcpFlows.set(key, {
            sourceIp: src,
            destinationIp: dst,
            protocol: 'TCP',
            handshakeStatus: { syn: 'X', synAck: 'X', ack: 'X' },
            rttStats: { min: Number.MAX_VALUE, max: 0, total: 0, count: 0 },
            retransmissionCount: 0,
            rstCount: 0,
            totalBytes: 0,
            startTime: parseFloat(timeEpoch),
            endTime: parseFloat(timeEpoch)
          })
        }

        const flow = tcpFlows.get(key)
        if (!flow) return

        flow.totalBytes += parseInt(len || '0', 10) || 0
        flow.endTime = parseFloat(timeEpoch)

        if (flags) {
          if (flags.includes('0x002')) flow.handshakeStatus.syn = 'SYN'
          if (flags.includes('0x012')) flow.handshakeStatus.synAck = 'SYN-ACK'
          if (flags.includes('0x010')) flow.handshakeStatus.ack = 'ACK'
          if (flags.includes('0x004')) flow.rstCount += 1
        }

        if (rtt && !Number.isNaN(parseFloat(rtt))) {
          const rttValue = parseFloat(rtt) * 1000
          flow.rttStats.min = Math.min(flow.rttStats.min, rttValue)
          flow.rttStats.max = Math.max(flow.rttStats.max, rttValue)
          flow.rttStats.total += rttValue
          flow.rttStats.count += 1
        }

        if (retrans) flow.retransmissionCount += 1
      })

      const { stdout: udpFlowInfo } = await runCommand(tsharkPath, ['-r', filePath, '-T', 'fields', '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len', '-Y', 'udp'])
      const udpFlows = new Map<string, { sourceIp: string; destinationIp: string; protocol: string; totalBytes: number; startTime: number; endTime: number }>()

      udpFlowInfo.split('\n').filter(Boolean).forEach((line) => {
        const [timeEpoch, src, dst, len] = line.split('\t')
        if (!timeEpoch || !src || !dst) {
          return
        }
        const key = `${src}-${dst}`

        if (!udpFlows.has(key)) {
          udpFlows.set(key, {
            sourceIp: src,
            destinationIp: dst,
            protocol: 'UDP',
            totalBytes: 0,
            startTime: parseFloat(timeEpoch),
            endTime: parseFloat(timeEpoch)
          })
        }

        const flow = udpFlows.get(key)
        if (!flow) return
        flow.totalBytes += parseInt(len || '0', 10) || 0
        flow.endTime = parseFloat(timeEpoch)
      })

      const flowStats = [
        ...Array.from(tcpFlows.values()).map((flow) => {
          const duration = flow.endTime - flow.startTime
          return {
            ...flow,
            rttStats: flow.rttStats.count > 0
              ? {
                  min: Number(flow.rttStats.min.toFixed(2)),
                  max: Number(flow.rttStats.max.toFixed(2)),
                  average: Number((flow.rttStats.total / flow.rttStats.count).toFixed(2))
                }
              : null,
            throughput: duration > 0 ? flow.totalBytes / duration : 0
          }
        }),
        ...Array.from(udpFlows.values()).map((flow) => {
          const duration = flow.endTime - flow.startTime
          return {
            ...flow,
            rttStats: null,
            handshakeStatus: null,
            retransmissionCount: 0,
            throughput: duration > 0 ? flow.totalBytes / duration : 0
          }
        })
      ]

      return NextResponse.json({
        trafficSummary: {
          file_size: fileSize,
          total_bytes: packets.reduce((sum, packet) => sum + packet.length, 0),
          packet_count: packetCount,
          time_range: {
            start: new Date(firstEpoch * 1000).toISOString(),
            end: new Date(lastEpoch * 1000).toISOString(),
            duration: lastEpoch - firstEpoch,
            file_created: fileStats.birthtime.toISOString(),
            file_modified: fileStats.mtime.toISOString()
          },
          protocol_counts: protocolCounts,
          packet_sizes: {
            min: Math.min(...packets.map((packet) => packet.length)),
            max: Math.max(...packets.map((packet) => packet.length)),
            average: packets.reduce((sum, packet) => sum + packet.length, 0) / packets.length
          },
          ip_addresses: {
            source: Array.from(sourceIPs),
            destination: Array.from(destIPs)
          },
          protocols: Object.keys(protocolCounts),
          tcp_ports: Array.from(tcpPorts),
          udp_ports: Array.from(udpPorts),
          dns_queries: dnsQueries,
          packets,
          conversations,
          flowStats
        }
      })
    } catch (error) {
      console.error('Analysis error:', error)
      return NextResponse.json(
        {
          error: 'Failed to analyze the PCAP file',
          details: sanitizeErrorMessage(error, 'Analysis failed')
        },
        { status: 500 }
      )
    }
  } catch (error) {
    console.error('Request handling error:', error)
    return NextResponse.json(
      {
        error: 'Failed to process the request',
        details: sanitizeErrorMessage(error, 'Request failed')
      },
      { status: 500 }
    )
  }
}

function getDnsType(type: string): string {
  const dnsTypes: Record<string, string> = {
    '1': 'A',
    '2': 'NS',
    '5': 'CNAME',
    '6': 'SOA',
    '12': 'PTR',
    '15': 'MX',
    '16': 'TXT',
    '28': 'AAAA',
    '33': 'SRV',
    '35': 'NAPTR',
    '39': 'DNAME',
    '43': 'DS',
    '46': 'RRSIG',
    '47': 'NSEC',
    '48': 'DNSKEY',
    '50': 'NSEC3',
    '51': 'NSEC3PARAM',
    '52': 'TLSA',
    '99': 'SPF',
    '255': 'ANY'
  }

  return dnsTypes[type] || `TYPE${type}`
}
