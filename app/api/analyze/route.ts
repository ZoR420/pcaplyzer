import { NextResponse } from 'next/server'
import { exec } from 'child_process'
import { promisify } from 'util'
import path from 'path'
import fs from 'fs'

const execAsync = promisify(exec)

// Set a larger buffer size for tshark output (100MB)
const EXEC_OPTIONS = { maxBuffer: 100 * 1024 * 1024 }

// Check if tshark is available
async function isTsharkAvailable() {
  try {
    // First try the direct command
    try {
      await execAsync('tshark --version', EXEC_OPTIONS)
      return true
    } catch (error) {
      console.warn('Direct tshark command failed, checking common installation paths...')
    }

    // Check common installation paths on Windows
    const commonPaths = [
      'C:\\Program Files\\Wireshark\\tshark.exe',
      'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
      process.env.WIRESHARK_PATH // Allow custom path through environment variable
    ].filter(Boolean) // Remove undefined paths

    for (const path of commonPaths) {
      try {
        await execAsync(`"${path}" --version`, EXEC_OPTIONS)
        console.log(`Found tshark at: ${path}`)
        // If found, set it as an environment variable for future use
        process.env.TSHARK_PATH = path
        return true
      } catch (error) {
        console.warn(`Tshark not found at: ${path}`)
      }
    }

    // If we get here, tshark was not found
    console.warn(`
      Tshark is not installed or not in PATH. 
      Please install Wireshark from https://www.wireshark.org/download.html
      
      Installation tips:
      1. Windows: Make sure to check "Add Wireshark to the system PATH" during installation
      2. macOS: Install via 'brew install wireshark'
      3. Linux: Install via 'sudo apt-get install tshark' or equivalent
    `)
    return false
  } catch (error) {
    console.error('Error checking for tshark:', error)
    return false
  }
}

// Function to get tshark command with proper path
function getTsharkCommand() {
  return process.env.TSHARK_PATH ? `"${process.env.TSHARK_PATH}"` : 'tshark'
}

// Basic file analysis without tshark
function analyzeFileBasic(filePath: string) {
  const stats = fs.statSync(filePath)
  return {
    file_size: stats.size,
    created_at: stats.birthtime.toISOString(),
    modified_at: stats.mtime.toISOString(),
    access_at: stats.atime.toISOString()
  }
}

export async function POST(request: Request) {
  try {
    const { fileName } = await request.json()
    console.log('Analyze request received for file:', fileName)
    
    if (!fileName) {
      console.log('No filename provided')
      return NextResponse.json(
        { error: 'No file name provided' },
        { status: 400 }
      )
    }

    const uploadsDir = path.join(process.cwd(), 'uploads')
    const filePath = path.join(uploadsDir, fileName)
    console.log('Looking for file at:', filePath)

    // Check if file exists and is readable
    try {
      await fs.promises.access(filePath, fs.constants.R_OK)
      console.log('File exists and is readable')
    } catch (error) {
      console.error('File access error:', error)
      return NextResponse.json(
        { error: 'File not found or not readable' },
        { status: 404 }
      )
    }

    // Get basic file stats
    const fileStats = fs.statSync(filePath)
    const fileSize = fileStats.size
    console.log('File stats:', { size: fileSize, created: fileStats.birthtime, modified: fileStats.mtime })

    // Check if tshark is available and get its path
    let tsharkPath = 'tshark'
    try {
      // Try common Wireshark installation paths on Windows
      const commonPaths = [
        'C:\\Program Files\\Wireshark\\tshark.exe',
        'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
        process.env.WIRESHARK_PATH
      ].filter(Boolean)

      for (const path of commonPaths) {
        if (path && fs.existsSync(path)) {
          tsharkPath = `"${path}"`
          console.log('Found tshark at:', path)
          break
        }
      }
    } catch (error) {
      console.error('Error finding tshark:', error)
    }

    // Test if tshark is working
    try {
      const { stdout } = await execAsync(`${tsharkPath} -v`, EXEC_OPTIONS)
      console.log('Tshark version:', stdout.split('\n')[0])
    } catch (error) {
      console.error('Tshark not available:', error)
      return NextResponse.json({
        error: 'Tshark is not available. Please install Wireshark.',
        details: error instanceof Error ? error.message : 'Unknown error'
      }, { status: 500 })
    }

    // Test if file is a valid PCAP
    try {
      const { stdout } = await execAsync(`${tsharkPath} -r "${filePath}" -c 1`, EXEC_OPTIONS)
      console.log('PCAP validation successful')
    } catch (error) {
      console.error('Invalid PCAP file:', error)
      return NextResponse.json({
        error: 'Invalid PCAP file. Please ensure the file is a valid PCAP/PCAPNG file.',
        details: error instanceof Error ? error.message : 'Unknown error'
      }, { status: 400 })
    }

    // Get packet count and timestamps
    try {
      const { stdout: packetInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e frame.time_epoch`,
        EXEC_OPTIONS
      )
      const timestamps = packetInfo.split('\n').filter(Boolean).map(Number)
      const packetCount = timestamps.length
      const firstEpoch = Math.min(...timestamps)
      const lastEpoch = Math.max(...timestamps)
      
      console.log('Packet analysis:', {
        count: packetCount,
        firstPacket: new Date(firstEpoch * 1000),
        lastPacket: new Date(lastEpoch * 1000)
      })

      // Get protocols
      const { stdout: protocolInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e frame.protocols`,
        EXEC_OPTIONS
      )
      const protocols = protocolInfo
        .split('\n')
        .filter(Boolean)
        .flatMap(line => line.split(':'))
        .filter(protocol => protocol.length > 0)

      const protocolCounts = protocols.reduce((counts: Record<string, number>, protocol: string) => {
        counts[protocol] = (counts[protocol] || 0) + 1
        return counts
      }, {})

      // Get IP addresses
      const { stdout: ipInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e ip.src -e ip.dst`,
        EXEC_OPTIONS
      )
      const sourceIPs = new Set<string>()
      const destIPs = new Set<string>()
      
      ipInfo.split('\n').filter(Boolean).forEach(line => {
        const [src, dst] = line.split('\t')
        if (src) sourceIPs.add(src)
        if (dst) destIPs.add(dst)
      })

      // Get ports
      const { stdout: tcpInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e tcp.srcport -e tcp.dstport`,
        EXEC_OPTIONS
      )
      const { stdout: udpInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e udp.srcport -e udp.dstport`,
        EXEC_OPTIONS
      )

      const tcpPorts = new Set<number>()
      const udpPorts = new Set<number>()

      tcpInfo.split('\n').filter(Boolean).forEach(line => {
        line.split('\t').forEach(port => {
          if (port) tcpPorts.add(Number(port))
        })
      })

      udpInfo.split('\n').filter(Boolean).forEach(line => {
        line.split('\t').forEach(port => {
          if (port) udpPorts.add(Number(port))
        })
      })

      // Get packet details
      const { stdout: packetDetails } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info`,
        EXEC_OPTIONS
      )

      const packets = packetDetails
        .split('\n')
        .filter(Boolean)
        .map(line => {
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

      // Get DNS queries
      const { stdout: dnsInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e dns.qry.name -e dns.qry.type -e dns.resp.name -e dns.a -e dns.aaaa -e dns.cname -e dns.txt -Y "dns.flags.response eq 0 or dns.flags.response eq 1"`,
        EXEC_OPTIONS
      )

      const dnsQueries = dnsInfo
        .split('\n')
        .filter(Boolean)
        .map(line => {
          const [qname, qtype, rname, a, aaaa, cname, txt] = line.split('\t')
          return {
            query: qname,
            type: getDnsType(qtype),
            responses: [a, aaaa, cname, txt].filter(Boolean)
          }
        })
        .filter(query => query.query)

      // Get conversations
      const { stdout: convInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -q -z conv,ip`,
        EXEC_OPTIONS
      )

      const conversations = convInfo
        .split('\n')
        .filter(line => !line.includes('Filter:') && !line.includes('=======') && line.trim() !== '')
        .map(line => {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 7) {
            const [sourceIp, , destinationIp, framesAtoB, framesBtoA, totals, timing] = parts;
            
            // Parse frames and bytes
            const [totalFrames, totalBytes] = totals.split(':').map(Number);
            const [startTime, duration] = timing.split(':').map(Number);

            return {
              sourceIp,
              destinationIp,
              protocol: 'IP',
              packetCount: totalFrames,
              dataVolume: totalBytes,
              duration: duration,
              hasErrors: false,
              hasRetransmissions: false
            };
          }
          return null;
        })
        .filter(Boolean);

      // Get TCP retransmissions
      const { stdout: retransInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e ip.src -e ip.dst -Y "tcp.analysis.retransmission"`,
        EXEC_OPTIONS
      )

      const retransmissions = new Set();
      retransInfo.split('\n').filter(Boolean).forEach(line => {
        const [src, dst] = line.split('\t');
        if (src && dst) {
          retransmissions.add(`${src}-${dst}`);
        }
      });

      // Mark conversations with retransmissions
      conversations.forEach(conv => {
        if (conv && retransmissions.has(`${conv.sourceIp}-${conv.destinationIp}`)) {
          conv.hasRetransmissions = true;
        }
      });

      // Get TCP flow statistics
      const { stdout: tcpFlowInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.flags -e tcp.analysis.ack_rtt -e tcp.analysis.retransmission -e frame.len -Y "tcp"`,
        EXEC_OPTIONS
      )

      const tcpFlows = new Map();
      tcpFlowInfo.split('\n').filter(Boolean).forEach(line => {
        const [timeEpoch, src, dst, flags, rtt, retrans, len] = line.split('\t');
        const key = `${src}-${dst}`;
        
        if (!tcpFlows.has(key)) {
          tcpFlows.set(key, {
            sourceIp: src,
            destinationIp: dst,
            protocol: 'TCP',
            handshakeStatus: {
              syn: 'X',
              synAck: 'X',
              ack: 'X'
            },
            rttStats: {
              min: Number.MAX_VALUE,
              max: 0,
              total: 0,
              count: 0
            },
            retransmissionCount: 0,
            rstCount: 0,
            totalBytes: 0,
            startTime: parseFloat(timeEpoch),
            endTime: parseFloat(timeEpoch)
          });
        }

        const flow = tcpFlows.get(key);
        flow.totalBytes += parseInt(len) || 0;
        flow.endTime = parseFloat(timeEpoch);

        // Update handshake status
        if (flags) {
          // SYN flag (0x02)
          if (flags.includes('0x002')) {
            flow.handshakeStatus.syn = 'SYN';
          }
          
          // SYN-ACK flag (0x12)
          if (flags.includes('0x012')) {
            flow.handshakeStatus.synAck = 'SYN-ACK';
          }
          
          // ACK flag (0x10)
          if (flags.includes('0x010')) {
            flow.handshakeStatus.ack = 'ACK';
          }
          
          // RST flag (0x04)
          if (flags.includes('0x004')) {
            flow.rstCount++;
          }
        }

        // Update RTT stats
        if (rtt && !isNaN(parseFloat(rtt))) {
          const rttValue = parseFloat(rtt) * 1000; // Convert to milliseconds
          flow.rttStats.min = Math.min(flow.rttStats.min, rttValue);
          flow.rttStats.max = Math.max(flow.rttStats.max, rttValue);
          flow.rttStats.total += rttValue;
          flow.rttStats.count++;
        }

        // Count retransmissions
        if (retrans) {
          flow.retransmissionCount++;
        }
      });

      // Get UDP flow statistics
      const { stdout: udpFlowInfo } = await execAsync(
        `${tsharkPath} -r "${filePath}" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len -Y "udp"`,
        EXEC_OPTIONS
      )

      const udpFlows = new Map();
      udpFlowInfo.split('\n').filter(Boolean).forEach(line => {
        const [timeEpoch, src, dst, len] = line.split('\t');
        const key = `${src}-${dst}`;
        
        if (!udpFlows.has(key)) {
          udpFlows.set(key, {
            sourceIp: src,
            destinationIp: dst,
            protocol: 'UDP',
            totalBytes: 0,
            startTime: parseFloat(timeEpoch),
            endTime: parseFloat(timeEpoch)
          });
        }

        const flow = udpFlows.get(key);
        flow.totalBytes += parseInt(len) || 0;
        flow.endTime = parseFloat(timeEpoch);
      });

      // Process flow statistics
      const flowStats = [
        ...Array.from(tcpFlows.values()).map(flow => {
          const duration = flow.endTime - flow.startTime;
          return {
            ...flow,
            rttStats: flow.rttStats.count > 0 ? {
              min: Number(flow.rttStats.min.toFixed(2)),
              max: Number(flow.rttStats.max.toFixed(2)),
              average: Number((flow.rttStats.total / flow.rttStats.count).toFixed(2))
            } : null,
            throughput: duration > 0 ? flow.totalBytes / duration : 0
          };
        }),
        ...Array.from(udpFlows.values()).map(flow => {
          const duration = flow.endTime - flow.startTime;
          return {
            ...flow,
            rttStats: null,
            handshakeStatus: null,
            retransmissionCount: 0,
            throughput: duration > 0 ? flow.totalBytes / duration : 0
          };
        })
      ];

      const results = {
        trafficSummary: {
          file_size: fileSize,
          total_bytes: packets.reduce((sum, p) => sum + p.length, 0),
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
            min: Math.min(...packets.map(p => p.length)),
            max: Math.max(...packets.map(p => p.length)),
            average: packets.reduce((sum, p) => sum + p.length, 0) / packets.length
          },
          ip_addresses: {
            source: Array.from(sourceIPs),
            destination: Array.from(destIPs)
          },
          protocols: Object.keys(protocolCounts),
          tcp_ports: Array.from(tcpPorts),
          udp_ports: Array.from(udpPorts),
          dns_queries: dnsQueries,
          packets: packets,
          conversations: conversations,
          flowStats: flowStats,
        }
      }

      console.log('Analysis completed successfully')
      return NextResponse.json(results)

    } catch (error) {
      console.error('Analysis error:', error)
      return NextResponse.json({
        error: 'Failed to analyze the PCAP file',
        details: error instanceof Error ? error.message : 'Unknown error'
      }, { status: 500 })
    }
  } catch (error) {
    console.error('Request handling error:', error)
    return NextResponse.json({
      error: 'Failed to process the request',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

// Helper function to get DNS record type names
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
  };
  
  return dnsTypes[type] || `TYPE${type}`;
} 