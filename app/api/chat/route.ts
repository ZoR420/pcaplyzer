import { NextResponse } from 'next/server'
import OpenAI from 'openai'
import { spawn } from 'child_process'
import path from 'path'
import fs from 'fs'

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
})

// Function to run Python script and get PCAP analysis
async function analyzePcapFile(filePath: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const pythonScriptPath = path.join(process.cwd(), 'lib', 'pcap_parser.py')
    const pythonCommand = process.platform === 'win32' ? 'python.exe' : 'python'

    const pythonProcess = spawn(pythonCommand, [
      pythonScriptPath,
      filePath
    ], {
      shell: process.platform === 'win32',
      env: { 
        ...process.env, 
        PYTHONIOENCODING: 'utf-8',
        OPENAI_API_KEY: process.env.OPENAI_API_KEY 
      }
    })

    let dataString = ''
    let errorString = ''

    pythonProcess.stdout.on('data', (data) => {
      dataString += data.toString('utf-8')
    })

    pythonProcess.stderr.on('data', (data) => {
      errorString += data.toString('utf-8')
    })

    pythonProcess.on('error', (error) => {
      reject(new Error(`Failed to start Python process: ${error.message}`))
    })

    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Analysis failed: ${errorString}`))
        return
      }

      try {
        const jsonLines = dataString.split('\n').filter(line => {
          try {
            const trimmed = line.trim()
            if (!trimmed) return false
            JSON.parse(trimmed)
            return true
          } catch {
            return false
          }
        })

        if (jsonLines.length === 0) {
          throw new Error('No analysis results found')
        }

        const lastJsonLine = jsonLines[jsonLines.length - 1]
        const jsonData = JSON.parse(lastJsonLine)

        if (jsonData.error) {
          reject(new Error(jsonData.error))
          return
        }

        resolve(jsonData)
      } catch (error) {
        reject(new Error(`Failed to parse analysis results: ${error}`))
      }
    })
  })
}

// Function to create a structured prompt for OpenAI
function createPrompt(pcapData: any, userQuestion: string): string {
  if (!pcapData || Object.keys(pcapData).length === 0) {
    return `No PCAP analysis data is available. User question: ${userQuestion}`
  }

  if (pcapData.error) {
    return `Error analyzing PCAP file: ${pcapData.error}\nUser question: ${userQuestion}`
  }

  function formatArray(arr: any[], maxItems: number = 5): string {
    if (!arr || arr.length === 0) return 'None';
    const total = arr.length;
    const items = arr.slice(0, maxItems);
    return `${items.join(', ')}${total > maxItems ? ` (and ${total - maxItems} more...)` : ''}`;
  }

  const summary = `
PCAP File Analysis Summary:
- Total Packets: ${pcapData.packet_count || 0}
- Time Range: ${pcapData.time_range?.start || 'N/A'} to ${pcapData.time_range?.end || 'N/A'}
- Protocols: ${formatArray(pcapData.protocols || [])}

Protocol Distribution:
${Object.entries(pcapData.protocol_counts || {})
  .slice(0, 5)
  .map(([protocol, count]) => `- ${protocol}: ${count} packets`)
  .join('\n')}${Object.keys(pcapData.protocol_counts || {}).length > 5 ? '\n(showing top 5 protocols)' : ''}

Network Layer Information:
- Unique Source IPs: ${(pcapData.ip_addresses?.source || []).length || 0}
- Unique Destination IPs: ${(pcapData.ip_addresses?.destination || []).length || 0}
- Sample Source IPs: ${formatArray(pcapData.ip_addresses?.source || [])}
- Sample Destination IPs: ${formatArray(pcapData.ip_addresses?.destination || [])}

Transport Layer Information:
- TCP Ports: ${formatArray(pcapData.tcp_ports || [])}
- UDP Ports: ${formatArray(pcapData.udp_ports || [])}

Packet Size Statistics:
- Minimum: ${pcapData.packet_sizes?.min || 0} bytes
- Maximum: ${pcapData.packet_sizes?.max || 0} bytes
- Average: ${Math.round(pcapData.packet_sizes?.average || 0)} bytes
- Total: ${pcapData.packet_sizes?.total || 0} bytes
`

  return `You are a network analysis expert helping to analyze PCAP files. Here is the analysis of a PCAP file:

${summary}

User Question: ${userQuestion}

Please provide a clear and concise answer based on the PCAP analysis data above. Consider all layers of the network stack (Physical, Link, Network, Transport) in your analysis when relevant. If the question cannot be answered with the available data, please say so and explain what additional information would be needed.`
}

export async function POST(req: Request) {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return NextResponse.json(
        { error: 'OpenAI API key not configured' },
        { status: 500 }
      )
    }

    const body = await req.json()
    const { message, fileName } = body

    if (!message || !fileName) {
      return NextResponse.json(
        { error: 'Missing required parameters' },
        { status: 400 }
      )
    }

    const filePath = path.join(process.cwd(), 'uploads', fileName)
    if (!fs.existsSync(filePath)) {
      return NextResponse.json(
        { error: 'PCAP file not found' },
        { status: 404 }
      )
    }

    try {
      const pcapData = await analyzePcapFile(filePath)
      const prompt = createPrompt(pcapData, message)

      const completion = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [
          {
            role: "system",
            content: "You are a network analysis expert helping users understand their PCAP files. Provide clear, concise explanations focusing on the relevant information from the PCAP analysis."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        temperature: 0.7,
        max_tokens: 500
      })

      if (!completion.choices[0]?.message?.content) {
        throw new Error('No response from OpenAI')
      }

      return NextResponse.json({ response: completion.choices[0].message.content })
    } catch (error: any) {
      return NextResponse.json(
        { 
          error: 'Analysis failed',
          message: error.message
        },
        { status: 500 }
      )
    }
  } catch (error: any) {
    return NextResponse.json(
      { 
        error: 'Request failed',
        message: error.message
      },
      { status: 500 }
    )
  }
} 