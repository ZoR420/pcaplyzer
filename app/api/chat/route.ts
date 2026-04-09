import { NextResponse } from 'next/server'
import OpenAI from 'openai'
import { GoogleGenerativeAI } from '@google/generative-ai'
import { spawn } from 'child_process'
import fs from 'fs'
import path from 'path'
import { enforceApiGuard } from '@/lib/api-guard'
import { resolveUploadedFilePath } from '@/lib/upload-storage'

const openAiApiKey = process.env.OPENAI_API_KEY
const geminiApiKey = process.env.GEMINI_API_KEY
const aiProvider = (process.env.AI_PROVIDER || 'openai').toLowerCase()

const openai = openAiApiKey ? new OpenAI({ apiKey: openAiApiKey }) : null
const gemini = geminiApiKey ? new GoogleGenerativeAI(geminiApiKey) : null

// Function to run Python script and get PCAP analysis
type PcapAnalysis = Record<string, unknown> & {
  error?: string
  packet_count?: number
  time_range?: { start?: string; end?: string }
  protocols?: string[]
  protocol_counts?: Record<string, number>
  ip_addresses?: { source?: string[]; destination?: string[] }
  tcp_ports?: number[]
  udp_ports?: number[]
  packet_sizes?: { min?: number; max?: number; average?: number; total?: number }
}

async function analyzePcapFile(filePath: string): Promise<PcapAnalysis> {
  return new Promise((resolve, reject) => {
    const pythonScriptPath = path.join(process.cwd(), 'lib', 'pcap_parser.py')
    const pythonCandidates = process.platform === 'win32'
      ? ['python.exe']
      : [process.env.PYTHON_PATH, 'python3', 'python'].filter(Boolean) as string[]

    let attemptIndex = 0

    const startProcess = () => {
      const pythonCommand = pythonCandidates[attemptIndex]
      if (!pythonCommand) {
        reject(new Error('No Python interpreter available'))
        return
      }
      const pythonProcess = spawn(pythonCommand, [
        pythonScriptPath,
        filePath
      ], {
        shell: process.platform === 'win32',
        env: {
          ...process.env,
          PYTHONIOENCODING: 'utf-8'
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

      pythonProcess.on('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT' && attemptIndex < pythonCandidates.length - 1) {
          attemptIndex += 1
          return startProcess()
        }
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
          if (!lastJsonLine) {
            throw new Error('No analysis results found')
          }
          const jsonData = JSON.parse(lastJsonLine) as PcapAnalysis

          if (jsonData.error) {
            reject(new Error(jsonData.error))
            return
          }

          resolve(jsonData)
        } catch (error) {
          reject(new Error(`Failed to parse analysis results: ${error}`))
        }
      })
    }

    startProcess()
  })
}

// Function to create a structured prompt for OpenAI
function createPrompt(pcapData: PcapAnalysis, userQuestion: string): string {
  if (!pcapData || Object.keys(pcapData).length === 0) {
    return `No PCAP analysis data is available. User question: ${userQuestion}`
  }

  if (pcapData.error) {
    return `Error analyzing PCAP file: ${pcapData.error}\nUser question: ${userQuestion}`
  }

  function formatArray(arr: Array<string | number>, maxItems: number = 5): string {
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
    const guard = enforceApiGuard(req.headers)
    if (!guard.ok) {
      return NextResponse.json(
        { error: guard.message },
        {
          status: guard.status || 429,
          headers: guard.headers
        }
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

    const filePath = await resolveUploadedFilePath(fileName)
    if (!fs.existsSync(filePath)) {
      return NextResponse.json(
        { error: 'PCAP file not found' },
        { status: 404 }
      )
    }

    try {
      const pcapData = await analyzePcapFile(filePath)
      const prompt = createPrompt(pcapData, message)

      let responseText: string | null = null

      if (aiProvider === 'gemini') {
        if (!gemini) {
          throw new Error('Gemini API key not configured')
        }
        const modelName = process.env.GEMINI_MODEL || 'gemini-1.5-flash'
        const model = gemini.getGenerativeModel({ model: modelName })
        const result = await model.generateContent(prompt)
        responseText = result.response.text()
      } else {
        if (!openai) {
          if (gemini) {
            const modelName = process.env.GEMINI_MODEL || 'gemini-1.5-flash'
            const model = gemini.getGenerativeModel({ model: modelName })
            const result = await model.generateContent(prompt)
            responseText = result.response.text()
          } else {
            throw new Error('OpenAI API key not configured')
          }
        } else {
          const completion = await openai.chat.completions.create({
            model: process.env.OPENAI_MODEL || "gpt-4",
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

          responseText = completion.choices[0]?.message?.content || null
        }
      }

      if (!responseText) {
        throw new Error('No response from AI provider')
      }

      if (process.env.CLEANUP_UPLOADS === 'true') {
        try {
          await fs.promises.unlink(filePath)
        } catch (cleanupError) {
          console.warn('Failed to cleanup uploaded file:', cleanupError)
        }
      }

      return NextResponse.json({ response: responseText })
    } catch (error) {
      return NextResponse.json(
        {
          error: 'Analysis failed',
          message: error instanceof Error ? error.message : 'Analysis failed'
        },
        { status: 500 }
      )
    }
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Request failed',
        message: error instanceof Error ? error.message : 'Request failed'
      },
      { status: 500 }
    )
  }
} 