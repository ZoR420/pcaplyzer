const { execFileSync } = require('child_process')
const fs = require('fs')

function testBinary(name, candidates) {
  for (const candidate of candidates) {
    if (!candidate) continue

    if (fs.existsSync(candidate)) {
      return { name, found: true, path: candidate }
    }

    try {
      const output = execFileSync(process.platform === 'win32' ? 'where' : 'which', [candidate], { encoding: 'utf8' })
      const first = output.split(/\r?\n/).find(Boolean)
      if (first) {
        return { name, found: true, path: first }
      }
    } catch {
      // continue
    }
  }

  return { name, found: false, path: null }
}

const results = [
  testBinary('tshark', [
    process.env.TSHARK_PATH,
    'tshark',
    'C:\\Program Files\\Wireshark\\tshark.exe',
    'C:\\Program Files (x86)\\Wireshark\\tshark.exe'
  ]),
  testBinary('stratoshark', [
    process.env.STRATOSHARK_PATH,
    'stratoshark',
    'stratoshark.exe',
    'C:\\Program Files\\Stratoshark\\stratoshark.exe',
    'C:\\Program Files (x86)\\Stratoshark\\stratoshark.exe'
  ]),
  testBinary('python', [process.env.PYTHON_PATH, 'python', 'python3'])
]

process.stdout.write(`${JSON.stringify(results, null, 2)}\n`)
