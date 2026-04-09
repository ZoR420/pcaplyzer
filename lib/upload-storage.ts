import { randomUUID } from 'crypto'
import { existsSync } from 'fs'
import { mkdir, readFile, readdir, stat, unlink, writeFile } from 'fs/promises'
import path from 'path'

const ALLOWED_EXTENSIONS = new Set(['.pcap', '.pcapng'])
const uploadTtlHours = Number(process.env.UPLOAD_TTL_HOURS || 0)

export type UploadManifest = {
  artifactId: string
  originalName: string
  storedName: string
  size: number
  uploadedAt: string
  extension: string
}

export function sanitizeErrorMessage(error: unknown, fallback: string) {
  if (error instanceof Error && error.message) {
    return error.message.replace(/([A-Za-z]:\\[^\s]+|\/[^\s]+)/g, '[path]')
  }

  return fallback
}

export function getUploadsRoot() {
  return path.join(process.cwd(), 'uploads')
}

export function getArtifactsRoot() {
  return path.join(getUploadsRoot(), 'artifacts')
}

export function getManifestPath(fileName: string) {
  return path.join(getUploadsRoot(), `${fileName}.json`)
}

export function getExtension(fileName: string) {
  return path.extname(fileName).toLowerCase()
}

export function assertAllowedExtension(fileName: string) {
  const extension = getExtension(fileName)
  if (!ALLOWED_EXTENSIONS.has(extension)) {
    throw new Error('Invalid file type. Only .pcap and .pcapng files are supported')
  }

  return extension
}

export async function cleanupOldUploads(uploadDir: string) {
  if (!uploadTtlHours || uploadTtlHours <= 0) return

  const cutoff = Date.now() - uploadTtlHours * 60 * 60 * 1000
  try {
    const files = await readdir(uploadDir)
    await Promise.all(
      files.map(async (file) => {
        const filePath = path.join(uploadDir, file)
        try {
          const fileStats = await stat(filePath)
          if (fileStats.mtimeMs < cutoff) {
            await unlink(filePath)
          }
        } catch (error) {
          console.warn('Failed to cleanup file:', filePath, error)
        }
      })
    )
  } catch (error) {
    console.warn('Failed to cleanup uploads directory:', error)
  }
}

export async function storeUploadedFile(file: File) {
  const extension = assertAllowedExtension(file.name)
  const bytes = await file.arrayBuffer()
  const buffer = Buffer.from(bytes)

  const uploadsRoot = getUploadsRoot()
  const artifactsRoot = getArtifactsRoot()
  await mkdir(artifactsRoot, { recursive: true })

  const artifactId = randomUUID()
  const storedName = `${artifactId}${extension}`
  const storedPath = path.join(artifactsRoot, storedName)
  const manifestPath = getManifestPath(file.name)

  await writeFile(storedPath, buffer)
  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        artifactId,
        originalName: file.name,
        storedName,
        size: file.size,
        uploadedAt: new Date().toISOString(),
        extension
      } satisfies UploadManifest,
      null,
      2
    ),
    'utf8'
  )

  await cleanupOldUploads(uploadsRoot)
  await cleanupOldUploads(artifactsRoot)

  return { artifactId }
}

export async function resolveUploadedFilePath(fileName: string) {
  const uploadsRoot = getUploadsRoot()
  const manifestPath = getManifestPath(fileName)

  if (existsSync(manifestPath)) {
    const manifestRaw = await readFile(manifestPath, 'utf8')
    const manifest = JSON.parse(manifestRaw) as UploadManifest
    const candidate = path.resolve(getArtifactsRoot(), manifest.storedName)
    const artifactsRoot = path.resolve(getArtifactsRoot())

    if (!candidate.startsWith(`${artifactsRoot}${path.sep}`) && candidate !== artifactsRoot) {
      throw new Error('Invalid stored artifact path')
    }

    return candidate
  }

  const fallbackPath = path.resolve(uploadsRoot, fileName)
  const uploadsResolved = path.resolve(uploadsRoot)
  if (!fallbackPath.startsWith(`${uploadsResolved}${path.sep}`) && fallbackPath !== uploadsResolved) {
    throw new Error('Invalid file reference')
  }

  return fallbackPath
}
