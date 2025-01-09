'use client'

import { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { Upload, Loader2 } from 'lucide-react'
import { Card } from "@/app/components/ui/card"

const MAX_FILE_SIZE = 100 * 1024 * 1024 // 100MB
const VALID_EXTENSIONS = ['.pcap', '.pcapng']

interface FileUploadProps {
  onFileUpload: (file: File) => void
  onError: (message: string) => void
  onSuccess: (message: string) => void
}

export default function FileUpload({ onFileUpload, onError, onSuccess }: FileUploadProps) {
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)

  const validateFile = (file: File) => {
    console.log('Validating file:', { name: file.name, size: file.size, type: file.type })
    
    if (file.size > MAX_FILE_SIZE) {
      throw new Error(`File size exceeds 100MB limit. Current size: ${formatFileSize(file.size)}`)
    }

    const extension = file.name.toLowerCase().slice(file.name.lastIndexOf('.'))
    console.log('File extension:', extension)
    
    if (!VALID_EXTENSIONS.includes(extension)) {
      throw new Error('Invalid file type. Only .pcap and .pcapng files are supported')
    }
  }

  const uploadFile = async (file: File) => {
    console.log('Starting file upload:', { name: file.name, size: file.size, type: file.type })
    const formData = new FormData()
    formData.append('file', file)

    try {
      console.log('Sending request to /api/upload')
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      })

      console.log('Upload response details:', {
        ok: response.ok,
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries())
      })

      if (!response.ok) {
        let errorMessage = `Upload failed with status ${response.status}`
        try {
          const errorData = await response.json()
          errorMessage = errorData.error || errorMessage
        } catch (e) {
          console.error('Failed to parse error response:', e)
        }
        throw new Error(errorMessage)
      }

      const data = await response.json()
      console.log('Upload successful:', data)

      onSuccess(`Successfully uploaded ${file.name} (${formatFileSize(file.size)})`)
      onFileUpload(file)
    } catch (error) {
      console.error('Upload error:', error)
      onError(error instanceof Error ? error.message : 'Failed to upload file')
    }
  }

  const onDrop = useCallback(async (acceptedFiles: File[], rejectedFiles: any[]) => {
    console.log('Files dropped:', { 
      accepted: acceptedFiles.map(f => ({ name: f.name, size: f.size, type: f.type })),
      rejected: rejectedFiles 
    })

    if (acceptedFiles.length === 0) {
      console.log('No files accepted')
      if (rejectedFiles.length > 0) {
        onError('File type not supported. Please upload a .pcap or .pcapng file.')
      }
      return
    }

    const file = acceptedFiles[0]
    if (!file) {
      onError('No file selected')
      return
    }

    setUploading(false)
    setUploadProgress(0)

    try {
      validateFile(file)
      setUploading(true)
      await uploadFile(file)
    } catch (error) {
      console.error('File processing error:', error)
      onError(error instanceof Error ? error.message : 'Failed to process file')
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
  }, [onFileUpload, onError, onSuccess])

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng'],
      'application/octet-stream': ['.pcap', '.pcapng'],
      'application/x-pcap': ['.pcap', '.pcapng'],
      'application/x-pcapng': ['.pcapng']
    },
    maxFiles: 1,
    disabled: uploading,
    multiple: false
  })

  return (
    <div className="mb-4">
      <Card
        {...getRootProps()}
        className={`p-8 border-dashed cursor-pointer transition-colors relative
          ${isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:bg-gray-50'}
          ${uploading ? 'pointer-events-none opacity-70' : ''}`}
      >
        <input {...getInputProps()} />
        <div className="flex flex-col items-center justify-center text-center">
          {uploading ? (
            <>
              <Loader2 className="w-12 h-12 mb-4 text-blue-500 animate-spin" />
              <p className="text-lg font-medium">Uploading... {uploadProgress}%</p>
              <div className="w-full max-w-xs mx-auto h-2 bg-gray-200 rounded-full mt-2 overflow-hidden">
                <div 
                  className="h-full bg-blue-500 transition-all duration-300 ease-in-out"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </>
          ) : (
            <>
              <Upload className="w-12 h-12 mb-4 text-gray-400" />
              <p className="text-lg font-medium">
                {isDragActive
                  ? 'Drop the file here'
                  : 'Drag & drop a packet capture file here, or click to select'}
              </p>
              <p className="mt-2 text-sm text-gray-500">
                Supports .pcap and .pcapng files (max 100MB)
              </p>
            </>
          )}
        </div>
      </Card>
    </div>
  )
} 