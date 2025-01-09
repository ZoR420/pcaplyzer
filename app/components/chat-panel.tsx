'use client'

import { useState } from 'react'
import { Button } from "@/app/components/ui/button"
import { ScrollArea } from "@/app/components/ui/scroll-area"

interface ChatPanelProps {
  fileContent: any
}

export default function ChatPanel({ fileContent }: ChatPanelProps) {
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant', content: string }>>([])
  const [input, setInput] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim()) return

    const newMessage = { role: 'user' as const, content: input }
    setMessages(prev => [...prev, newMessage])
    setInput('')

    // Here you would typically send the message to your AI backend
    // For now, we'll just add a mock response
    setTimeout(() => {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'This is a placeholder response. In a real application, this would be processed by an AI model.'
      }])
    }, 1000)
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-medium">Interactive Analysis</h3>
      <ScrollArea className="h-[300px] rounded-md border p-4">
        <div className="space-y-4">
          {messages.map((message, index) => (
            <div
              key={index}
              className={`p-3 rounded-lg ${
                message.role === 'user'
                  ? 'bg-blue-100 ml-auto max-w-[80%]'
                  : 'bg-gray-100 mr-auto max-w-[80%]'
              }`}
            >
              {message.content}
            </div>
          ))}
        </div>
      </ScrollArea>
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about your PCAP analysis..."
          className="flex-1 px-3 py-2 border rounded-md"
        />
        <Button type="submit">Send</Button>
      </form>
    </div>
  )
} 