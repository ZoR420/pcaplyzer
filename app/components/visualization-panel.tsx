'use client'

import { Line } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
)

interface VisualizationPanelProps {
  data: any
}

export default function VisualizationPanel({ data }: VisualizationPanelProps) {
  if (!data) return null

  const chartData = {
    labels: data.labels || [],
    datasets: [
      {
        label: 'Network Traffic',
        data: data.values || [],
        borderColor: 'rgb(75, 192, 192)',
        tension: 0.1
      }
    ]
  }

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: true,
        text: 'Network Traffic Analysis'
      }
    }
  }

  return (
    <div className="mt-6">
      <h3 className="text-lg font-medium mb-4">Traffic Visualization</h3>
      <div className="h-[300px]">
        <Line data={chartData} options={options} />
      </div>
    </div>
  )
} 