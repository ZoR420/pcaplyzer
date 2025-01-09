'use client'

import { useState, useEffect } from 'react'
import { ResponsiveNetwork } from '@nivo/network'
import { formatBytes } from '@/lib/utils'

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

interface NetworkGraphProps {
  data: {
    nodes: NetworkNode[];
    links: NetworkLink[];
  };
}

export function NetworkGraph({ data }: NetworkGraphProps) {
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  if (!isMounted) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-gray-50">
        <div className="text-gray-500">Loading network graph...</div>
      </div>
    );
  }

  return (
    <ResponsiveNetwork<NetworkNode, NetworkLink>
      data={data}
      margin={{ top: 20, right: 20, bottom: 20, left: 20 }}
      linkBlendMode="multiply"
      repulsivity={4}
      iterations={60}
      nodeColor={node => node.color}
      nodeBorderWidth={1}
      nodeBorderColor={{ from: 'color', modifiers: [['darker', 0.8]] }}
      linkDistance={100}
      centeringStrength={0.3}
      linkThickness={link => Math.max(1, Math.sqrt(link.traffic || 0))}
      animate={false}
      tooltip={({ node, link }: { node?: NetworkNode; link?: NetworkLink }) => {
        if (node) {
          return (
            <div className="bg-white p-2 shadow-lg rounded-md border text-sm">
              <div className="font-medium">{node.id}</div>
              <div className="text-gray-600">
                Packets: {node.packets.toLocaleString()}
              </div>
              <div className="text-gray-600">
                Bytes: {formatBytes(node.bytes)}
              </div>
            </div>
          );
        }
        if (link) {
          return (
            <div className="bg-white p-2 shadow-lg rounded-md border text-sm">
              <div>{link.source} → {link.target}</div>
              <div className="text-gray-600">
                Traffic: {formatBytes(link.traffic)}
              </div>
            </div>
          );
        }
        return null;
      }}
    />
  );
} 