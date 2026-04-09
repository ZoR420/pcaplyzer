'use client'

import { useState, useEffect } from 'react'
import { ResponsiveNetwork } from '@nivo/network'

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
      linkThickness={(link) => Math.max(1, Math.sqrt((link.data.traffic as number) || 0))}
      animate={false}
    />
  );
} 