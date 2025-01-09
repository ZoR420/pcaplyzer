function AnalysisResults({ results }) {
  if (!results) return null;

  if (results.error) {
    return (
      <div className="analysis-error">
        <h2>Analysis Error</h2>
        <div className="error-details">
          <p><strong>Error:</strong> {results.error}</p>
          <p><strong>Details:</strong> {results.details}</p>
          {results.tsharkVersion && (
            <p><strong>Tshark Version:</strong> {results.tsharkVersion}</p>
          )}
          {results.fileInfo && (
            <div>
              <p><strong>File:</strong> {results.fileInfo.name}</p>
              <p><strong>Size:</strong> {(results.fileInfo.size / 1024 / 1024).toFixed(2)} MB</p>
              <p><strong>Created:</strong> {new Date(results.fileInfo.created).toLocaleString()}</p>
              <p><strong>Modified:</strong> {new Date(results.fileInfo.modified).toLocaleString()}</p>
            </div>
          )}
          {results.command && (
            <p><strong>Command:</strong> {results.command}</p>
          )}
          {results.errorOutput && (
            <pre className="error-output">{results.errorOutput}</pre>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="analysis-results">
      <h2>Analysis Results</h2>
      <div className="results-content">
        <div className="file-info">
          <h3>File Information</h3>
          <p><strong>Name:</strong> {results.fileInfo.name}</p>
          <p><strong>Size:</strong> {(results.fileInfo.size / 1024 / 1024).toFixed(2)} MB</p>
          <p><strong>Created:</strong> {new Date(results.fileInfo.created).toLocaleString()}</p>
          <p><strong>Modified:</strong> {new Date(results.fileInfo.modified).toLocaleString()}</p>
        </div>

        <div className="analysis-stats">
          <h3>Statistics</h3>
          <p><strong>Total Packets:</strong> {results.results.totalPackets}</p>
          <p><strong>Unique IP Addresses:</strong> {results.results.uniqueIpAddresses.length}</p>
          <p><strong>Protocols:</strong> {results.results.protocols.join(', ')}</p>
          
          <h4>Packet Sizes</h4>
          <p>Minimum: {results.results.packetSizes.min} bytes</p>
          <p>Maximum: {results.results.packetSizes.max} bytes</p>
          <p>Average: {results.results.packetSizes.average} bytes</p>
          
          <h4>Time Range</h4>
          <p>Start: {new Date(results.results.timeRange.start).toLocaleString()}</p>
          <p>End: {new Date(results.results.timeRange.end).toLocaleString()}</p>
          <p>Duration: {results.results.timeRange.duration.toFixed(2)} seconds</p>
        </div>
      </div>
    </div>
  );
}

export default AnalysisResults; 