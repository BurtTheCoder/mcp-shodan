# Shodan MCP Server

A Model Context Protocol (MCP) server for querying the [Shodan API](https://shodan.io) and [Shodan CVEDB](https://cvedb.shodan.io). This server provides tools for IP lookups, device searches, DNS lookups, vulnerability queries, CPE lookups, and more. It is designed to integrate seamlessly with MCP-compatible applications like [Claude Desktop](https://claude.ai).

<a href="https://glama.ai/mcp/servers/79uakvikcj"><img width="380" height="200" src="https://glama.ai/mcp/servers/79uakvikcj/badge" /></a>

## Quick Start (Recommended)

1. Install the server globally via npm:
```bash
npm install -g @burtthecoder/mcp-shodan
```

2. Add to your Claude Desktop configuration file:
```json
{
  "mcpServers": {
    "shodan": {
      "command": "mcp-shodan",
      "env": {
        "SHODAN_API_KEY": "your-shodan-api-key"
      }
    }
  }
}
```

Configuration file location:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

3. Restart Claude Desktop

## Alternative Setup (From Source)

If you prefer to run from source or need to modify the code:

1. Clone and build:
```bash
git clone https://github.com/BurtTheCoder/mcp-shodan.git
cd mcp-shodan
npm install
npm run build
```

2. Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "shodan": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-shodan/build/index.js"],
      "env": {
        "SHODAN_API_KEY": "your-shodan-api-key"
      }
    }
  }
}
```

## Features

- **IP Lookup**: Retrieve detailed information about an IP address
- **Search**: Search for devices on Shodan matching specific queries
- **Ports**: Get a list of ports that Shodan is scanning
- **CVE Lookup**: Fetch detailed information about specific CVEs using Shodan's CVEDB
- **CPE Lookup**: Search for Common Platform Enumeration (CPE) entries by product name
- **CVEs by Product**: Search for all CVEs affecting a specific product or CPE
- **DNS Lookup**: Resolve hostnames to IP addresses

## Tools

### 1. IP Lookup Tool
- Name: `ip_lookup`
- Description: Retrieve detailed information about an IP address
- Parameters:
  * `ip` (required): IP address to lookup

### 2. Search Tool
- Name: `search`
- Description: Search for devices on Shodan
- Parameters:
  * `query` (required): Shodan search query
  * `max_results` (optional, default: 10): Number of results to return

### 3. CVE Lookup Tool
- Name: `cve_lookup`
- Description: Fetch detailed information about CVEs using Shodan's CVEDB
- Parameters:
  * `cve` (required): CVE identifier in format CVE-YYYY-NNNNN (e.g., CVE-2021-44228)
- Returns:
  * CVE details including:
    - CVSS v2 and v3 scores
    - EPSS score and ranking
    - KEV status
    - Proposed action
    - Ransomware campaign information
    - Affected products (CPEs)
    - References

### 4. CPE Lookup Tool
- Name: `cpe_lookup`
- Description: Search for Common Platform Enumeration (CPE) entries by product name
- Parameters:
  * `product` (required): Name of the product to search for
  * `count` (optional, default: false): If true, returns only the count of matching CPEs
  * `skip` (optional, default: 0): Number of CPEs to skip (for pagination)
  * `limit` (optional, default: 1000): Maximum number of CPEs to return
- Returns:
  * When count is true: Total number of matching CPEs
  * When count is false: List of CPEs with pagination details

### 5. CVEs by Product Tool
- Name: `cves_by_product`
- Description: Search for CVEs affecting a specific product or CPE
- Parameters:
  * `cpe23` (optional): CPE 2.3 identifier (format: cpe:2.3:part:vendor:product:version)
  * `product` (optional): Name of the product to search for CVEs
  * `count` (optional, default: false): If true, returns only the count of matching CVEs
  * `is_kev` (optional, default: false): If true, returns only CVEs with KEV flag set
  * `sort_by_epss` (optional, default: false): If true, sorts CVEs by EPSS score
  * `skip` (optional, default: 0): Number of CVEs to skip (for pagination)
  * `limit` (optional, default: 1000): Maximum number of CVEs to return
  * `start_date` (optional): Start date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)
  * `end_date` (optional): End date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)
- Notes:
  * Must provide either cpe23 or product, but not both
  * Date filtering uses published time of CVEs
- Returns:
  * When count is true: Total number of matching CVEs
  * When count is false: List of CVEs with pagination details and query parameters

### 6. DNS Lookup Tool
- Name: `dns_lookup`
- Description: Resolve hostnames to IP addresses
- Parameters:
  * `hostnames` (required): Array of hostnames to resolve

## Requirements

- Node.js (v18 or later)
- A valid [Shodan API Key](https://account.shodan.io/)

## Troubleshooting

### API Key Issues

If you see API key related errors:

1. Verify your API key:
   - Should be a valid Shodan API key
   - No extra spaces or quotes around the key
   - Must be from your Shodan account settings
2. After any configuration changes:
   - Save the config file
   - Restart Claude Desktop

### Module Loading Issues

If you see module loading errors:
1. For global installation: Use the simple configuration shown in Quick Start
2. For source installation: Ensure you're using Node.js v18 or later

## Development

To run in development mode with hot reloading:
```bash
npm run dev
```

## Error Handling

The server includes comprehensive error handling for:
- Invalid API keys
- Rate limiting
- Network errors
- Invalid input parameters
- Invalid CVE formats
- Invalid CPE lookup parameters
- Invalid date formats
- Mutually exclusive parameter validation

## Version History

- v1.0.7: Added CVEs by Product search functionality and renamed vulnerabilities tool to cve_lookup
- v1.0.6: Added CVEDB integration for enhanced CVE lookups and CPE search functionality
- v1.0.0: Initial release with core functionality

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
