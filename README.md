# Shodan MCP Server

[![smithery badge](https://smithery.ai/badge/@burtthecoder/mcp-shodan)](https://smithery.ai/server/@burtthecoder/mcp-shodan)

A Model Context Protocol (MCP) server for querying the [Shodan API](https://shodan.io) and [Shodan CVEDB](https://cvedb.shodan.io). This server provides comprehensive access to Shodan's network intelligence and security services, including IP reconnaissance, DNS operations, vulnerability tracking, and device discovery. All tools provide structured, formatted output for easy analysis and integration.

<a href="https://glama.ai/mcp/servers/79uakvikcj"><img width="380" height="200" src="https://glama.ai/mcp/servers/79uakvikcj/badge" /></a>

## Quick Start (Recommended)

### Installing via Smithery

To install Shodan Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@burtthecoder/mcp-shodan):

```bash
npx -y @smithery/cli install @burtthecoder/mcp-shodan --client claude
```

### Installing Manually
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

- **Network Reconnaissance**: Query detailed information about IP addresses, including open ports, services, and vulnerabilities
- **DNS Operations**: Forward and reverse DNS lookups for domains and IP addresses
- **Vulnerability Intelligence**: Access to Shodan's CVEDB for detailed vulnerability information, CPE lookups, and product-specific CVE tracking
- **Device Discovery**: Search Shodan's database of internet-connected devices with advanced filtering

## Tools

### 1. IP Lookup Tool
- Name: `ip_lookup`
- Description: Retrieve comprehensive information about an IP address, including geolocation, open ports, running services, SSL certificates, hostnames, and cloud provider details if available
- Parameters:
  * `ip` (required): IP address to lookup
- Returns:
  * IP Information (address, organization, ISP, ASN)
  * Location (country, city, coordinates)
  * Services (ports, protocols, banners)
  * Cloud Provider details (if available)
  * Associated hostnames and domains
  * Tags

### 2. Shodan Search Tool
- Name: `shodan_search`
- Description: Search Shodan's database of internet-connected devices
- Parameters:
  * `query` (required): Shodan search query
  * `max_results` (optional, default: 10): Number of results to return
- Returns:
  * Search summary with total results
  * Country-based distribution statistics
  * Detailed device information including:
    - Basic information (IP, organization, ISP)
    - Location data
    - Service details
    - Web server information
    - Associated hostnames and domains

### 3. CVE Lookup Tool
- Name: `cve_lookup`
- Description: Query detailed vulnerability information from Shodan's CVEDB
- Parameters:
  * `cve` (required): CVE identifier in format CVE-YYYY-NNNNN (e.g., CVE-2021-44228)
- Returns:
  * Basic Information (ID, published date, summary)
  * Severity Scores:
    - CVSS v2 and v3 with severity levels
    - EPSS probability and ranking
  * Impact Assessment:
    - KEV status
    - Proposed mitigations
    - Ransomware associations
  * Affected products (CPEs)
  * References

### 4. DNS Lookup Tool
- Name: `dns_lookup`
- Description: Resolve domain names to IP addresses using Shodan's DNS service
- Parameters:
  * `hostnames` (required): Array of hostnames to resolve
- Returns:
  * DNS resolutions mapping hostnames to IPs
  * Summary of total lookups and queried hostnames

### 5. Reverse DNS Lookup Tool
- Name: `reverse_dns_lookup`
- Description: Perform reverse DNS lookups to find hostnames associated with IP addresses
- Parameters:
  * `ips` (required): Array of IP addresses to lookup
- Returns:
  * Reverse DNS resolutions mapping IPs to hostnames
  * Summary of total lookups and results

### 6. CPE Lookup Tool
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

### 7. CVEs by Product Tool
- Name: `cves_by_product`
- Description: Search for vulnerabilities affecting specific products or CPEs
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
  * Query information
  * Results summary with pagination details
  * Detailed vulnerability information including:
    - Basic information
    - Severity scores
    - Impact assessments
    - References

## Requirements

- Node.js (v18 or later)
- A valid [Shodan API Key](https://account.shodan.io/)

## Troubleshooting

### API Key Issues

If you see API key related errors (e.g., "Request failed with status code 401"):

1. Verify your API key:
   - Must be a valid Shodan API key from your [account settings](https://account.shodan.io/)
   - Ensure the key has sufficient credits/permissions for the operation
   - Check for extra spaces or quotes around the key in the configuration
   - Verify the key is correctly set in the SHODAN_API_KEY environment variable

2. Common Error Codes:
   - 401 Unauthorized: Invalid API key or missing authentication
   - 402 Payment Required: Out of query credits
   - 429 Too Many Requests: Rate limit exceeded

3. Configuration Steps:
   a. Get your API key from [Shodan Account](https://account.shodan.io/)
   b. Add it to your configuration file:
      ```json
      {
        "mcpServers": {
          "shodan": {
            "command": "mcp-shodan",
            "env": {
              "SHODAN_API_KEY": "your-actual-api-key-here"
            }
          }
        }
      }
      ```
   c. Save the config file
   d. Restart Claude Desktop

4. Testing Your Key:
   - Try a simple query first (e.g., dns_lookup for "google.com")
   - Check your [Shodan account dashboard](https://account.shodan.io/) for credit status
   - Verify the key works directly with curl:
     ```bash
     curl "https://api.shodan.io/dns/resolve?hostnames=google.com&key=your-api-key"
     ```

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

- v1.0.12: Added reverse DNS lookup and improved output formatting
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
