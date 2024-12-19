#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import dotenv from "dotenv";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import fs from "fs";
import path from "path";
import os from "os";

// Shodan API Response Types
interface DnsResponse {
  [hostname: string]: string;  // Maps hostname to IP address
}

interface ReverseDnsResponse {
  [ip: string]: string[];  // Maps IP address to array of hostnames
}

interface SearchLocation {
  city: string | null;
  region_code: string | null;
  area_code: number | null;
  longitude: number;
  latitude: number;
  country_code: string;
  country_name: string;
}

interface SearchMatch {
  product?: string;
  hash: number;
  ip: number;
  ip_str: string;
  org: string;
  isp: string;
  transport: string;
  cpe?: string[];
  version?: string;
  hostnames: string[];
  domains: string[];
  location: SearchLocation;
  timestamp: string;
  port: number;
  data: string;
  asn: string;
  http?: {
    server?: string;
    title?: string;
    robots?: string | null;
    sitemap?: string | null;
  };
}

interface SearchResponse {
  matches: SearchMatch[];
  facets: {
    country?: Array<{
      count: number;
      value: string;
    }>;
  };
  total: number;
}

interface ShodanService {
  port: number;
  transport: string;
  data?: string;
  http?: {
    server?: string;
    title?: string;
  };
  cloud?: {
    provider: string;
    service: string;
    region: string;
  };
}

interface CveResponse {
  cve_id: string;
  summary: string;
  cvss: number;
  cvss_version: number;
  cvss_v2: number;
  cvss_v3: number;
  epss: number;
  ranking_epss: number;
  kev: boolean;
  propose_action: string;
  ransomware_campaign: string;
  references: string[];
  published_time: string;
  cpes: string[];
}

interface ShodanHostResponse {
  ip_str: string;
  org: string;
  isp: string;
  asn: string;
  last_update: string;
  country_name: string;
  city: string;
  latitude: number;
  longitude: number;
  region_code: string;
  ports: number[];
  data: ShodanService[];
  hostnames: string[];
  domains: string[];
  tags: string[];
}

dotenv.config();

const logFilePath = path.join(os.tmpdir(), "mcp-shodan-server.log");
const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
if (!SHODAN_API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is required.");
}

const API_BASE_URL = "https://api.shodan.io";
const CVEDB_API_URL = "https://cvedb.shodan.io";

// Logging Helper Function
function logToFile(message: string) {
  try {
    const timestamp = new Date().toISOString();
    const formattedMessage = `[${timestamp}] ${message}\n`;
    fs.appendFileSync(logFilePath, formattedMessage, "utf8");
    console.error(formattedMessage.trim()); // Use stderr for logging to avoid interfering with stdout
  } catch (error) {
    console.error(`Failed to write to log file: ${error}`);
  }
}

// Tool Schemas
const IpLookupArgsSchema = z.object({
  ip: z.string().describe("The IP address to query."),
});

const ShodanSearchArgsSchema = z.object({
  query: z.string().describe("Search query for Shodan."),
  max_results: z
    .number()
    .optional()
    .default(10)
    .describe("Maximum results to return."),
});

const CVELookupArgsSchema = z.object({
  cve: z.string()
    .regex(/^CVE-\d{4}-\d{4,}$/i, "Must be a valid CVE ID format (e.g., CVE-2021-44228)")
    .describe("The CVE identifier to query (format: CVE-YYYY-NNNNN)."),
});

const DnsLookupArgsSchema = z.object({
  hostnames: z.array(z.string()).describe("List of hostnames to resolve."),
});

const ReverseDnsLookupArgsSchema = z.object({
  ips: z.array(z.string()).describe("List of IP addresses to perform reverse DNS lookup on."),
});

const CpeLookupArgsSchema = z.object({
  product: z.string().describe("The name of the product to search for CPEs."),
  count: z.boolean().optional().default(false).describe("If true, returns only the count of matching CPEs."),
  skip: z.number().optional().default(0).describe("Number of CPEs to skip (for pagination)."),
  limit: z.number().optional().default(1000).describe("Maximum number of CPEs to return (max 1000)."),
});

const CVEsByProductArgsSchema = z.object({
  cpe23: z.string().optional().describe("The CPE version 2.3 identifier (format: cpe:2.3:part:vendor:product:version)."),
  product: z.string().optional().describe("The name of the product to search for CVEs."),
  count: z.boolean().optional().default(false).describe("If true, returns only the count of matching CVEs."),
  is_kev: z.boolean().optional().default(false).describe("If true, returns only CVEs with the KEV flag set."),
  sort_by_epss: z.boolean().optional().default(false).describe("If true, sorts CVEs by EPSS score in descending order."),
  skip: z.number().optional().default(0).describe("Number of CVEs to skip (for pagination)."),
  limit: z.number().optional().default(1000).describe("Maximum number of CVEs to return (max 1000)."),
  start_date: z.string().optional().describe("Start date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)."),
  end_date: z.string().optional().describe("End date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS).")
}).refine(
  data => !(data.cpe23 && data.product),
  { message: "Cannot specify both cpe23 and product. Use only one." }
).refine(
  data => data.cpe23 || data.product,
  { message: "Must specify either cpe23 or product." }
);

// Helper Function to Query Shodan API
async function queryShodan(endpoint: string, params: Record<string, any>) {
  try {
    const response = await axios.get(`${API_BASE_URL}${endpoint}`, {
      params: { ...params, key: SHODAN_API_KEY },
      timeout: 10000,
    });
    return response.data;
  } catch (error: any) {
    const errorMessage = error.response?.data?.error || error.message;
    logToFile(`Shodan API error: ${errorMessage}`);
    throw new Error(`Shodan API error: ${errorMessage}`);
  }
}

// Helper Function for CVE lookups using CVEDB
async function queryCVEDB(cveId: string) {
  try {
    logToFile(`Querying CVEDB for: ${cveId}`);
    const response = await axios.get(`${CVEDB_API_URL}/cve/${cveId}`);
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new Error(`Invalid CVE ID format: ${cveId}`);
    }
    if (error.response?.status === 404) {
      throw new Error(`CVE not found: ${cveId}`);
    }
    throw new Error(`CVEDB API error: ${error.message}`);
  }
}

// Helper Function for CPE lookups using CVEDB
async function queryCPEDB(params: {
  product: string;
  count?: boolean;
  skip?: number;
  limit?: number;
}) {
  try {
    logToFile(`Querying CVEDB for CPEs with params: ${JSON.stringify(params)}`);
    const response = await axios.get(`${CVEDB_API_URL}/cpes`, { params });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new Error(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new Error(`CVEDB API error: ${error.message}`);
  }
}

// Helper Function for CVEs by product/CPE lookups using CVEDB
async function queryCVEsByProduct(params: {
  cpe23?: string;
  product?: string;
  count?: boolean;
  is_kev?: boolean;
  sort_by_epss?: boolean;
  skip?: number;
  limit?: number;
  start_date?: string;
  end_date?: string;
}) {
  try {
    logToFile(`Querying CVEDB for CVEs with params: ${JSON.stringify(params)}`);
    const response = await axios.get(`${CVEDB_API_URL}/cves`, { params });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new Error(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new Error(`CVEDB API error: ${error.message}`);
  }
}

// Server Setup
const server = new Server(
  {
    name: "shodan-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {
        listChanged: true,
      },
    },
  }
);

// Handle Initialization
server.setRequestHandler(InitializeRequestSchema, async (request) => {
  logToFile("Received initialize request.");
  return {
    protocolVersion: "2024-11-05",
    capabilities: {
      tools: {
        listChanged: true,
      },
    },
    serverInfo: {
      name: "shodan-mcp",
      version: "1.0.0",
    },
    instructions: `This MCP server provides comprehensive access to Shodan's network intelligence and security services:

- Network Reconnaissance: Query detailed information about IP addresses, including open ports, services, and vulnerabilities
- DNS Operations: Forward and reverse DNS lookups for domains and IP addresses
- Vulnerability Intelligence: Access to Shodan's CVEDB for detailed vulnerability information, CPE lookups, and product-specific CVE tracking
- Device Discovery: Search Shodan's database of internet-connected devices with advanced filtering

Each tool provides structured, formatted output for easy analysis and integration.`,
  };
});

// Register Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [
    {
      name: "ip_lookup",
      description: "Retrieve comprehensive information about an IP address, including geolocation, open ports, running services, SSL certificates, hostnames, and cloud provider details if available. Returns service banners and HTTP server information when present.",
      inputSchema: zodToJsonSchema(IpLookupArgsSchema),
    },
    {
      name: "shodan_search",
      description: "Search Shodan's database of internet-connected devices. Returns detailed information about matching devices including services, vulnerabilities, and geographic distribution. Supports advanced search filters and returns country-based statistics.",
      inputSchema: zodToJsonSchema(ShodanSearchArgsSchema),
    },
    {
      name: "cve_lookup",
      description: "Query detailed vulnerability information from Shodan's CVEDB. Returns comprehensive CVE details including CVSS scores (v2/v3), EPSS probability and ranking, KEV status, proposed mitigations, ransomware associations, and affected products (CPEs).",
      inputSchema: zodToJsonSchema(CVELookupArgsSchema),
    },
    {
      name: "dns_lookup",
      description: "Resolve domain names to IP addresses using Shodan's DNS service. Supports batch resolution of multiple hostnames in a single query. Returns IP addresses mapped to their corresponding hostnames.",
      inputSchema: zodToJsonSchema(DnsLookupArgsSchema),
    },
    {
      name: "cpe_lookup",
      description: "Search for Common Platform Enumeration (CPE) entries by product name in Shodan's CVEDB. Supports pagination and can return either full CPE details or just the total count. Useful for identifying specific versions and configurations of software and hardware.",
      inputSchema: zodToJsonSchema(CpeLookupArgsSchema),
    },
    {
      name: "cves_by_product",
      description: "Search for vulnerabilities affecting specific products or CPEs. Supports filtering by KEV status, sorting by EPSS score, date ranges, and pagination. Can search by product name or CPE 2.3 identifier. Returns detailed vulnerability information including severity scores and impact assessments.",
      inputSchema: zodToJsonSchema(CVEsByProductArgsSchema),
    },
    {
      name: "reverse_dns_lookup",
      description: "Perform reverse DNS lookups to find hostnames associated with IP addresses. Supports batch lookups of multiple IP addresses in a single query. Returns all known hostnames for each IP address, with clear indication when no hostnames are found.",
      inputSchema: zodToJsonSchema(ReverseDnsLookupArgsSchema),
    },
  ];

  logToFile("Registered tools.");
  return { tools };
});

// Handle Tool Calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  logToFile(`Tool called: ${request.params.name}`);

  try {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "ip_lookup": {
        const parsedIpArgs = IpLookupArgsSchema.safeParse(args);
        if (!parsedIpArgs.success) {
          throw new Error("Invalid ip_lookup arguments");
        }
        const result = await queryShodan(`/shodan/host/${parsedIpArgs.data.ip}`, {});
        
        // Format the response in a user-friendly way
        const formattedResult = {
          "IP Information": {
            "IP Address": result.ip_str,
            "Organization": result.org,
            "ISP": result.isp,
            "ASN": result.asn,
            "Last Update": result.last_update
          },
          "Location": {
            "Country": result.country_name,
            "City": result.city,
            "Coordinates": `${result.latitude}, ${result.longitude}`,
            "Region": result.region_code
          },
          "Services": result.ports.map((port: number) => {
            const service = result.data.find((d: ShodanService) => d.port === port);
            return {
              "Port": port,
              "Protocol": service?.transport || "unknown",
              "Service": service?.data?.trim() || "No banner",
              ...(service?.http ? {
                "HTTP": {
                  "Server": service.http.server,
                  "Title": service.http.title,
                }
              } : {})
            };
          }),
          "Cloud Provider": result.data[0]?.cloud ? {
            "Provider": result.data[0].cloud.provider,
            "Service": result.data[0].cloud.service,
            "Region": result.data[0].cloud.region
          } : "Not detected",
          "Hostnames": result.hostnames || [],
          "Domains": result.domains || [],
          "Tags": result.tags || []
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2),
            },
          ],
        };
      }

      case "shodan_search": {
        const parsedSearchArgs = ShodanSearchArgsSchema.safeParse(args);
        if (!parsedSearchArgs.success) {
          throw new Error("Invalid search arguments");
        }
        const result: SearchResponse = await queryShodan("/shodan/host/search", {
          query: parsedSearchArgs.data.query,
          limit: parsedSearchArgs.data.max_results,
        });

        // Format the response in a user-friendly way
        const formattedResult = {
          "Search Summary": {
            "Query": parsedSearchArgs.data.query,
            "Total Results": result.total,
            "Results Returned": result.matches.length
          },
          "Country Distribution": result.facets?.country?.map(country => ({
            "Country": country.value,
            "Count": country.count,
            "Percentage": `${((country.count / result.total) * 100).toFixed(2)}%`
          })) || [],
          "Matches": result.matches.map(match => ({
            "Basic Information": {
              "IP Address": match.ip_str,
              "Organization": match.org,
              "ISP": match.isp,
              "ASN": match.asn,
              "Last Update": match.timestamp
            },
            "Location": {
              "Country": match.location.country_name,
              "City": match.location.city || "Unknown",
              "Region": match.location.region_code || "Unknown",
              "Coordinates": `${match.location.latitude}, ${match.location.longitude}`
            },
            "Service Details": {
              "Port": match.port,
              "Transport": match.transport,
              "Product": match.product || "Unknown",
              "Version": match.version || "Unknown",
              "CPE": match.cpe || []
            },
            "Web Information": match.http ? {
              "Server": match.http.server,
              "Title": match.http.title,
              "Robots.txt": match.http.robots ? "Present" : "Not found",
              "Sitemap": match.http.sitemap ? "Present" : "Not found"
            } : "No HTTP information",
            "Hostnames": match.hostnames,
            "Domains": match.domains
          }))
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2),
            },
          ],
        };
      }

      case "cve_lookup": {
        const parsedCveArgs = CVELookupArgsSchema.safeParse(args);
        if (!parsedCveArgs.success) {
          throw new Error("Invalid CVE format. Please use format: CVE-YYYY-NNNNN (e.g., CVE-2021-44228)");
        }

        const cveId = parsedCveArgs.data.cve.toUpperCase();
        logToFile(`Looking up CVE: ${cveId}`);
        
        try {
          const result = await queryCVEDB(cveId);

          // Helper function to format CVSS score severity
          const getCvssSeverity = (score: number) => {
            if (score >= 9.0) return "Critical";
            if (score >= 7.0) return "High";
            if (score >= 4.0) return "Medium";
            if (score >= 0.1) return "Low";
            return "None";
          };

          // Format the response in a user-friendly way
          const formattedResult = {
            "Basic Information": {
              "CVE ID": result.cve_id,
              "Published": new Date(result.published_time).toLocaleString(),
              "Summary": result.summary
            },
            "Severity Scores": {
              "CVSS v3": result.cvss_v3 ? {
                "Score": result.cvss_v3,
                "Severity": getCvssSeverity(result.cvss_v3)
              } : "Not available",
              "CVSS v2": result.cvss_v2 ? {
                "Score": result.cvss_v2,
                "Severity": getCvssSeverity(result.cvss_v2)
              } : "Not available",
              "EPSS": result.epss ? {
                "Score": `${(result.epss * 100).toFixed(2)}%`,
                "Ranking": `Top ${(result.ranking_epss * 100).toFixed(2)}%`
              } : "Not available"
            },
            "Impact Assessment": {
              "Known Exploited Vulnerability": result.kev ? "Yes" : "No",
              "Proposed Action": result.propose_action || "No specific action proposed",
              "Ransomware Campaign": result.ransomware_campaign || "No known ransomware campaigns"
            },
            "Affected Products": result.cpes?.length > 0 ? result.cpes : ["No specific products listed"],
            "Additional Information": {
              "References": result.references?.length > 0 ? result.references : ["No references provided"]
            }
          };

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(formattedResult, null, 2),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: error.message,
              },
            ],
            isError: true,
          };
        }
      }

      case "dns_lookup": {
        const parsedDnsArgs = DnsLookupArgsSchema.safeParse(args);
        if (!parsedDnsArgs.success) {
          throw new Error("Invalid dns_lookup arguments");
        }
        
        // Join hostnames with commas for the API request
        const hostnamesString = parsedDnsArgs.data.hostnames.join(",");
        
        const result: DnsResponse = await queryShodan("/dns/resolve", {
          hostnames: hostnamesString
        });

        // Format the response in a user-friendly way
        const formattedResult = {
          "DNS Resolutions": Object.entries(result).map(([hostname, ip]) => ({
            "Hostname": hostname,
            "IP Address": ip
          })),
          "Summary": {
            "Total Lookups": Object.keys(result).length,
            "Queried Hostnames": parsedDnsArgs.data.hostnames
          }
        };
        
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2)
            },
          ],
        };
      }

      case "cpe_lookup": {
        const parsedCpeArgs = CpeLookupArgsSchema.safeParse(args);
        if (!parsedCpeArgs.success) {
          throw new Error("Invalid cpe_lookup arguments");
        }

        try {
          const result = await queryCPEDB({
            product: parsedCpeArgs.data.product,
            count: parsedCpeArgs.data.count,
            skip: parsedCpeArgs.data.skip,
            limit: parsedCpeArgs.data.limit
          });

          // Format the response based on whether it's a count request or full CPE list
          const formattedResult = parsedCpeArgs.data.count
            ? { total_cpes: result.total }
            : {
                cpes: result.cpes,
                skip: parsedCpeArgs.data.skip,
                limit: parsedCpeArgs.data.limit,
                total_returned: result.cpes.length
              };

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(formattedResult, null, 2),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: error.message,
              },
            ],
            isError: true,
          };
        }
      }

      case "cves_by_product": {
        const parsedArgs = CVEsByProductArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid arguments. Must provide either cpe23 or product name, but not both.");
        }

        try {
          const result = await queryCVEsByProduct({
            cpe23: parsedArgs.data.cpe23,
            product: parsedArgs.data.product,
            count: parsedArgs.data.count,
            is_kev: parsedArgs.data.is_kev,
            sort_by_epss: parsedArgs.data.sort_by_epss,
            skip: parsedArgs.data.skip,
            limit: parsedArgs.data.limit,
            start_date: parsedArgs.data.start_date,
            end_date: parsedArgs.data.end_date
          });

          // Helper function to format CVSS score severity
          const getCvssSeverity = (score: number) => {
            if (score >= 9.0) return "Critical";
            if (score >= 7.0) return "High";
            if (score >= 4.0) return "Medium";
            if (score >= 0.1) return "Low";
            return "None";
          };

          // Format the response based on whether it's a count request or full CVE list
          const formattedResult = parsedArgs.data.count
            ? {
                "Query Information": {
                  "Product": parsedArgs.data.product || "N/A",
                  "CPE 2.3": parsedArgs.data.cpe23 || "N/A",
                  "KEV Only": parsedArgs.data.is_kev ? "Yes" : "No",
                  "Sort by EPSS": parsedArgs.data.sort_by_epss ? "Yes" : "No"
                },
                "Results": {
                  "Total CVEs Found": result.total
                }
              }
            : {
                "Query Information": {
                  "Product": parsedArgs.data.product || "N/A",
                  "CPE 2.3": parsedArgs.data.cpe23 || "N/A",
                  "KEV Only": parsedArgs.data.is_kev ? "Yes" : "No",
                  "Sort by EPSS": parsedArgs.data.sort_by_epss ? "Yes" : "No",
                  "Date Range": parsedArgs.data.start_date ? 
                    `${parsedArgs.data.start_date} to ${parsedArgs.data.end_date || 'now'}` : 
                    "All dates"
                },
                "Results Summary": {
                  "Total CVEs Found": result.total,
                  "CVEs Returned": result.cves.length,
                  "Page": `${Math.floor(parsedArgs.data.skip! / parsedArgs.data.limit!) + 1}`,
                  "CVEs per Page": parsedArgs.data.limit
                },
                "Vulnerabilities": result.cves.map((cve: CveResponse) => ({
                  "Basic Information": {
                    "CVE ID": cve.cve_id,
                    "Published": new Date(cve.published_time).toLocaleString(),
                    "Summary": cve.summary
                  },
                  "Severity Scores": {
                    "CVSS v3": cve.cvss_v3 ? {
                      "Score": cve.cvss_v3,
                      "Severity": getCvssSeverity(cve.cvss_v3)
                    } : "Not available",
                    "CVSS v2": cve.cvss_v2 ? {
                      "Score": cve.cvss_v2,
                      "Severity": getCvssSeverity(cve.cvss_v2)
                    } : "Not available",
                    "EPSS": cve.epss ? {
                      "Score": `${(cve.epss * 100).toFixed(2)}%`,
                      "Ranking": `Top ${(cve.ranking_epss * 100).toFixed(2)}%`
                    } : "Not available"
                  },
                  "Impact Assessment": {
                    "Known Exploited Vulnerability": cve.kev ? "Yes" : "No",
                    "Proposed Action": cve.propose_action || "No specific action proposed",
                    "Ransomware Campaign": cve.ransomware_campaign || "No known ransomware campaigns"
                  },
                  "References": cve.references?.length > 0 ? cve.references : ["No references provided"]
                }))
              };

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(formattedResult, null, 2),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: error.message,
              },
            ],
            isError: true,
          };
        }
      }

      case "reverse_dns_lookup": {
        const parsedArgs = ReverseDnsLookupArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid reverse_dns_lookup arguments");
        }
        
        // Join IPs with commas for the API request
        const ipsString = parsedArgs.data.ips.join(",");
        
        const result: ReverseDnsResponse = await queryShodan("/dns/reverse", {
          ips: ipsString
        });

        // Format the response in a user-friendly way
        const formattedResult = {
          "Reverse DNS Resolutions": Object.entries(result).map(([ip, hostnames]) => ({
            "IP Address": ip,
            "Hostnames": hostnames.length > 0 ? hostnames : ["No hostnames found"]
          })),
          "Summary": {
            "Total IPs Queried": parsedArgs.data.ips.length,
            "IPs with Results": Object.keys(result).length,
            "Queried IP Addresses": parsedArgs.data.ips
          }
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(formattedResult, null, 2)
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logToFile(`Error handling tool call: ${errorMessage}`);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the Server
async function runServer() {
  logToFile("Starting Shodan MCP Server...");

  try {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logToFile("Shodan MCP Server is running.");
  } catch (error: any) {
    logToFile(`Error connecting server: ${error.message}`);
    process.exit(1);
  }
}

// Handle process events
process.on('uncaughtException', (error) => {
  logToFile(`Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logToFile(`Unhandled rejection: ${reason}`);
  process.exit(1);
});

runServer().catch((error: any) => {
  logToFile(`Fatal error: ${error.message}`);
  process.exit(1);
});
