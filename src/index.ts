#!/usr/bin/env node
import { FastMCP } from "fastmcp";
import dotenv from "dotenv";
import { registerIpLookup } from "./tools/ip-lookup.js";
import { registerShodanSearch } from "./tools/shodan-search.js";
import { registerCveLookup } from "./tools/cve-lookup.js";
import { registerDnsLookup } from "./tools/dns-lookup.js";
import { registerReverseDnsLookup } from "./tools/reverse-dns-lookup.js";
import { registerCpeLookup } from "./tools/cpe-lookup.js";
import { registerCvesByProduct } from "./tools/cves-by-product.js";

dotenv.config();

if (!process.env.SHODAN_API_KEY) {
  throw new Error("SHODAN_API_KEY environment variable is required.");
}

const server = new FastMCP({
  name: "shodan-mcp",
  version: "1.0.0",
  instructions: `This MCP server provides comprehensive access to Shodan's network intelligence and security services:

- Network Reconnaissance: Query detailed information about IP addresses, including open ports, services, and vulnerabilities
- DNS Operations: Forward and reverse DNS lookups for domains and IP addresses
- Vulnerability Intelligence: Access to Shodan's CVEDB for detailed vulnerability information, CPE lookups, and product-specific CVE tracking
- Device Discovery: Search Shodan's database of internet-connected devices with advanced filtering

Each tool provides structured, formatted output for easy analysis and integration.`,
});

registerIpLookup(server);
registerShodanSearch(server);
registerCveLookup(server);
registerDnsLookup(server);
registerReverseDnsLookup(server);
registerCpeLookup(server);
registerCvesByProduct(server);

server.start({ transportType: "stdio" });
