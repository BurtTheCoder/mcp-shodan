import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan } from "../helpers.js";
import type { SearchResponse } from "../types.js";

export function registerShodanSearch(server: FastMCP) {
  server.addTool({
    name: "shodan_search",
    description:
      "Search Shodan's database of internet-connected devices. Returns detailed information about matching devices including services, vulnerabilities, and geographic distribution. Supports advanced search filters and returns country-based statistics.",
    parameters: z.object({
      query: z.string().describe("Search query for Shodan."),
      max_results: z
        .number()
        .optional()
        .default(10)
        .describe("Maximum results to return."),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const result: SearchResponse = await queryShodan(
        "/shodan/host/search",
        {
          query: args.query,
          limit: args.max_results,
        }
      );

      const formattedResult = {
        "Search Summary": {
          Query: args.query,
          "Total Results": result.total,
          "Results Returned": result.matches.length,
        },
        "Country Distribution":
          result.facets?.country?.map((country) => ({
            Country: country.value,
            Count: country.count,
            Percentage: `${((country.count / result.total) * 100).toFixed(2)}%`,
          })) || [],
        Matches: result.matches.map((match) => ({
          "Basic Information": {
            "IP Address": match.ip_str,
            Organization: match.org,
            ISP: match.isp,
            ASN: match.asn,
            "Last Update": match.timestamp,
          },
          Location: {
            Country: match.location.country_name,
            City: match.location.city || "Unknown",
            Region: match.location.region_code || "Unknown",
            Coordinates: `${match.location.latitude}, ${match.location.longitude}`,
          },
          "Service Details": {
            Port: match.port,
            Transport: match.transport,
            Product: match.product || "Unknown",
            Version: match.version || "Unknown",
            CPE: match.cpe || [],
          },
          "Web Information": match.http
            ? {
                Server: match.http.server,
                Title: match.http.title,
                "Robots.txt": match.http.robots ? "Present" : "Not found",
                Sitemap: match.http.sitemap ? "Present" : "Not found",
              }
            : "No HTTP information",
          Hostnames: match.hostnames,
          Domains: match.domains,
        })),
      };

      return JSON.stringify(formattedResult, null, 2);
    },
  });
}
