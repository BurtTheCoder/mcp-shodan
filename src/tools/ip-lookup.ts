import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan } from "../helpers.js";
import type { ShodanService } from "../types.js";

export function registerIpLookup(server: FastMCP) {
  server.addTool({
    name: "ip_lookup",
    description:
      "Retrieve comprehensive information about an IP address, including geolocation, open ports, running services, SSL certificates, hostnames, and cloud provider details if available. Returns service banners and HTTP server information when present.",
    parameters: z.object({
      ip: z.string().describe("The IP address to query."),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const result = await queryShodan(`/shodan/host/${args.ip}`, {});

      const formattedResult = {
        "IP Information": {
          "IP Address": result.ip_str,
          Organization: result.org,
          ISP: result.isp,
          ASN: result.asn,
          "Last Update": result.last_update,
        },
        Location: {
          Country: result.country_name,
          City: result.city,
          Coordinates: `${result.latitude}, ${result.longitude}`,
          Region: result.region_code,
        },
        Services: result.ports.map((port: number) => {
          const service = result.data.find(
            (d: ShodanService) => d.port === port
          );
          return {
            Port: port,
            Protocol: service?.transport || "unknown",
            Service: service?.data?.trim() || "No banner",
            ...(service?.http
              ? {
                  HTTP: {
                    Server: service.http.server,
                    Title: service.http.title,
                  },
                }
              : {}),
          };
        }),
        "Cloud Provider": result.data[0]?.cloud
          ? {
              Provider: result.data[0].cloud.provider,
              Service: result.data[0].cloud.service,
              Region: result.data[0].cloud.region,
            }
          : "Not detected",
        Hostnames: result.hostnames || [],
        Domains: result.domains || [],
        Tags: result.tags || [],
      };

      return JSON.stringify(formattedResult, null, 2);
    },
  });
}
