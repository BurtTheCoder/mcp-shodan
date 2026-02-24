import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan } from "../helpers.js";
import type { DnsResponse } from "../types.js";

export function registerDnsLookup(server: FastMCP) {
  server.addTool({
    name: "dns_lookup",
    description:
      "Resolve domain names to IP addresses using Shodan's DNS service. Supports batch resolution of multiple hostnames in a single query. Returns IP addresses mapped to their corresponding hostnames.",
    parameters: z.object({
      hostnames: z
        .array(z.string())
        .describe("List of hostnames to resolve."),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const hostnamesString = args.hostnames.join(",");

      const result: DnsResponse = await queryShodan("/dns/resolve", {
        hostnames: hostnamesString,
      });

      const formattedResult = {
        "DNS Resolutions": Object.entries(result).map(([hostname, ip]) => ({
          Hostname: hostname,
          "IP Address": ip,
        })),
        Summary: {
          "Total Lookups": Object.keys(result).length,
          "Queried Hostnames": args.hostnames,
        },
      };

      return JSON.stringify(formattedResult, null, 2);
    },
  });
}
