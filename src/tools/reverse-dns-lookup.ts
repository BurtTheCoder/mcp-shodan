import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryShodan } from "../helpers.js";
import type { ReverseDnsResponse } from "../types.js";

export function registerReverseDnsLookup(server: FastMCP) {
  server.addTool({
    name: "reverse_dns_lookup",
    description:
      "Perform reverse DNS lookups to find hostnames associated with IP addresses. Supports batch lookups of multiple IP addresses in a single query. Returns all known hostnames for each IP address, with clear indication when no hostnames are found.",
    parameters: z.object({
      ips: z
        .array(z.string())
        .describe(
          "List of IP addresses to perform reverse DNS lookup on."
        ),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const ipsString = args.ips.join(",");

      const result: ReverseDnsResponse = await queryShodan("/dns/reverse", {
        ips: ipsString,
      });

      const formattedResult = {
        "Reverse DNS Resolutions": Object.entries(result).map(
          ([ip, hostnames]) => ({
            "IP Address": ip,
            Hostnames:
              hostnames.length > 0 ? hostnames : ["No hostnames found"],
          })
        ),
        Summary: {
          "Total IPs Queried": args.ips.length,
          "IPs with Results": Object.keys(result).length,
          "Queried IP Addresses": args.ips,
        },
      };

      return JSON.stringify(formattedResult, null, 2);
    },
  });
}
