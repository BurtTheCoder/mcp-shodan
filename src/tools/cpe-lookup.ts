import { FastMCP } from "fastmcp";
import { z } from "zod";
import { queryCPEDB } from "../helpers.js";

export function registerCpeLookup(server: FastMCP) {
  server.addTool({
    name: "cpe_lookup",
    description:
      "Search for Common Platform Enumeration (CPE) entries by product name in Shodan's CVEDB. Supports pagination and can return either full CPE details or just the total count. Useful for identifying specific versions and configurations of software and hardware.",
    parameters: z.object({
      product: z
        .string()
        .describe("The name of the product to search for CPEs."),
      count: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, returns only the count of matching CPEs."
        ),
      skip: z
        .number()
        .optional()
        .default(0)
        .describe("Number of CPEs to skip (for pagination)."),
      limit: z
        .number()
        .optional()
        .default(1000)
        .describe("Maximum number of CPEs to return (max 1000)."),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      const result = await queryCPEDB({
        product: args.product,
        count: args.count,
        skip: args.skip,
        limit: args.limit,
      });

      const formattedResult = args.count
        ? { total_cpes: result.total }
        : {
            cpes: result.cpes,
            skip: args.skip,
            limit: args.limit,
            total_returned: result.cpes.length,
          };

      return JSON.stringify(formattedResult, null, 2);
    },
  });
}
