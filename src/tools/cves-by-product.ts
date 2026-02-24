import { FastMCP, UserError } from "fastmcp";
import { z } from "zod";
import { queryCVEsByProduct, getCvssSeverity } from "../helpers.js";
import type { CveResponse } from "../types.js";

export function registerCvesByProduct(server: FastMCP) {
  server.addTool({
    name: "cves_by_product",
    description:
      "Search for vulnerabilities affecting specific products or CPEs. Supports filtering by KEV status, sorting by EPSS score, date ranges, and pagination. Can search by product name or CPE 2.3 identifier. Returns detailed vulnerability information including severity scores and impact assessments.",
    parameters: z.object({
      cpe23: z
        .string()
        .optional()
        .describe(
          "The CPE version 2.3 identifier (format: cpe:2.3:part:vendor:product:version)."
        ),
      product: z
        .string()
        .optional()
        .describe("The name of the product to search for CVEs."),
      count: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, returns only the count of matching CVEs."
        ),
      is_kev: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, returns only CVEs with the KEV flag set."
        ),
      sort_by_epss: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, sorts CVEs by EPSS score in descending order."
        ),
      skip: z
        .number()
        .optional()
        .default(0)
        .describe("Number of CVEs to skip (for pagination)."),
      limit: z
        .number()
        .optional()
        .default(1000)
        .describe("Maximum number of CVEs to return (max 1000)."),
      start_date: z
        .string()
        .optional()
        .describe(
          "Start date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)."
        ),
      end_date: z
        .string()
        .optional()
        .describe(
          "End date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)."
        ),
    }),
    annotations: {
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args) => {
      if (args.cpe23 && args.product) {
        throw new UserError(
          "Cannot specify both cpe23 and product. Use only one."
        );
      }
      if (!args.cpe23 && !args.product) {
        throw new UserError("Must specify either cpe23 or product.");
      }

      const result = await queryCVEsByProduct({
        cpe23: args.cpe23,
        product: args.product,
        count: args.count,
        is_kev: args.is_kev,
        sort_by_epss: args.sort_by_epss,
        skip: args.skip,
        limit: args.limit,
        start_date: args.start_date,
        end_date: args.end_date,
      });

      const formattedResult = args.count
        ? {
            "Query Information": {
              Product: args.product || "N/A",
              "CPE 2.3": args.cpe23 || "N/A",
              "KEV Only": args.is_kev ? "Yes" : "No",
              "Sort by EPSS": args.sort_by_epss ? "Yes" : "No",
            },
            Results: {
              "Total CVEs Found": result.total,
            },
          }
        : {
            "Query Information": {
              Product: args.product || "N/A",
              "CPE 2.3": args.cpe23 || "N/A",
              "KEV Only": args.is_kev ? "Yes" : "No",
              "Sort by EPSS": args.sort_by_epss ? "Yes" : "No",
              "Date Range": args.start_date
                ? `${args.start_date} to ${args.end_date || "now"}`
                : "All dates",
            },
            "Results Summary": {
              "Total CVEs Found": result.total,
              "CVEs Returned": result.cves.length,
              Page: `${Math.floor(args.skip! / args.limit!) + 1}`,
              "CVEs per Page": args.limit,
            },
            Vulnerabilities: result.cves.map((cve: CveResponse) => ({
              "Basic Information": {
                "CVE ID": cve.cve_id,
                Published: new Date(cve.published_time).toLocaleString(),
                Summary: cve.summary,
              },
              "Severity Scores": {
                "CVSS v3": cve.cvss_v3
                  ? {
                      Score: cve.cvss_v3,
                      Severity: getCvssSeverity(cve.cvss_v3),
                    }
                  : "Not available",
                "CVSS v2": cve.cvss_v2
                  ? {
                      Score: cve.cvss_v2,
                      Severity: getCvssSeverity(cve.cvss_v2),
                    }
                  : "Not available",
                EPSS: cve.epss
                  ? {
                      Score: `${(cve.epss * 100).toFixed(2)}%`,
                      Ranking: `Top ${(cve.ranking_epss * 100).toFixed(2)}%`,
                    }
                  : "Not available",
              },
              "Impact Assessment": {
                "Known Exploited Vulnerability": cve.kev ? "Yes" : "No",
                "Proposed Action":
                  cve.propose_action || "No specific action proposed",
                "Ransomware Campaign":
                  cve.ransomware_campaign ||
                  "No known ransomware campaigns",
              },
              References:
                cve.references?.length > 0
                  ? cve.references
                  : ["No references provided"],
            })),
          };

      return JSON.stringify(formattedResult, null, 2);
    },
  });
}
