import axios from "axios";
import { UserError } from "fastmcp";

export const API_BASE_URL = "https://api.shodan.io";
export const CVEDB_API_URL = "https://cvedb.shodan.io";
export const SHODAN_API_KEY = process.env.SHODAN_API_KEY!;

export async function queryShodan(endpoint: string, params: Record<string, any>) {
  try {
    const response = await axios.get(`${API_BASE_URL}${endpoint}`, {
      params: { ...params, key: SHODAN_API_KEY },
      timeout: 10000,
    });
    return response.data;
  } catch (error: any) {
    const errorMessage = error.response?.data?.error || error.message;
    console.error(`Shodan API error: ${errorMessage}`);
    throw new UserError(`Shodan API error: ${errorMessage}`);
  }
}

export async function queryCVEDB(cveId: string) {
  try {
    const response = await axios.get(`${CVEDB_API_URL}/cve/${cveId}`);
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new UserError(`Invalid CVE ID format: ${cveId}`);
    }
    if (error.response?.status === 404) {
      throw new UserError(`CVE not found: ${cveId}`);
    }
    throw new UserError(`CVEDB API error: ${error.message}`);
  }
}

export async function queryCPEDB(params: {
  product: string;
  count?: boolean;
  skip?: number;
  limit?: number;
}) {
  try {
    const response = await axios.get(`${CVEDB_API_URL}/cpes`, { params });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new UserError(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new UserError(`CVEDB API error: ${error.message}`);
  }
}

export async function queryCVEsByProduct(params: {
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
    const response = await axios.get(`${CVEDB_API_URL}/cves`, { params });
    return response.data;
  } catch (error: any) {
    if (error.response?.status === 422) {
      throw new UserError(`Invalid parameters: ${error.response.data?.detail || error.message}`);
    }
    throw new UserError(`CVEDB API error: ${error.message}`);
  }
}

export function getCvssSeverity(score: number): string {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >= 0.1) return "Low";
  return "None";
}
