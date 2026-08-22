"use client";

import { useEffect, useState } from "react";
import { apiClient } from "@/lib/api-client";
import { HealthResponse, HealthStatus } from "@/types/api";

export default function HealthBadge() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    async function checkHealth() {
      try {
        const data = await apiClient.get<HealthResponse>("/api/v1/health");
        if (mounted) {
          setHealth(data);
          setError(null);
        }
      } catch (err: any) {
        if (mounted) {
          console.error("Health check failed:", err);
          setError(err.message || "Failed to connect to API");
          setHealth(null);
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    }

    checkHealth();
    // Refresh every 30s
    const interval = setInterval(checkHealth, 30000);
    
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const getStatusColor = (status?: HealthStatus) => {
    switch (status) {
      case "healthy":
        return "bg-green-500 shadow-green-500/50";
      case "degraded":
        return "bg-yellow-500 shadow-yellow-500/50";
      case "unhealthy":
      default:
        return "bg-red-500 shadow-red-500/50";
    }
  };

  return (
    <div className="flex items-center gap-3 px-4 py-2 rounded-full bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-sm transition-all">
      <div className="relative flex h-3 w-3">
        {!isLoading && !error && (
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${getStatusColor(health?.status)}`} />
        )}
        <span className={`relative inline-flex rounded-full h-3 w-3 shadow-md ${isLoading ? "bg-slate-300" : (error ? "bg-red-500" : getStatusColor(health?.status))}`} />
      </div>
      <div className="flex flex-col">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          API Status
        </span>
        <span className="text-sm font-medium">
          {isLoading ? "Checking..." : error ? "Disconnected" : (
            <span className="capitalize">{health?.status} (v{health?.version})</span>
          )}
        </span>
      </div>
    </div>
  );
}
