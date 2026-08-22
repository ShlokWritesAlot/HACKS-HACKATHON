"use client";

import React, { useEffect, useState } from "react";

interface Props {
  token: string;
}

export default function OverviewDashboard({ token }: Props) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/v1/analyst/overview", {
      headers: { "X-Session-Token": token },
    })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to fetch overview metrics.");
        return res.json();
      })
      .then((d) => setData(d))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) {
    return <div className="text-slate-400 text-sm p-6 text-center">Loading Overview Telemetry...</div>;
  }

  if (error || !data) {
    return <div className="text-red-400 text-sm p-6 bg-red-950/40 rounded-lg">{error || "Failed to load"}</div>;
  }

  return (
    <div className="space-y-6">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Scanned</p>
          <h3 className="text-2xl font-bold text-slate-100 mt-2">{data.total_messages}</h3>
          <p className="text-xs text-slate-500 mt-1">Processed across engines</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">High Risk Threat %</p>
          <h3 className="text-2xl font-bold text-red-400 mt-2">{data.high_risk_percentage}%</h3>
          <p className="text-xs text-slate-500 mt-1">{data.high_risk_count} confirmed criticals</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Campaigns</p>
          <h3 className="text-2xl font-bold text-amber-400 mt-2">{data.active_campaigns_count}</h3>
          <p className="text-xs text-slate-500 mt-1">Tracked semantic clusters</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Scam Taxonomy</p>
          <h3 className="text-2xl font-bold text-emerald-400 mt-2">{Object.keys(data.scam_family_distribution).length}</h3>
          <p className="text-xs text-slate-500 mt-1">Active scam families</p>
        </div>
      </div>

      {/* Distributions & Threat Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scam Families */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h4 className="text-sm font-semibold text-slate-200 mb-4">Scam Family Distribution</h4>
          <div className="space-y-3">
            {Object.entries(data.scam_family_distribution).map(([family, count]: any) => (
              <div key={family} className="space-y-1">
                <div className="flex justify-between text-xs font-medium">
                  <span className="text-slate-300">{family}</span>
                  <span className="text-slate-400">{count}</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className="bg-red-500 h-full rounded-full"
                    style={{ width: `${Math.min(100, (count / data.total_messages) * 100 * 2)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Threats */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h4 className="text-sm font-semibold text-slate-200 mb-4">Recent Threats Detected</h4>
          <div className="space-y-3">
            {data.recent_threats.map((t: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 bg-slate-950 border border-slate-800/80 rounded-lg text-xs">
                <div>
                  <span className="font-semibold text-slate-200">{t.type}</span>
                  <p className="text-slate-400 mt-0.5">{t.domain || t.phone || t.upi}</p>
                </div>
                <div className="px-2.5 py-1 rounded bg-red-950 border border-red-800/60 text-red-300 font-bold">
                  Risk {t.risk}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
