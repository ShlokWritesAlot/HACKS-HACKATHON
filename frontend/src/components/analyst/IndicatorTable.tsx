"use client";

import React, { useEffect, useState } from "react";

interface Props {
  token: string;
}

export default function IndicatorTable({ token }: Props) {
  const [indicators, setIndicators] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/v1/analyst/indicators", {
      headers: { "X-Session-Token": token },
    })
      .then((res) => res.json())
      .then((d) => setIndicators(Array.isArray(d) ? d : []))
      .catch(() => setIndicators([]))
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) {
    return <div className="text-slate-400 text-sm p-6 text-center">Loading Threat Indicators...</div>;
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      <div className="px-5 py-4 border-b border-slate-800 flex justify-between items-center">
        <h3 className="text-sm font-semibold text-slate-200">Extracted Threat Indicators (IOCs)</h3>
        <span className="text-xs text-slate-400">{indicators.length} unique indicators</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
            <tr>
              <th className="px-5 py-3">Type</th>
              <th className="px-5 py-3">Value</th>
              <th className="px-5 py-3">Occurrences</th>
              <th className="px-5 py-3">Confidence</th>
              <th className="px-5 py-3">SSRF Classification</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {indicators.map((item, idx) => (
              <tr key={idx} className="hover:bg-slate-800/40 transition">
                <td className="px-5 py-3.5 font-semibold uppercase text-slate-400">{item.type}</td>
                <td className="px-5 py-3.5 font-mono text-red-300">{item.value}</td>
                <td className="px-5 py-3.5 font-bold">{item.count}</td>
                <td className="px-5 py-3.5 text-emerald-400">{(item.confidence * 100).toFixed(0)}%</td>
                <td className="px-5 py-3.5 font-mono uppercase text-xs">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    item.ssrf_risk === "safe"
                      ? "bg-emerald-950 text-emerald-300 border border-emerald-800/60"
                      : "bg-red-950 text-red-300 border border-red-800/60"
                  }`}>
                    {item.ssrf_risk}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
