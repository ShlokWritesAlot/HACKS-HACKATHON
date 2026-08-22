"use client";

import React, { useEffect, useState } from "react";

interface Props {
  token: string;
}

export default function CampaignTable({ token }: Props) {
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCampaign, setSelectedCampaign] = useState<any>(null);

  useEffect(() => {
    fetch("/api/v1/campaigns", {
      headers: { "X-Analyst-Key": "dev", "X-Session-Token": token },
    })
      .then((res) => res.json())
      .then((data) => setCampaigns(Array.isArray(data) ? data : []))
      .catch(() => setCampaigns([]))
      .finally(() => setLoading(false));
  }, [token]);

  const loadDetail = (id: string) => {
    fetch(`/api/v1/campaigns/${id}`, {
      headers: { "X-Analyst-Key": "dev", "X-Session-Token": token },
    })
      .then((res) => res.json())
      .then((d) => setSelectedCampaign(d))
      .catch(() => {});
  };

  if (loading) {
    return <div className="text-slate-400 text-sm p-6 text-center">Loading Campaigns...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Campaign List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-4 border-b border-slate-800 flex justify-between items-center">
          <h3 className="text-sm font-semibold text-slate-200">Active Semantic Campaigns</h3>
          <span className="text-xs text-slate-400">{campaigns.length} campaigns tracked</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
              <tr>
                <th className="px-5 py-3">Campaign ID</th>
                <th className="px-5 py-3">Scam Family</th>
                <th className="px-5 py-3">Members</th>
                <th className="px-5 py-3">Confidence</th>
                <th className="px-5 py-3">Language</th>
                <th className="px-5 py-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {campaigns.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-6 text-center text-slate-500">
                    No active campaigns clustered yet.
                  </td>
                </tr>
              ) : (
                campaigns.map((c) => (
                  <tr key={c.campaign_id} className="hover:bg-slate-800/40 transition">
                    <td className="px-5 py-3.5 font-mono text-slate-300">{c.campaign_id.slice(0, 8)}...</td>
                    <td className="px-5 py-3.5 font-semibold text-red-400">{c.scam_family}</td>
                    <td className="px-5 py-3.5">{c.member_count}</td>
                    <td className="px-5 py-3.5 text-emerald-400">{(c.campaign_confidence * 100).toFixed(0)}%</td>
                    <td className="px-5 py-3.5 uppercase">{c.dominant_language}</td>
                    <td className="px-5 py-3.5">
                      <button
                        onClick={() => loadDetail(c.campaign_id)}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-medium text-xs transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Campaign Detail Modal/Drawer */}
      {selectedCampaign && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex justify-between items-start border-b border-slate-800 pb-3">
            <div>
              <h4 className="text-base font-bold text-slate-100">
                Campaign #{selectedCampaign.campaign_id.slice(0, 8)}
              </h4>
              <p className="text-xs text-slate-400 mt-0.5">Family: {selectedCampaign.scam_family}</p>
            </div>
            <button
              onClick={() => setSelectedCampaign(null)}
              className="text-slate-400 hover:text-slate-200 text-xs font-semibold px-2 py-1 bg-slate-800 rounded"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase">Members</span>
              <p className="text-lg font-bold text-slate-200">{selectedCampaign.member_count}</p>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase">Avg Risk</span>
              <p className="text-lg font-bold text-red-400">{selectedCampaign.avg_risk_score}</p>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase">Confidence</span>
              <p className="text-lg font-bold text-emerald-400">
                {(selectedCampaign.campaign_confidence * 100).toFixed(0)}%
              </p>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
              <span className="text-slate-500 uppercase">Dominant Lang</span>
              <p className="text-lg font-bold text-slate-200 uppercase">{selectedCampaign.dominant_language}</p>
            </div>
          </div>

          {selectedCampaign.top_domains?.length > 0 && (
            <div>
              <h5 className="text-xs font-semibold text-slate-300 mb-1">Associated Domains</h5>
              <div className="flex flex-wrap gap-1.5">
                {selectedCampaign.top_domains.map((d: string, i: number) => (
                  <span key={i} className="px-2 py-0.5 bg-slate-950 border border-slate-800 text-red-300 font-mono text-[11px] rounded">
                    {d}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
