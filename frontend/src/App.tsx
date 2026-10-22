import { useEffect, useState } from 'react';
import './App.css';

// API helper (typed)
interface HealthResponse {
  status: string;
  version: string;
  kill_switch_active: boolean;
  policy_thresholds: Record<string, any>;
  slack_alerting_enabled: boolean;
  total_events: number;
  total_violations: number;
}
interface ToolExecutionResult {
  decision: string; // ALLOWED | BLOCKED | ESCALATED | FAILED
  execution_status: string;
  correlation_id: string;
  violation_reason?: string;
}
interface EventRecord {
  correlation_id: string;
  timestamp: string;
  agent_id: string;
  requested_tool: string;
  decision: string;
  execution_status: string;
  reason?: string;
}
interface IncidentRecord {
  timestamp: string;
  severity: string;
  reason: string;
  agent_id: string;
  correlation_id: string;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, { credentials: 'include', ...init });
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${txt}`);
  }
  return resp.json();
}

function Header({ health }: { health: HealthResponse | null }) {
  const kill = health?.kill_switch_active ?? false;
  return (
    <header className="flex items-center justify-between p-4 bg-gray-800 border-b border-gray-700 text-gray-100">
      <h1 className="text-xl font-semibold">AgentGuard</h1>
      <div className="flex items-center space-x-4">
        <span className="text-sm">Backend: {health?.status ?? '…'}</span>
        <span className={`px-2 py-1 rounded text-xs font-medium ${kill ? 'bg-red-600' : 'bg-green-600'}`}>
          Kill‑Switch: {kill ? 'ACTIVE' : 'OFF'}
        </span>
      </div>
    </header>
  );
}

function StatCard({ title, value }: { title: string; value: number | string }) {
  return (
    <div className="bg-gray-700 rounded-lg p-4 text-center shadow-sm">
      <p className="text-sm text-gray-400 mb-1">{title}</p>
      <p className="text-2xl font-medium text-gray-100">{value}</p>
    </div>
  );
}

function SecurityOverview({ health }: { health: HealthResponse | null }) {
  if (!health) return null;
  const { total_events, total_violations } = health;
  return (
    <section className="grid grid-cols-2 gap-4 mb-6">
      <StatCard title="Tool Calls" value={total_events} />
      <StatCard title="Violations" value={total_violations} />
    </section>
  );
}

function LoanSimulator({ onResult }: { onResult: (res: ToolExecutionResult) => void }) {
  const [agent, setAgent] = useState<'A' | 'B'>('A');
  const [scenario, setScenario] = useState<string>('compliant');
  const [amount, setAmount] = useState(5000);
  const [confidence, setConfidence] = useState(0.95);
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (loading) return;
    setLoading(true);
    try {
      if (agent === 'A') {
        const data = await fetchJson<ToolExecutionResult>(`${API_BASE}/api/v1/agents/agent-a/run`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount, confidence }),
        });
        onResult(data);
      } else {
        const data = await fetchJson<ToolExecutionResult[]>(`${API_BASE}/api/v1/agents/agent-b/run`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario, amount, confidence }),
        });
        if (data && data.length > 0) {
          onResult(data[0]);
        } else {
          throw new Error('Agent B returned no results');
        }
      }
    } catch (e: any) {
      alert('Request failed: ' + e.message);
    } finally {
      setLoading(false);
    }
  };




  const quick = (amt: number, conf: number, sc?: string, ag?: 'A' | 'B') => {
    setAmount(amt);
    setConfidence(conf);
    if (ag) setAgent(ag);
    if (sc) setScenario(sc);
  };

  return (
    <section className="bg-gray-800 rounded-lg p-6 mb-6">
      <h2 className="text-xl font-medium text-gray-100 mb-4">Loan Simulator</h2>
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="block text-sm text-gray-300 mb-1">Agent</label>
          <select
            value={agent}
            onChange={e => setAgent(e.target.value as any)}
            className="w-full rounded border border-gray-600 bg-gray-700 text-gray-100 p-2"
          >
            <option value="A">Agent A (compliant)</option>
            <option value="B">Agent B (adversarial)</option>
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Amount (₹)</label>
          <input
            type="number"
            value={amount}
            onChange={e => setAmount(Number(e.target.value))}
            className="w-full rounded border border-gray-600 bg-gray-700 text-gray-100 p-2"
          />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Confidence (0‑1)</label>
          <input
            type="number"
            step="0.01"
            min="0"
            max="1"
            value={confidence}
            onChange={e => setConfidence(Number(e.target.value))}
            className="w-full rounded border border-gray-600 bg-gray-700 text-gray-100 p-2"
          />
        </div>
      </div>
      <div className="flex gap-3 mb-4">
        <button onClick={() => quick(5000, 0.95, 'compliant', 'A')} className="flex-1 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-500 transition">
          Safe loan
        </button>
        <button onClick={() => quick(5000, 0.4, 'low_confidence', 'B')} className="flex-1 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-500 transition">
          Low confidence
        </button>
        <button onClick={() => quick(50000, 0.99, 'high_value_bypass', 'B')} className="flex-1 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-500 transition">
          High‑value bypass
        </button>
      </div>
      <button
        onClick={submit}
        disabled={loading}
        className={`w-full py-2 rounded text-white ${loading ? 'bg-gray-500 cursor-not-allowed' : 'bg-green-600 hover:bg-green-500 transition'}`}
      >
        {loading ? 'Submitting…' : 'Submit proposal'}
      </button>
    </section>
  );
}


function ResultPanel({ result }: { result: ToolExecutionResult | null }) {
  if (!result) {
    return (
      <section className="bg-gray-800 rounded-lg p-4 mt-4 text-gray-400">
        <p>No result yet. Submit a proposal to see the decision.</p>
      </section>
    );
  }
  const colorMap: Record<string, string> = {
    ALLOWED: 'bg-green-600',
    BLOCKED: 'bg-red-600',
    ESCALATED: 'bg-yellow-600',
    FAILED: 'bg-gray-600',
  };
  const bg = colorMap[result.decision] ?? 'bg-gray-600';
  return (
    <section className="bg-gray-800 rounded-lg p-4 mt-4 text-gray-100">
      <h3 className="text-lg font-medium mb-2">Decision</h3>
      <span className={`inline-block px-2 py-1 text-sm font-medium rounded ${bg}`}>{result.decision}</span>
      <div className="mt-3 space-y-1">
        <p>Execution status: {result.execution_status}</p>
        {result.violation_reason && <p>Reason: {result.violation_reason}</p>}
        <p>Correlation ID: {result.correlation_id}</p>
      </div>
    </section>
  );
}


function EventFeed() {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const fetch = async () => {
    try {
      const data = await fetchJson<EventRecord[]>(`${API_BASE}/api/v1/observability/events?limit=10`);
      setEvents(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    fetch();
    const id = setInterval(fetch, 5000);
    return () => clearInterval(id);
  }, []);

  if (loading) {
    return <p className="text-gray-400">Loading events…</p>;
  }
  if (events.length === 0) {
    return <p className="text-gray-400">No recent events.</p>;
  }

  return (
    <section className="bg-gray-800 rounded-lg p-4 mb-6">
      <h2 className="text-lg font-medium text-gray-100 mb-2">Recent Events</h2>
      <table className="w-full text-sm text-gray-200 divide-y divide-gray-700">
        <thead className="border-b border-gray-700">
          <tr>
            <th className="text-left py-1">Time</th>
            <th className="text-left py-1">Agent</th>
            <th className="text-left py-1">Tool</th>
            <th className="text-left py-1">Decision</th>
            <th className="text-left py-1">Status</th>
          </tr>
        </thead>
        <tbody>
          {events.map(ev => (
            <tr key={ev.correlation_id} className="border-b border-gray-700">
              <td className="py-1">{new Date(ev.timestamp).toLocaleTimeString()}</td>
              <td className="py-1">{ev.agent_id}</td>
              <td className="py-1">{ev.requested_tool}</td>
              <td className="py-1 font-medium">{ev.decision}</td>
              <td className="py-1">{ev.execution_status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}


function IncidentPanel() {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const fetch = async () => {
    try {
      const data = await fetchJson<IncidentRecord[]>(`${API_BASE}/api/v1/monitoring/incidents?limit=10`);
      setIncidents(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    fetch();
    const id = setInterval(fetch, 5000);
    return () => clearInterval(id);
  }, []);

  if (loading) {
    return <p className="text-gray-400">Loading incidents…</p>;
  }
  if (incidents.length === 0) {
    return <p className="text-gray-400">No incidents recorded.</p>;
  }

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-600';
      case 'HIGH':
        return 'bg-yellow-600';
      case 'MEDIUM':
        return 'bg-indigo-600';
      default:
        return 'bg-gray-600';
    }
  };

  return (
    <section className="bg-gray-800 rounded-lg p-4 mb-6">
      <h2 className="text-lg font-medium text-gray-100 mb-2">Recent Incidents</h2>
      <table className="w-full text-sm text-gray-200">
        <thead className="border-b border-gray-700">
          <tr>
            <th className="text-left py-1">Time</th>
            <th className="text-left py-1">Severity</th>
            <th className="text-left py-1">Reason</th>
            <th className="text-left py-1">Agent</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map(inc => (
            <tr key={inc.correlation_id} className="border-b border-gray-700">
              <td className="py-1">{new Date(inc.timestamp).toLocaleTimeString()}</td>
              <td className="py-1">
                <span className={`px-2 py-0.5 rounded ${severityColor(inc.severity)} text-xs`}>{inc.severity}</span>
              </td>
              <td className="py-1">{inc.reason}</td>
              <td className="py-1">{inc.agent_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [result, setResult] = useState<ToolExecutionResult | null>(null);

  useEffect(() => {
    fetchJson<HealthResponse>(`${API_BASE}/health`).then(setHealth).catch(console.error);
  }, []);

  return (
    <div className="flex min-h-screen bg-gray-900 text-gray-100">
      {/* Sidebar */}
      <aside className="w-56 bg-gray-800 border-r border-gray-700 p-4 flex flex-col">
        <h2 className="text-xl font-bold text-gray-100 mb-6">AgentGuard</h2>
        <nav className="flex flex-col space-y-2">
          <a href="#" className="text-gray-300 hover:text-gray-100">Overview</a>
          <a href="#" className="text-gray-300 hover:text-gray-100">Simulator</a>
          <a href="#" className="text-gray-300 hover:text-gray-100">Events</a>
          <a href="#" className="text-gray-300 hover:text-gray-100">Incidents</a>
          <a href="#" className="text-gray-300 hover:text-gray-100">Policy Rules</a>
        </nav>
      </aside>

      <div className="flex-1 flex flex-col overflow-auto">
        <Header health={health} />
        <main className="p-6 flex-1 space-y-6">
          <SecurityOverview health={health} />
          <LoanSimulator onResult={setResult} />
          <ResultPanel result={result} />
          <EventFeed />
          <IncidentPanel />
        </main>
      </div>
    </div>
  );
}

export default App;
