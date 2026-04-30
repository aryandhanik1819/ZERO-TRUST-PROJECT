import API from "../services/api";
import { useState } from "react";

export default function Dashboard() {
  const [result, setResult] = useState<any>(null);

  const checkAccess = async () => {
    const token = localStorage.getItem("token");

    const res = await API.post(
      "/access/check",
      {
        resource: "/api/financial-data",
        is_managed_device: false,
        os_patch_days: 90,
        has_antivirus: false,
        is_encrypted: false,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    setResult(res.data);
  };

  const getColor = (decision: string) => {
    if (decision === "ALLOW") return "#22c55e";
    if (decision === "DENY") return "#ef4444";
    if (decision === "STEP_UP_AUTH") return "#facc15";
    return "#38bdf8";
  };

  return (
    <div style={styles.container}>
      <h1>🛡️ Zero Trust Security Dashboard</h1>
      <p style={{ color: "#94a3b8" }}>
        This dashboard checks how safe a request is before allowing access.
      </p>

      <button style={styles.button} onClick={checkAccess}>
        🔍 Run Security Check
      </button>

      {result && (
        <>
          <div
            style={{
              ...styles.card,
              borderLeft: `5px solid ${getColor(result.decision)}`,
            }}
          >
            <h2>Decision: {result.decision}</h2>
            <p>{result.message}</p>
          </div>

          <div style={styles.grid}>
            <div style={styles.card}>
              <h3>⚠ Risk Score</h3>
              <p style={styles.big}>{result.risk_assessment.final_score}/100</p>
            </div>

            <div style={styles.card}>
              <h3>📊 Risk Level</h3>
              <p style={styles.big}>{result.risk_assessment.risk_level}</p>
            </div>

            <div style={styles.card}>
              <h3>🔐 Access</h3>
              <p style={styles.big}>{result.access_level}</p>
            </div>
          </div>

          <div style={styles.card}>
            <h3>📉 Risk Breakdown</h3>
            <ul>
              <li>Identity: {result.risk_assessment.breakdown.identity}</li>
              <li>Device: {result.risk_assessment.breakdown.device}</li>
              <li>Behavior: {result.risk_assessment.breakdown.behavioral}</li>
              <li>Context: {result.risk_assessment.breakdown.context}</li>
            </ul>
          </div>

          <div style={styles.card}>
            <h3>🧠 Why this decision?</h3>
            <ul>
              {result.risk_assessment.explanation.map(
                (item: string, i: number) => (
                  <li key={i}>{item}</li>
                )
              )}
            </ul>
          </div>

          <div style={styles.card}>
            <h3>📡 Monitoring</h3>
            <p>
              Requests: {result.monitoring.session_request_count}
            </p>
            <p>
              Anomalies:{" "}
              {result.monitoring.anomalies_detected ? "⚠ Yes" : "✅ No"}
            </p>
          </div>
        </>
      )}
    </div>
  );
}

const styles = {
  container: {
    padding: "30px",
    background: "#020617",
    color: "white",
    minHeight: "100vh",
  },
  button: {
    marginTop: "15px",
    padding: "12px 20px",
    background: "#2563eb",
    border: "none",
    borderRadius: "8px",
    color: "white",
  },
  grid: {
    display: "flex",
    gap: "15px",
    marginTop: "20px",
  },
  card: {
    background: "#1e293b",
    padding: "20px",
    borderRadius: "10px",
    marginTop: "20px",
    flex: 1,
  },
  big: {
    fontSize: "22px",
    fontWeight: "bold",
  },
};