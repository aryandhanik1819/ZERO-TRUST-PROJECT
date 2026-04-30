import { useState } from "react";
import API from "../services/api";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const navigate = useNavigate();

  const login = async () => {
    try {
      const res = await API.post("/auth/login", {
        username,
        password,
      });

      localStorage.setItem("token", res.data.access_token);
      navigate("/dashboard");
    } catch {
      alert("Login failed");
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1>🔐 Secure Login</h1>
        <p style={{ color: "#94a3b8" }}>
          Access your Zero Trust Security Dashboard
        </p>

        <input
          style={styles.input}
          placeholder="Username"
          onChange={(e) => setUsername(e.target.value)}
        />

        <input
          style={styles.input}
          type="password"
          placeholder="Password"
          onChange={(e) => setPassword(e.target.value)}
        />

        <button style={styles.button} onClick={login}>
          Login Securely
        </button>

        <p style={styles.demo}>Demo: alice / Alice@123</p>
      </div>
    </div>
  );
}

const styles = {
  container: {
    height: "100vh",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    background: "linear-gradient(135deg, #0f172a, #020617)",
  },
  card: {
    background: "rgba(255,255,255,0.05)",
    padding: "30px",
    borderRadius: "12px",
    backdropFilter: "blur(10px)",
    textAlign: "center",
  },
  input: {
    display: "block",
    width: "250px",
    margin: "10px auto",
    padding: "10px",
    borderRadius: "6px",
    border: "none",
  },
  button: {
    marginTop: "10px",
    padding: "10px 20px",
    borderRadius: "6px",
    background: "#2563eb",
    color: "white",
    border: "none",
    cursor: "pointer",
  },
  demo: {
    marginTop: "15px",
    fontSize: "12px",
    color: "#64748b",
  },
};