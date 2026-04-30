🛡️ Zero Trust Security Framework

A full-stack cybersecurity project implementing the Zero Trust Architecture principle:

🔐 "Never Trust, Always Verify"

This system evaluates every access request dynamically based on Identity, Device, Behavior, and Context, and decides whether to ALLOW, DENY, or STEP-UP authentication.

🚀 Features
🔑 Secure Login using JWT Authentication
🧠 Risk-Based Access Control System
📊 Interactive Security Dashboard
📉 Risk Score & Breakdown Visualization
📡 Session Monitoring
📝 Audit Logging for Security Events
🔍 Zero Trust Policy Engine
🏗️ Architecture
Frontend (React) 
        ↓
FastAPI Backend 
        ↓
Risk Engine → Policy Engine → Access Decision
Zero Trust Factors Used:
👤 Identity → User authentication & MFA
💻 Device → Device trust, patch status, antivirus
🧠 Behavior → Activity patterns, request frequency
🌍 Context → IP reputation, location, network
🖥️ Tech Stack
🔹 Frontend
React (TypeScript)
Axios
React Router
🔹 Backend
FastAPI
Python
JWT Authentication
SQLAlchemy
📸 Screenshots
🔐 Login Page

📊 Dashboard

⚙️ How to Run
🔹 Backend
pip install fastapi uvicorn sqlalchemy bcrypt pyjwt
uvicorn api.main:app --reload
🔹 Frontend
cd frontend
npm install
npm run dev
🧪 Demo Credentials
Username: alice
Password: Alice@123
📊 Example Output
Risk Score: 85
Risk Level: HIGH
Decision: DENY
Example Risk Factors:
Unmanaged device
No antivirus protection
High request frequency
🎯 Learning Outcomes
Implemented Zero Trust Security Model
Built secure authentication using JWT tokens
Designed risk-based decision system
Integrated frontend with secure backend APIs
Visualized cybersecurity concepts in a user-friendly dashboard
👨‍💻 My Contribution

As the Frontend Developer, I was responsible for:

Designing and developing the React-based UI
Building the Login System with JWT authentication
Creating the Security Dashboard
Visualizing:
Risk Score
Access Decision
Risk Breakdown
Making the system easy to understand for non-technical users
📌 Future Improvements
📊 Add charts & data visualization
🧠 AI-based anomaly detection
🌐 Deploy on cloud (AWS / Azure)
🐳 Docker containerization
🔄 CI/CD pipeline
⭐ Give a Star

If you found this project useful or interesting, please ⭐ the repository!

👤 Author

Aryan Singh Dhanik
Frontend Developer | Cybersecurity Enthusiast
