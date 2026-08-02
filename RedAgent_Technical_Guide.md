# RedAgent: Autonomous Penetration Testing Platform
## Technical Architecture & Setup Guide

Welcome to RedAgent! This guide is designed to help both technical and non-technical team members understand how RedAgent works, what technologies it uses, how it stores data, and how to run it.

---

### 1. What is RedAgent? (The Non-Technical Overview)
RedAgent is an **Autonomous Penetration Testing Agent**. Think of it as an AI-powered cybersecurity expert that works inside an isolated lab environment. 
When you give it a target (like a vulnerable test server), RedAgent automatically:
- **Plans its attack** (like a real hacker would).
- **Runs security tools** (to find open ports and weaknesses).
- **Analyzes the results** to understand what vulnerabilities exist.
- **Generates a professional PDF report** summarizing the risks and how to fix them.

**Safety First:** RedAgent has a strict "Scope Gate". It will *only* attack private lab servers that you explicitly authorize. It will refuse to attack public internet servers unless explicitly added to the authorized public scope.

---

### 2. The Technical Architecture (How It Works Under the Hood)
RedAgent is built using a modern, 4-layer architecture:

1. **The Brain (AI Agent Layer)**
   - Uses **LangGraph** and **LangChain** to create a "ReAct" (Reason → Act → Observe) loop. The AI thinks about what to do, runs a tool, looks at the output, and decides its next step.
   - **LLM (Large Language Model):** Powered primarily by **Groq** (using the `llama-3.3-70b-versatile` model) for incredibly fast reasoning. It also has a local fallback (`Ollama`) if needed.

2. **The Tool Belt (Execution Layer)**
   - RedAgent wraps industry-standard security tools so the AI can use them:
     - **Subfinder:** Finds subdomains.
     - **Nmap:** Scans for open ports and services.
     - **Nikto & Nuclei:** Scans for specific web vulnerabilities.
     - **SQLMap & Metasploit:** Used for deeper exploitation (always defaults to safe mode).

3. **The Memory & Knowledge Base (Data Layer)**
   - **RAG (Retrieval-Augmented Generation):** RedAgent has a local copy of the **NVD (National Vulnerability Database)**. It contains over 240,000 known vulnerabilities (CVEs). When the agent finds a software version (e.g., `nginx 1.14`), it instantly searches this database to see if it's vulnerable.

4. **The Operator Dashboard (User Interface Layer)**
   - A beautiful web interface where you can watch the AI "think" in real-time, manage your scope, and download PDF reports.

---

### 3. Tech Stack & Databases
Here is the exact technology stack used to build RedAgent:

#### Core Programming Languages
- **Backend:** Python (FastAPI)
- **Frontend:** TypeScript / React 19

#### Databases (Where is data stored?)
RedAgent uses two main databases:
1. **PostgreSQL (Relational Database)**
   - **What it stores:** Engagement history, scan results, and tool findings.
   - **Where it lives:** Usually run via Docker locally. This ensures that even if you restart the server, your past pentest reports and findings are saved.
2. **ChromaDB (Vector Database for AI)**
   - **What it stores:** The massive NVD vulnerability database (~2-3 GB of data). It converts text into mathematical vectors (using `sentence-transformers`) so the AI can search for vulnerabilities instantly based on meaning.
   - **Where it lives:** Stored locally in a hidden folder (`chroma_db/`) inside the project directory. It runs entirely offline and costs nothing.

#### Frontend & UI
- **Framework:** React with Vite.
- **Styling:** Tailwind CSS and shadcn/ui components for a sleek, modern look.
- **Communication:** WebSockets are used so the backend can stream the AI's thoughts to the frontend live.

---

### 4. How to Run and Access the Project
Running RedAgent requires starting both the backend API and the frontend Dashboard.

#### Step 1: Start the Backend (The Brain & API)
Open a terminal, navigate to the RedAgent folder, and run:
```bash
# Activate the Python virtual environment
source .venv/bin/activate

# Start the FastAPI server
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```
- **Access the API Docs:** Open your browser to `http://localhost:8000/docs` to see all available API endpoints.

#### Step 2: Start the Frontend (The Dashboard)
Open a second terminal, navigate to the dashboard folder, and run:
```bash
cd dashboard
npm run dev
```
- **Access the Dashboard:** Open your browser to `http://localhost:5173`. You will see the RedAgent interface.

#### Step 3: Running an Engagement
1. Open the Dashboard at `http://localhost:5173`.
2. Look at the **Scope Manager** on the right side. Ensure your target IP or domain is listed there (either under Lab or Public scope).
3. Type the target into the **Target Bar** at the top and click **Launch**.
4. Watch the **Reasoning Stream** as the AI plans its attack, runs tools like Nmap and Nuclei, and discovers vulnerabilities.
5. Once finished, click **Export PDF** to download the final report.

---

### Summary
RedAgent bridges the gap between advanced cybersecurity tools and cutting-edge AI. By using a robust Python backend, a blazing-fast React frontend, and local, secure databases (PostgreSQL and ChromaDB), it provides a safe, autonomous penetration testing experience that is both powerful for experts and easy to understand for beginners.
