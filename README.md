# 🛡️ Network Threat Detection Automata System

An Automata-driven Network Intrusion Detection System (NIDS) that applies **Formal Languages and Automata Theory (TOA)** principles—specifically **Deterministic Finite Automata (DFA)**—to inspect network payloads and detect malicious attack signatures in real time.

---

## 📌 Project Overview

Traditional pattern-matching engines can suffer from high computational overhead when parsing complex regular expressions. This project demonstrates how **Deterministic Finite Automata (DFA)** can be constructed to achieve linear-time $O(n)$ pattern matching for recognizing cyber threats, including:
- **SQL Injection (SQLi) Signatures**
- **Port Scanning Patterns**
- **Cross-Site Scripting (XSS) Payloads**
- **Suspicious Command Injections**

---

## ✨ Key Features

- ⚙️ **Finite State Machine (FSM) Engine:** Fast string processing using custom DFA/NFA state transitions.
- 🔍 **Threat Pattern Matching:** Matches input streams against valid state paths corresponding to known attack signatures.
- 📊 **State Transition Tracking:** Log execution paths and identify exact states where malicious patterns trigger an ACCEPT state.
- ⚡ **Optimized Performance:** Guarantees deterministic $O(n)$ time complexity for pattern verification.

---

## 🧮 How It Works (Automata Logic)

1. **Alphabet ($\Sigma$):** Set of ASCII characters representing network packet contents/logs.
2. **States ($Q$):** Collection of operational states representing progress through potential threat patterns.
3. **Start State ($q_0$):** Initial state awaiting network packet stream.
4. **Transition Function ($\delta$):** Maps current state and incoming character to the next state $\delta(q, a) \rightarrow q'$.
5. **Accepting/Final States ($F$):** Reached when a malicious pattern is fully matched (triggers an alert).

---

## 🛠️ Tech Stack

- **Language:** C*
- **Core Concepts:** Deterministic Finite Automata (DFA), Non-Deterministic Finite Automata (NFA), Regular Languages, State Transition Graphs.

---

## 🚀 Getting Started

### Prerequisites
- Compiler / Runtime environment (C).

### Installation & Execution
1. Clone the repository:
   ```bash
   git clone [https://github.com/skillsstackpro/Network-Threat-Detection-Automata-System.git](https://github.com/skillsstackpro/Network-Threat-Detection-Automata-System.git)
