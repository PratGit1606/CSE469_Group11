# BCHOC: Blockchain Chain of Custody

## Group Information
**Group Name:** Group #11  
**Members:** Pratham Hegde, Kara Melvin, Raj Sarode, Ben Kim, Justin Guerro 

---

## Project Overview
This project implements a **Blockchain Chain of Custody (BCHOC)** system — a digital version of a chain of custody form used in forensic investigations. The system ensures that all evidence handling actions are securely recorded, tamper-evident, and verifiable through blockchain technology.

In forensic practice, a chain of custody form answers:
- **Where** the evidence was stored,  
- **Who** accessed the evidence (and when),  
- **What actions** were performed on the evidence.  

By storing these actions in a blockchain, the project guarantees immutability, transparency, and verifiable integrity of evidence logs.

---

## Features and Commands
The `bchoc` program provides the following commands:

- `bchoc add -c case_id -i item_id [-i item_id ...] -g creator -p password`  
  Add new evidence items to a case. New items are CHECKEDIN by default.  

- `bchoc checkout -i item_id -p password`  
  Checkout an existing evidence item.  

- `bchoc checkin -i item_id -p password`  
  Check an evidence item back into storage.  

- `bchoc show cases`  
  Display all case identifiers.  

- `bchoc show items -c case_id`  
  Display all evidence items for a given case.  

- `bchoc show history [-c case_id] [-i item_id] [-n num_entries] [-r] -p password`  
  Display chronological (or reverse) history of evidence items.  

- `bchoc remove -i item_id -y reason -p password`  
  Remove an item permanently with a valid reason: DISPOSED, DESTROYED, or RELEASED.  

- `bchoc init`  
  Initialize the blockchain and ensure the **Genesis Block** exists.  

- `bchoc verify`  
  Validate the blockchain, checking for corruption, invalid actions, or tampering.  

- `bchoc summary -c case_id`  
  Summarize the blockchain: number of unique item IDs and counts by state (CHECKEDIN, CHECKEDOUT, DISPOSED, DESTROYED, RELEASED).  

---

## Data Structure
Each blockchain block includes:
- Previous Hash (32 bytes)  
- Timestamp (UTC, 8 bytes)  
- Case ID (UUID, 32 bytes, AES-encrypted)  
- Item ID (4-byte integer, AES-encrypted)  
- State (12 bytes, e.g., CHECKEDIN/OUT)  
- Creator and Owner IDs (12 bytes each)  
- Data Length and Data Payload  

All data is stored in **binary format**. Timestamps are in UTC.  

---

## System Requirements
- **OS:** Ubuntu 18.04 LTS (or later)  
- **Python:** Version 3.7+ recommended  
- **Dependencies:** Listed in `packages` file if not default  

Environment variables:
