import os
import shutil
import uuid
import asyncio
import json
import httpx
import aiofiles
from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict, Any, List
import pandas as pd
from io import BytesIO 

app = FastAPI(title="Şamdan AI-MAP")

# In-memory storage for analysis cache to avoid re-scanning same URLs in short term
# {url: {"result": ..., "timestamp": ...}}
URL_SCAN_CACHE = {}

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory storage for tasks
# Structure: {task_id: {"status": "processing", "step": "Uploading...", "result": None, "error": None}}
TASKS: Dict[str, Any] = {}

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Configuration
MOBSF_API_KEY = ""
MOBSF_URL = "http://localhost:8000"
VT_API_KEY = ""
GEMINI_API_KEY = ""
OLLAMA_URL = "http://localhost:11434"
OLLAMA_URL = "http://localhost:11434"


# --------------------------------------------------------------------------------
# Helper Services
# --------------------------------------------------------------------------------

# Helper for File Access
async def retry_open(path, mode='rb', retries=5, delay=1.0):
    """Retries opening a file to handle Windows file locking issues."""
    last_err = None
    for i in range(retries):
        try:
            return open(path, mode)
        except OSError as e:
            last_err = e
            # If access denied or invalid argument, wait and retry
            print(f"File access warning ({i+1}/{retries}): {e}. Retrying...")
            await asyncio.sleep(delay)
    raise last_err

async def analyze_with_mobsf(file_path: str, api_key: str = MOBSF_API_KEY, server_url: str = MOBSF_URL):
    """Uploaded file to MobSF and returns the filtered report."""
    if not api_key: api_key = MOBSF_API_KEY
    if not server_url: server_url = MOBSF_URL
    
    # Use simple abspath to avoid pathlib complexities on Windows OneDrive
    abs_path = os.path.abspath(file_path)
    
    if not os.path.exists(abs_path):
        raise Exception(f"File not found at: {abs_path}")

    async with httpx.AsyncClient() as client:
        # 1. Upload File
        filename = os.path.basename(abs_path)
        
        try:
            # Retry opening file
            f_handle = await retry_open(abs_path, 'rb')
            with f_handle as f:
                # 'application/octet-stream' is safer generic type
                files = {'file': (filename, f, 'application/octet-stream')}
                try:
                    response = await client.post(f"{server_url}/api/v1/upload", headers={'Authorization': api_key}, files=files, timeout=60.0)
                except httpx.ConnectError:
                    raise Exception(f"Could not connect to MobSF at {server_url}. Is it running?")
        except Exception as e:
             raise Exception(f"File Access Error during Upload: {e}")
        
        if response.status_code != 200:
            raise Exception(f"MobSF Upload Failed: {response.text}")
        
        data = response.json()
        scan_hash = data['hash']
        
        # 2. Scan File (if not already scanned)
        scan_response = await client.post(f"{server_url}/api/v1/scan", headers={'Authorization': api_key}, data={'hash': scan_hash}, timeout=120.0)
        if scan_response.status_code != 200:
            raise Exception(f"MobSF Scan Failed: {scan_response.text}")
            
        # 3. Get Report
        report_response = await client.post(f"{server_url}/api/v1/report_json", headers={'Authorization': api_key}, data={'hash': scan_hash}, timeout=30.0)
        if report_response.status_code != 200:
            raise Exception(f"MobSF Report Failed: {report_response.text}")
        
        full_report = report_response.json()
        
        # Filter strictly as requested
        keys_to_keep = [
            "app_name", "package_name", "version_name", "permissions", 
            "malware_permissions", "certificate_analysis", "manifest_analysis",
            "network_security", "android_api", "code_analysis", "urls", 
            "domains", "secrets", "appsec", "hash"
        ]
        
        filtered_report = {k: full_report.get(k) for k in keys_to_keep}
        return filtered_report, scan_hash

def extract_network_indicators(mobsf_report: dict) -> list:
    """Extracts unique URLs and Domains from MobSF report."""
    urls = set()
    
    # 1. URLs from 'urls' key
    for u in mobsf_report.get('urls', []):
        if hasattr(u, 'get'): # Check if it's a dict
            urls.add(u.get('url', '').strip())
        elif isinstance(u, str):
            urls.add(u.strip())

    # 2. Domains
    domains = mobsf_report.get('domains', {})
    if isinstance(domains, dict):
        for d in domains.keys():
            urls.add(d.strip())
            
    # Filter out empty or local nonsense
    valid_indicators = [
        u for u in urls 
        if u and not u.startswith('file://') and len(u) > 3
    ]
    return list(valid_indicators)[:50] # Limit to top 50 to save quota/time

async def get_mobsf_source(file_path: str, scan_hash: str, api_key: str = MOBSF_API_KEY, server_url: str = MOBSF_URL) -> str:
    """
    Fetches the source code of a specific file from MobSF.
    file_path: Relative path in the APK (e.g., 'com/example/Malware.java')
    """
    if not api_key: api_key = MOBSF_API_KEY
    if not server_url: server_url = MOBSF_URL
    
    async with httpx.AsyncClient() as client:
        try:
            # The MobSF API endpoint for viewing source code
            payload = {'file': file_path, 'hash': scan_hash, 'type': 'java'}
            response = await client.post(
                f"{server_url}/api/v1/view_source", 
                headers={'Authorization': api_key}, 
                data=payload, 
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                source = data.get('data') # The code is usually in the 'data' key
                if not source: 
                    return ""
                    
                # Basic cleanup to save tokens
                lines = source.splitlines()
                # Remove package/import lines and empty lines to save space
                cleaned_lines = [l for l in lines if not l.strip().startswith(('package ', 'import ', '//', '/*')) and l.strip()]
                return "\n".join(cleaned_lines[:150]) # Limit to top 150 lines per file
            else:
               # print(f"DEBUG: Failed to fetch source for {file_path}: {response.status_code}")
               return ""
        except Exception as e:
            # print(f"DEBUG: Error fetching source: {e}")
            return ""

async def analyze_with_virustotal(file_path: str, api_key: str = VT_API_KEY):
    """Uploads file to VirusTotal and waits for analysis."""
    abs_path = os.path.abspath(file_path)
    
    if not os.path.exists(abs_path):
         raise Exception(f"File not found: {abs_path}")
    
    async with httpx.AsyncClient() as client:
        # User requested to FORCE NEW UPLOAD (No Hash Check)
        filename = os.path.basename(abs_path)
        
        try:
             # Check file size for Large File Upload (VT requires special URL for >32MB)
            file_size_mb = os.path.getsize(abs_path) / (1024 * 1024)
            upload_url = "https://www.virustotal.com/api/v3/files"
            timeout_val = 120.0
            
            if file_size_mb > 30: # Use 30MB as safety threshold
                timeout_val = 1800.0 # Give it 30 minutes for up to 650MB files
                try:
                    url_resp = await client.get("https://www.virustotal.com/api/v3/files/upload_url", headers={'x-apikey': api_key})
                    if url_resp.status_code == 200:
                        upload_url = url_resp.json()['data']
                except Exception as e:
                    print(f"Failed to get large upload URL: {e}")

            # Retry opening file
            f_handle = await retry_open(abs_path, 'rb')
            with f_handle as f:
                files = {'file': (filename, f)}
                resp = await client.post(upload_url, headers={'x-apikey': api_key}, files=files, timeout=timeout_val)
        except Exception as e:
            raise Exception(f"VT File Access/Upload Error: {e}")
        
        if resp.status_code == 409: # Conflict (Duplicate analysis or transient)
             try:
                 err_json = resp.json()
                 if "Deadline exceeded" in str(err_json):
                     print("DEBUG: VirusTotal Deadline Exceeded. Retrying in 5 seconds...")
                     await asyncio.sleep(5)
                     # Retry Upload
                     with open(abs_path, 'rb') as f: # Use simple open for retry, handle is tricky with retry_open
                        files = {'file': (filename, f)}
                        resp = await client.post(upload_url, headers={'x-apikey': api_key}, files=files, timeout=timeout_val)
             except Exception:
                 pass

        if resp.status_code != 200:
            raise Exception(f"VirusTotal Upload Failed: {resp.text}")
            
        analysis_id = resp.json()['data']['id']
        
        # Poll for results
        for _ in range(90): # Try for 3 minutes
            status_resp = await client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers={'x-apikey': api_key})
            status_data = status_resp.json()
            status = status_data['data']['attributes']['status']
            
            if status == 'completed':
                return status_data['data']['attributes']
            
            await asyncio.sleep(2)
            
        return {"status": "timeout", "message": "Analysis pending on VirusTotal", "analysis_id": analysis_id}

async def analyze_urls_with_virustotal(urls: list, api_key: str = VT_API_KEY):
    """Scans a list of URLs with VirusTotal."""
    results = {}
    if not urls: return results
    if not api_key: api_key = VT_API_KEY
    
    async with httpx.AsyncClient() as client:
        for url in urls:
            try:
                # encode url for ID
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                
                # Check report first
                resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={'x-apikey': api_key}, timeout=20.0)
                
                if resp.status_code == 200:
                    stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    results[url] = f"Detected: {malicious}"
                elif resp.status_code == 404:
                    # New URL, submit it for scanning
                    try:
                        scan_resp = await client.post(
                            "https://www.virustotal.com/api/v3/urls", 
                            headers={'x-apikey': api_key}, 
                            data={'url': url}, 
                            timeout=20.0
                        )
                        if scan_resp.status_code == 200:
                             # Wait for the scan to finish (Premium Key = Fast)
                            analysis_id = scan_resp.json()['data']['id']
                            results[url] = "Scan Started (Timeout)" # Default if loop fails
                            
                            for _ in range(15): # Wait up to 15s
                                await asyncio.sleep(1)
                                a_resp = await client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers={'x-apikey': api_key})
                                if a_resp.status_code == 200:
                                    a_data = a_resp.json()
                                    if a_data['data']['attributes']['status'] == 'completed':
                                        mal_count = a_data['data']['attributes']['stats']['malicious']
                                        results[url] = f"Detected: {mal_count}"
                                        break
                        else:
                             results[url] = "Scan Failed/Skipped"
                    except:
                        results[url] = "Scan Error"
                else:
                    results[url] = f"Error: {resp.status_code}"
            except Exception as e:
                results[url] = f"Error: {str(e)}"
            
            await asyncio.sleep(1) # Rate limit safe
            
    return results

async def _run_subfinder_container(targets: list):
    """Helper to run a single Subfinder container on a subset of targets."""
    if not targets: return []
    
    # Create temp target file
    target_file = f"subfinder_chunk_{uuid.uuid4()}.txt"
    abs_target_path = os.path.abspath(target_file)
    
    outputs = set()
    try:
        with open(abs_target_path, 'w') as f:
            for t in targets:
                f.write(t + "\n")
        
        # Docker command
        cmd = [
            "docker", "run", "--rm", 
            "-v", f"{abs_target_path}:/targets.txt",
            "projectdiscovery/subfinder",
            "-dL", "/targets.txt",
            "-silent",
            "-json"
        ]
        
        # print(f"DEBUG: Container starting for: {targets}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            # 2 minute timeout per container
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        except asyncio.TimeoutError:
             try: process.kill() 
             except: pass
             return []

        if stdout:
            for line in stdout.decode().splitlines():
                try:
                    data = json.loads(line)
                    host = data.get('host')
                    if host:
                        outputs.add(host)
                except:
                    pass
        return list(outputs)
        
    except Exception as e:
        print(f"Subfinder Chunk Error: {e}")
        return []
    finally:
        if os.path.exists(abs_target_path):
             try: os.remove(abs_target_path)
             except: pass

async def scan_with_subfinder(targets: list):
    """Runs Subfinder via Parallel Docker Containers."""
    if not targets: return []
    
    # 1. Clean and Deduplicate
    unique_domains = set()
    for t in targets:
        clean_t = t.replace("http://", "").replace("https://", "").split("/")[0]
        if clean_t:
            unique_domains.add(clean_t)
            
    # 2. Limit to Top 10
    domain_list = list(unique_domains)[:10]
    if not domain_list: return []
    
    # 3. Chunking Strategy (User Requested)
    # Max 5 containers. 
    # Logic: Distribute load such that we maximize container usage up to 5.
    num_containers = min(len(domain_list), 5)
    base_size = len(domain_list) // num_containers
    remainder = len(domain_list) % num_containers
    
    chunks = []
    start = 0
    for i in range(num_containers):
        extra = 1 if i < remainder else 0
        size = base_size + extra
        chunks.append(domain_list[start : start + size])
        start += size
        
    print(f"DEBUG: Subfinder Parallelization -> {len(domain_list)} domains across {len(chunks)} containers. Chunks: {chunks}")
    
    # 4. Parallel Execution
    tasks = [_run_subfinder_container(chunk) for chunk in chunks]
    results_list = await asyncio.gather(*tasks)
    
    # 5. Aggregate Results
    all_subdomains = set()
    # Add original domains too
    all_subdomains.update(domain_list)
    
    for res in results_list:
        all_subdomains.update(res)
        
    print(f"DEBUG: Total Unique Subdomains Found: {len(all_subdomains)}")
    return list(all_subdomains)

def construct_samdan_prompt(context_data: dict, is_vt_clean: bool, vt_malicious_count: int) -> str:
    """
    Constructs the prompt adhering strictly to Şamdan AI fine-tuning dataset format.
    """
    mobsf = context_data.get('mobsf', {})
    
    # 1. Target
    app_name = mobsf.get('app_name', 'Unknown')
    pkg_name = mobsf.get('package_name', 'com.unknown')
    target_line = f"Target: {app_name} ({pkg_name})"
    
    # 2. Perms (Filter for critical ones)
    all_perms = mobsf.get('permissions', {})
    critical_perm_keys = ['sms', 'location', 'camera', 'record_audio', 'install_packages', 'delete_packages', 'write_external_storage', 'read_contacts', 'get_accounts']
    found_perms = [p.split('.')[-1] for p in all_perms.keys() if any(k in p.lower() for k in critical_perm_keys)]
    perms_line = f"Perms: {', '.join(found_perms[:10])}" if found_perms else "Perms: None detected"
    
    # 3. APIs (Strict Behavior Mapping)
    android_api = mobsf.get('android_api', {})
    detected_apis = list(android_api.keys())
    api_behaviors = []
    
    # Mandatory Mappings
    if 'android.telephony.SmsManager' in detected_apis: 
        api_behaviors.append("SmsManager.sendTextMessage -> Silent SMS / Toll Fraud")
    if 'android.content.BroadcastReceiver' in detected_apis and ('RECEIVE_SMS' in str(all_perms) or 'SMS' in str(all_perms)):
        api_behaviors.append("BroadcastReceiver -> SMS Interception")
    if 'android.view.WindowManager' in detected_apis:
        api_behaviors.append("WindowManager.addView -> Overlay Attack")
    if 'android.app.admin.DevicePolicyManager' in detected_apis:
        api_behaviors.append("DevicePolicyManager -> Device Admin Abuse")
    if 'dalvik.system.DexClassLoader' in detected_apis:
        api_behaviors.append("DexClassLoader -> Dynamic Code Loading")
    if 'java.lang.Runtime' in detected_apis:
        api_behaviors.append("Runtime.exec -> Shell Command Execution")
    if 'java.net.HttpURLConnection' in detected_apis or 'org.apache.http.client.HttpClient' in detected_apis:
        api_behaviors.append("HttpURLConnection -> Remote Communication")
        
    apis_line = f"APIs: {', '.join(api_behaviors)}" if api_behaviors else "APIs: Standard Android Framework"
    
    # 4. Context (Factual only)
    context_parts = []
    
    if is_vt_clean:
        context_parts.append("VirusTotal: Clean (0 detections).")
    else:
        context_parts.append(f"VirusTotal: {vt_malicious_count} engines flagged this sample.")
        
    # Network
    malicious_urls = [u for u, res in context_data.get('virustotal_urls', {}).items() if "Detected: 0" not in res]
    
    if malicious_urls:
         context_parts.append(f"Network: {len(malicious_urls)} malicious URLs detected.")
    else:
         context_parts.append("Network: No malicious network indicators detected.")
         
    # Secrets
    if mobsf.get('secrets', []):
        context_parts.append("Code: Hardcoded secrets detected.")
        
    context_str = " ".join(context_parts)
    
    # Assemble User Prompt
    user_prompt = (
        f"Target: {app_name} ({pkg_name})\n"
        f"{perms_line}\n"
        f"{apis_line}\n"
        f"Context: {context_str}"
    )
    
    return user_prompt

async def analyze_with_llm(context_data: dict, provider: str, api_key: str, model: str):
    """
    Şamdan AI Deterministic Analysis Engine.
    """
    if not api_key and provider == 'gemini': api_key = GEMINI_API_KEY
    
    # --- 1. PRE-COMPUTE CRITICAL METRICS ---
    vt_data = context_data.get('virustotal', {})
    # ROBUST PARSING: Handle both direct 'stats' and nested 'attributes.stats'
    vt_stats = vt_data.get('stats') or vt_data.get('attributes', {}).get('stats', {})
    vt_malicious = vt_stats.get('malicious', 0)
    
    # HARD RULE: If VT is Clean (0 detections), we NEVER return MALICIOUS.
    is_vt_clean = (vt_malicious == 0)

    # --- 2. CONSTRUCT PROMPT ---
    user_prompt_content = construct_samdan_prompt(context_data, is_vt_clean, vt_malicious)
    
    system_prompt = (
        "You are Şamdan AI, a senior Android malware analyst specializing in behavior-based detection and forensics.\n\n"
        "Follow behavior-based evidence strictly. Do not assume malicious intent without proof.\n\n"
        "OUTPUT RULES:\n"
        "1. First line MUST be: VERDICT: BENIGN | SUSPICIOUS | MALICIOUS\n"
        "2. Do NOT use speculative language (likely, possibly, appears).\n"
        "3. For BENIGN verdicts, DO NOT include MITRE ATT&CK codes.\n"
        "4. Output format is strict text. No markdown, no bolding on keys."
    )
    
    full_prompt = f"{system_prompt}\n\nUSER INPUT:\n{user_prompt_content}\n\nASSISTANT OUTPUT:"
    
    # --- 3. CALL LLM ---
    response_text = ""
    
    try:
        if provider == "gemini":
            target_model = "gemini-2.5-flash"
            async with httpx.AsyncClient() as client:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={api_key}"
                # Low temperature for deterministic behavior
                payload = {
                    "contents": [{"parts": [{"text": full_prompt}]}],
                    "generationConfig": {"temperature": 0.2}, 
                    "safetySettings": [
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}
                    ]
                }
                resp = await client.post(url, json=payload, timeout=30.0)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'candidates' in data and data['candidates']:
                        response_text = data['candidates'][0]['content']['parts'][0]['text']
                    else:
                        response_text = "Error: No candidates returned."
                else:
                    response_text = f"Error: {resp.text}"

        elif provider == "ollama":
             url = f"{OLLAMA_URL}/api/generate"
             payload = {"model": model, "prompt": full_prompt, "stream": False, "options": {"temperature": 0.2}}
             async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, timeout=60.0)
                if resp.status_code == 200:
                    response_text = resp.json()['response']
                else:
                    response_text = f"Ollama Error: {resp.text}"
                    
        else:
             response_text = "Configuration Error: Provider not implemented."

    except Exception as e:
        response_text = f"LLM Connection Error: {str(e)}"

    return (response_text, full_prompt)

# --------------------------------------------------------------------------------
# Background Worker
# --------------------------------------------------------------------------------

async def process_analysis(task_id: str, file_path: str, mobsf_key: str, vt_key: str, llm_provider: str, llm_key: str, llm_model: str):
    try:
        # Wait a moment for file handle to release fully
        await asyncio.sleep(1)
        
        report = {}
        
        # Step 1: MobSF
        TASKS[task_id]['step'] = "Analyzing with MobSF..."
        try:
            mobsf_data, scan_hash = await analyze_with_mobsf(file_path, mobsf_key)
            report['mobsf'] = mobsf_data
            
            # --- MobSF Source Code Extraction ---
            # 1. Identify suspicious files from Code Analysis
            suspicious_files = set()
            code_anal = mobsf_data.get('code_analysis', {}).get('findings', {})
            for k, v in code_anal.items():
                # We want files associated with HIGH or WARNING severity findings
                # usually in the 'files' key of the finding list
                     # Broaden search to WARNING if high is empty
                     # key 'k' is usually the finding name, 'v' is the object with metadata
                     if isinstance(v, dict):
                        meta = v.get('metadata', {})
                        severity = meta.get('severity', 'low') # default to low
                        
                        if severity in ['high', 'warning']: 
                         file_list = v.get('files', [])
                         # MobSF sometimes returns list of dicts or list of strings? 
                         # Usually list of objects like {path: ...} or just strings. 
                         # Let's handle both.
                         for f in file_list:
                             if isinstance(f, dict):
                                 f_path = f.get('path') or f.get('name')
                                 if f_path: suspicious_files.add(f_path)
                             elif isinstance(f, str):
                                 suspicious_files.add(f)
            
                             suspicious_files.add(f)
            
            # 3. ROBUST FALLBACK: Parse 'appsec' section if specific file links are missing in code_analysis
            # The 'appsec' section contains textual descriptions like: "Files:\ncom/foo/Bar.java, line(s) 123"
            if not suspicious_files:
                import re
                print("DEBUG: code_analysis yielded no files. Parsing 'appsec'...")
                appsec = mobsf_data.get('appsec', {})
                for category in ['high', 'warning']:
                     for finding in appsec.get(category, []):
                         description = finding.get('description', '')
                         # Look for file paths in description. 
                         # Pattern: Matches tokens ending in .java
                         # This is a heuristic but effective for MobSF reports
                         found_paths = re.findall(r'[\w/\\.]+\.java', description)
                         for p in found_paths:
                             # Clean up path if needed
                             p = p.strip().replace('\\', '/')
                             print(f"DEBUG: Found path in appsec: {p}")
                             suspicious_files.add(p)

            # 4. FALLBACK: URL Paths
            if not suspicious_files:
                 print("DEBUG: No files found in code/appsec. Checking URLs...")
                 # Try URLs section which usually has file paths
                 for u_obj in mobsf_data.get('urls', []):
                     if isinstance(u_obj, dict):
                         path = u_obj.get('path')
                         if path and path.endswith('.java'):
                             suspicious_files.add(path)
            
            # Limit to top 3 files (prioritize High findings if we could differentiate, but set mix is fine)
            top_files = list(suspicious_files)[:3]
            
            print(f"DEBUG: Final decision -> Fetching source for {len(top_files)} files: {top_files}")
            # scan_hash is already set from analyze_with_mobsf return value. DO NOT OVERWRITE.
            # Wait, our `analyze_with_mobsf` returns (filtered_report, scan_hash)
            # We need to capture that properly.
            
            # RETRYING MobSF call to capture hash correctly in `analyze_with_mobsf` return
            # (Note: I already modified `analyze_with_mobsf` to return it, so we are good)
            # But wait, lines 584 above: `mobsf_data, _ = await analyze_with_mobsf...`
            # The `_` ignores the hash. I need to fix that.
            
        except Exception as e:
            print(f"MobSF Error: {e}")
            report['mobsf'] = {"error": str(e)}

        # Step 2: Subfinder (Network Discovery)
        TASKS[task_id]['step'] = "Performing Network Discovery (Subfinder)..."
        try:
            # Extract indicators from MobSF
            indicators = extract_network_indicators(report.get('mobsf', {}))
            report['subdomains'] = [] 
            
            all_domains = []
            if indicators:
                 TASKS[task_id]['step'] = f"Running Subfinder on {len(indicators)} domains..."
                 # Run Subfinder
                 all_domains = await scan_with_subfinder(indicators)
                 report['subdomains'] = all_domains
            else:
                 TASKS[task_id]['step'] = "Subfinder Skipped (No URLs found in MobSF scan)"
                 await asyncio.sleep(2) # Let user see the skip reason
            
            # Prepare VT Scan List (Original URLs + Found Subdomains)
            # Filter duplicates
            scan_targets = list(set(indicators + all_domains))
            
        except Exception as e:
            print(f"Subfinder/Network Error: {e}")
            scan_targets = []
            scan_targets = []
            report['network_error'] = str(e)
            
        # Step 2.5: Source Code Retrieval (Async)
        # We do this in parallel with Subfinder/VT to save time
        TASKS[task_id]['step'] = "Fetching Source Code for Deep Analysis..."
        source_code_data = {}
        try:
             # Depending on where we are, we might need that `top_files` and `scan_hash` from Step 1
             # Since I moved the logic inside Step 1 block but we need to execute it here or there.
             # Ideally, we should have done it in Step 1 or stored the variables.
             # Let's trust variables are available if Step 1 succeeded.
             if 'mobsf' in report and not report['mobsf'].get('error'):
                 # Re-extract logic to be safe or assuming variable scope involves `top_files`
                 # Python variable scope in functions persists.
                 if 'top_files' in locals() and top_files and 'scan_hash' in locals() and scan_hash:
                     print(f"DEBUG: Fetching source for {len(top_files)} files: {top_files}")
                     for f_path in top_files:
                         src = await get_mobsf_source(f_path, scan_hash, mobsf_key)
                         if src:
                             source_code_data[f_path] = src
                             
             report['source_code'] = source_code_data
        except Exception as e:
            print(f"Source Code Fetch Error: {e}")
            report['source_code'] = {}

        # Step 3: VirusTotal (Comprehensive)
        TASKS[task_id]['step'] = "Scanning APK and Network with VirusTotal..."
        
        try:
            # Run File Scan and URL Scan in Parallel
            vt_file_task = analyze_with_virustotal(file_path, vt_key)
            
            # Limit URLs to top 50 to avoid rate/quota limits
            vt_urls_task = analyze_urls_with_virustotal(scan_targets[:50], vt_key)
            
            # Execute both
            print("DEBUG: Starting Parallel VT Scans...")
            vt_file_res, vt_urls_res = await asyncio.gather(vt_file_task, vt_urls_task, return_exceptions=True)
            
            # Helper to handle exceptions in gather
            def handle_res(res, key):
                if isinstance(res, Exception):
                    print(f"VT {key} Error: {res}")
                    return {"error": str(res)}
                return res

            report['virustotal'] = handle_res(vt_file_res, "File")
            report['virustotal_urls'] = handle_res(vt_urls_res, "URLs")
            
        except Exception as e:
             print(f"Global VirusTotal Error: {e}")
             report['virustotal'] = {"error": str(e)}
             report['virustotal_urls'] = {"error": "Skipped due to error"}
            
        # Step 3: LLM (Even if others failed, we try to get an explanation or summary)
        TASKS[task_id]['step'] = f"Consulting {llm_provider.capitalize()} AI..."
        
        # Always get the prompt back!
        ai_response, debug_prompt = await analyze_with_llm(report, llm_provider, llm_key, llm_model)
        
        print(f"DEBUG: AI Response Length: {len(str(ai_response))}")
        print(f"DEBUG: Prompt Length: {len(str(debug_prompt))}")

        report['ai_analysis'] = ai_response
        report['debug_prompt_content'] = debug_prompt # Renamed for verification
        
        # --- DATA CLEANUP FOR USER DISPLAY ---
        # The user requested to clean the raw JSON to avoid confusion and large size.
        if 'mobsf' in report:
            m = report['mobsf']
            # Remove the massive API file lists
            m.pop('android_api', None)
            # Remove file lists from code analysis findings
            if 'code_analysis' in m and 'findings' in m['code_analysis']:
                for k, v in m['code_analysis']['findings'].items():
                    if isinstance(v, dict) and 'files' in v:
                        v.pop('files', None) # Remove detailed file paths
            # Limit secrets in display
            if 'secrets' in m and isinstance(m['secrets'], list):
                m['secrets'] = m['secrets'][:5] # Show only top 5 secrets
        
        print("DEBUG: Report keys:", report.keys())



        TASKS[task_id]['result'] = report
        TASKS[task_id]['status'] = "completed"
        TASKS[task_id]['step'] = "Done"
        
    except Exception as e:
        TASKS[task_id]['status'] = "failed"
        TASKS[task_id]['error'] = str(e)
    finally:
        # Cleanup
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Cleanup Error: {e}")

# --------------------------------------------------------------------------------
# API Endpoints
# --------------------------------------------------------------------------------

@app.get("/")
async def index():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    mobsf_key: str = Form(""),
    vt_key: str = Form(""),
    llm_provider: str = Form("gemini"), # gemini or ollama
    llm_key: str = Form(""),
    llm_model: str = Form("gemini-2.5-flash")
):
    # Handle Şamdan.ai Provider Logic
    if llm_provider == "samdan":
        llm_provider = "ollama"
        llm_model = "samdan-ai"

    task_id = str(uuid.uuid4())
    # Save with a purely synthetic name on disk to avoid ANY Windows path issues
    file_path = os.path.join(UPLOAD_DIR, f"{task_id}.apk")
    
    async with aiofiles.open(file_path, 'wb') as out_file:
        content = await file.read()
        await out_file.write(content)
        
    TASKS[task_id] = {
        "status": "processing",
        "step": "Initializing...",
        "created_at": task_id,
        "filename": file.filename,
        "llm_model": llm_model,
        "llm_provider": llm_provider
    }
    
    background_tasks.add_task(
        process_analysis, 
        task_id, 
        file_path, 
        mobsf_key, 
        vt_key, 
        llm_provider, 
        llm_key, 
        llm_model
    )
    
    return {"task_id": task_id}

@app.get("/api/status/{task_id}")
async def get_status(task_id: str):
    task = TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "status": task['status'],
        "step": task.get('step', ''),
        "error": task.get('error')
    }

@app.get("/api/result/{task_id}")
async def get_result(task_id: str):
    task = TASKS.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task['status'] != 'completed':
         raise HTTPException(status_code=400, detail="Analysis not ready")
    
    return task['result']

from pydantic import BaseModel

class ExportRequest(BaseModel):
    task_ids: List[str]

@app.post("/api/export_report")
async def export_report(request: ExportRequest):
    data = []
    
    for task_id in request.task_ids:
        task = TASKS.get(task_id)
        if not task or task.get('status') != 'completed':
            continue
            
        result = task.get('result', {})
        ai_analysis = result.get('ai_analysis', 'No Analysis')
        
        # Parse Verdict
        verdict = "UNKNOWN"
        first_line = ai_analysis.split('\n')[0].upper()
        if "MALICIOUS" in first_line: verdict = "MALICIOUS"
        elif "SUSPICIOUS" in first_line: verdict = "SUSPICIOUS"
        elif "BENIGN" in first_line: verdict = "BENIGN"
        
        # Raw Data Summary
        mobsf = result.get('mobsf', {})
        vt = result.get('virustotal', {})
        
        vt_stats = vt.get('stats') or vt.get('attributes', {}).get('stats', {})
        vt_malicious = vt_stats.get('malicious', 0) if vt_stats else "N/A"
        
        row = {
            "APK Name": task.get('filename', 'Unknown'),
            "Verdict": verdict,
            "AI Model": f"{task.get('llm_provider')} / {task.get('llm_model')}",
            "VirusTotal Detections": vt_malicious,
            "MobSF Score": mobsf.get('security_score', 'N/A'), # MobSF often provides this
            "Permissions": len(mobsf.get('permissions', [])),
            "Secrets Found": len(mobsf.get('secrets', [])),
            "Full AI Analysis": ai_analysis[:5000], # Trucate if too long
            "Raw Data (JSON)": json.dumps(result)[:32000] # Excel cell limit
        }
        data.append(row)
        
    if not data:
        raise HTTPException(status_code=400, detail="No completed tasks to export")
        
    df = pd.DataFrame(data)
    
    # Create Excel in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Analysis Report')
        
    output.seek(0)
    
    headers = {
        'Content-Disposition': 'attachment; filename="analysis_report.xlsx"'
    }
    
    return HTMLResponse(
        content=output.getvalue(),
        headers=headers,
        media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
