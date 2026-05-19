import requests
import json
import re

def analyze_code(code, user_api_key):
    """Main function — runs all 5 checks and returns trust report"""
    
    results = {
        "trust_score": 0,
        "packages": check_packages(code, user_api_key),
        "explanation": explain_code(code, user_api_key),
        "risks": find_risks(code, user_api_key),
        "logic": verify_logic(code, user_api_key),
        "summary": ""
    }
    
    # Calculate trust score
    results["trust_score"] = calculate_score(results)
    results["summary"] = generate_summary(results, code, user_api_key)
    
    return results

def call_groq(prompt, api_key, max_tokens=1000):
    """Call Groq API with user's own key"""
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens
            },
            timeout=30
        )
        data = r.json()
        if "choices" not in data:
            return None
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return None

def extract_packages(code):
    """Extract all imported packages from code"""
    packages = set()
    
    # Match: import x, import x as y
    for match in re.findall(r'^import\s+([\w]+)', code, re.MULTILINE):
        packages.add(match)
    
    # Match: from x import y
    for match in re.findall(r'^from\s+([\w]+)', code, re.MULTILINE):
        packages.add(match)
    
    # Remove stdlib packages
    stdlib = {
        "os", "sys", "re", "json", "time", "datetime", "math",
        "random", "string", "hashlib", "hmac", "base64", "urllib",
        "http", "socket", "threading", "subprocess", "pathlib",
        "shutil", "glob", "io", "csv", "sqlite3", "pickle",
        "collections", "itertools", "functools", "typing",
        "logging", "traceback", "argparse", "getpass", "struct",
        "array", "queue", "heapq", "copy", "pprint", "textwrap",
        "difflib", "zipfile", "tarfile", "gzip", "email", "html",
        "xml", "unittest", "platform", "signal", "weakref", "abc",
        "enum", "dataclasses", "contextlib", "warnings", "inspect",
        "ast", "dis", "builtins", "secrets", "statistics", "decimal",
        "fractions", "uuid", "ipaddress", "calendar", "locale"
    }
    
    return [p for p in packages if p not in stdlib]

def check_package_on_pypi(package):
    """Check if package exists on PyPI"""
    try:
        r = requests.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            info = data.get("info", {})
            return {
                "exists": True,
                "name": info.get("name", package),
                "version": info.get("version", "unknown"),
                "author": info.get("author", "unknown"),
                "downloads": "available",
                "safe": True
            }
        return {"exists": False, "name": package, "safe": False}
    except:
        return {"exists": None, "name": package, "safe": None}

def check_packages(code, api_key):
    """Check 1 — Package Scanner"""
    packages = extract_packages(code)
    
    if not packages:
        return {
            "status": "clean",
            "message": "No external packages used — stdlib only",
            "packages": [],
            "score": 25
        }
    
    results = []
    all_safe = True
    
    for pkg in packages[:10]:  # Limit to 10 packages
        pypi_result = check_package_on_pypi(pkg)
        
        if not pypi_result["exists"]:
            all_safe = False
            results.append({
                "name": pkg,
                "status": "danger",
                "message": f"⚠️ '{pkg}' not found on PyPI — possible hallucinated package!",
                "icon": "❌"
            })
        else:
            results.append({
                "name": pkg,
                "status": "safe",
                "message": f"✅ '{pkg}' v{pypi_result['version']} — verified on PyPI",
                "icon": "✅"
            })
    
    score = 25 if all_safe else max(5, 25 - (len([r for r in results if r["status"] == "danger"]) * 8))
    
    return {
        "status": "safe" if all_safe else "warning",
        "message": f"Found {len(packages)} external package(s)",
        "packages": results,
        "score": score
    }

def explain_code(code, api_key):
    """Check 2 — Plain English Explanation"""
    prompt = f"""Explain this code in simple plain English.
Be concise. Use bullet points. Max 5 points.
Focus on WHAT it does, not HOW.

Code:
{code[:3000]}

Return only the bullet points, nothing else."""

    result = call_groq(prompt, api_key, max_tokens=400)
    
    return {
        "explanation": result or "Could not generate explanation.",
        "score": 20 if result else 10
    }

def find_risks(code, api_key):
    """Check 3 — Risk Detector"""
    prompt = f"""Analyze this code for security risks and bugs.
Be specific and concise.


You are a strict security auditor. Only report CONFIRMED issues, not theoretical ones.

ONLY flag something if you are 100% certain it is a real vulnerability in THIS specific code.

Rules:
- Do NOT flag missing features or potential improvements
- Do NOT flag things that MIGHT be an issue
- ONLY flag hardcoded passwords/keys/tokens you can actually see in the code
- ONLY flag eval() or exec() if they actually appear in the code
- ONLY flag SQL injection if raw string formatting into SQL is actually present
- If code looks clean, say so — do NOT invent issues

Be conservative. False positives destroy trust.
Code:
{code[:3000]}

Return a JSON object like this:
{{
    "risk_level": "low/medium/high",
    "risks": ["risk 1", "risk 2"],
    "safe_practices": ["good thing 1", "good thing 2"]
}}

Return ONLY the JSON, nothing else."""

    result = call_groq(prompt, api_key, max_tokens=500)
    
    try:
        start = result.find("{")
        end = result.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(result[start:end])
            risk_level = data.get("risk_level", "medium")
            score = {"low": 25, "medium": 15, "high": 5}.get(risk_level, 10)
            return {
                "risk_level": risk_level,
                "risks": data.get("risks", []),
                "safe_practices": data.get("safe_practices", []),
                "score": score
            }
    except:
        pass
    
    return {
        "risk_level": "unknown",
        "risks": ["Could not analyze risks"],
        "safe_practices": [],
        "score": 10
    }

def verify_logic(code, api_key):
    """Check 4 — Logic Verifier"""
    prompt = f"""Verify the logic of this code.
Check if the code actually does what it appears to do.

You are a strict code reviewer. Only report CONFIRMED logic errors you can prove.

Rules:
- Only flag errors you can trace through the code step by step
- Do NOT flag missing error handling as a logic error
- Do NOT flag style issues
- Do NOT flag things that MIGHT fail — only things that WILL fail
- If logic looks correct, say so honestly

Be conservative. Only real confirmed bugs.
Code:
{code[:3000]}

Return a JSON object:
{{
    "logic_sound": true/false,
    "issues": ["issue 1", "issue 2"],
    "confidence": "high/medium/low"
}}

Return ONLY the JSON."""

    result = call_groq(prompt, api_key, max_tokens=400)
    
    try:
        start = result.find("{")
        end = result.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(result[start:end])
            logic_sound = data.get("logic_sound", False)
            confidence = data.get("confidence", "low")
            score = 20 if logic_sound else 8
            if confidence == "low":
                score = max(5, score - 5)
            return {
                "logic_sound": logic_sound,
                "issues": data.get("issues", []),
                "confidence": confidence,
                "score": score
            }
    except:
        pass
    
    return {
        "logic_sound": None,
        "issues": ["Could not verify logic"],
        "confidence": "low",
        "score": 5
    }

def calculate_score(results):
    """Calculate final trust score 0-100"""
    score = (
        results["packages"]["score"] +
        results["explanation"]["score"] +
        results["risks"]["score"] +
        results["logic"]["score"]
    )
    return min(100, max(0, score))

def generate_summary(results, code, api_key):
    """Generate one line summary"""
    score = results["trust_score"]
    risk = results["risks"]["risk_level"]
    logic = results["logic"]["logic_sound"]
    
    if score >= 80:
        return "This code looks safe and well-written. Good to use."
    elif score >= 60:
        return "This code is mostly safe but has some issues worth reviewing."
    elif score >= 40:
        return "This code has significant issues. Review carefully before using."
    else:
        return "This code is risky. Do not use without major review."
