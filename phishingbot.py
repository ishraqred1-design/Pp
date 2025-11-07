# phishguard_bot.py
# Developed by Ajfar Fatin Ishraq and optimized by Gemini.
#
# PhishGuardBot: A Telegram bot for asynchronous URL scanning against
# multiple threat intelligence sources, using in-memory session history.

import asyncio
import re
import base64
import json # Used for structuring the history log details
from urllib.parse import urlparse, urlunparse
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List

from aiogram import Bot, Dispatcher, types, executor
from aiogram.utils.markdown import hbold, hlink, code
import aiohttp
import validators

# --- Configuration (CRITICAL: Replace with your actual tokens/keys) ---
# IMPORTANT: Never commit actual secrets to public repositories.
BOT_TOKEN = "8221951015:AAG__jsAKNNYBgRjBiH3hQGltG7Al5VEmDQ"
VIRUSTOTAL_API_KEY = "81908d5ee58802d9905557037ccdbfde46b3099860065b8bedc19538f7ff8d5e"
# --- API Endpoints ---
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

# --- Global State for Session History (Replaces SQLite for this version) ---
SCAN_HISTORY: List[Dict[str, Any]] = []
MAX_HISTORY_SIZE = 8 # Cap the history to the last 8 scans

# --- Risk Scoring Weights (Total must be 100) ---
WEIGHT_VIRUSTOTAL = 45
WEIGHT_URLHAUS = 40
WEIGHT_HEURISTICS = 15

# --- Utility Functions ---

def get_sanitized_link_id(url: str) -> str:
    """
    Creates a standardized and URL-safe ID for VirusTotal API lookups.
    VT uses the base64-encoded URL (without padding).
    """
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    # Ensure the URL is consistently formatted (e.g., removing fragment/trailing slashes)
    parsed = urlparse(url)
    clean_url = urlunparse(parsed._replace(fragment='', query=''))
    
    # Base64 encode the clean URL and remove padding (=)
    url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
    return url_id

def perform_heuristic_analysis(url: str) -> Tuple[int, str]:
    """Performs internal heuristic checks on the URL structure."""
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    heuristic_score = 0
    flags = []

    # 1. Keywords in Path/Domain (e.g., used to trick users)
    phishy_keywords = ["login", "secure", "verify", "update", "account", "paypal", "bank"]
    for keyword in phishy_keywords:
        if keyword in domain or keyword in path:
            heuristic_score += 15
            flags.append(f"Keyword in path/domain: '{keyword}'")
            break # Only score once for keywords

    # 2. Excessive Hyphens (used to obscure domain name)
    hyphen_count = domain.count('-')
    if hyphen_count > 3:
        heuristic_score += 20
        flags.append(f"Excessive hyphens ({hyphen_count})")

    # 3. IP Address in Domain (often malicious/temporary infrastructure)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        heuristic_score += 25
        flags.append("Domain is an IP address")

    # 4. Long Subdomains (subdomain stuffing)
    # Check for excessive dots which indicates many subdomains
    if domain.count('.') > 4:
        heuristic_score += 10
        flags.append(f"Long domain chain ({domain.count('.') - 1} subdomains)")

    # Normalize score to 100 max
    final_score = min(heuristic_score, 100)
    details = ", ".join(flags) if flags else "No specific issues found."
    
    return final_score, details

def log_to_history(scan_data: Dict[str, Any]):
    """Adds scan result to the in-memory history list, enforcing the cap."""
    SCAN_HISTORY.append(scan_data)
    # Maintain a fixed size by trimming the oldest entries
    if len(SCAN_HISTORY) > MAX_HISTORY_SIZE:
        SCAN_HISTORY.pop(0)

# --- Threat Intelligence Class (Handles Async API Calls) ---

class ThreatIntelligence:
    """Manages asynchronous calls to external threat intelligence APIs."""
    
    def __init__(self, vt_api_key: str):
        self.vt_api_key = vt_api_key

    async def _handle_request(self, session: aiohttp.ClientSession, method: str, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Generic handler for resilient API requests with error handling."""
        try:
            async with session.request(method, url, timeout=15, **kwargs) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status in (404, 400):
                    # 404/400 often means "not found" or bad input, not a server error
                    return {"status_code": response.status}
                else:
                    print(f"API Error: {url} returned status {response.status}")
                    return None
        except aiohttp.ClientError as e:
            print(f"Connection Error to {url}: {e}")
            return None
        except asyncio.TimeoutError:
            print(f"Timeout Error: Request to {url} timed out.")
            return None

    async def check_urlhaus(self, session: aiohttp.ClientSession, url: str) -> Tuple[int, str]:
        """Checks the URL against the URLhaus database."""
        data = {"url": url}
        result = await self._handle_request(session, "POST", URLHAUS_API_URL, data=data)

        if not result or result.get("status_code") in (404, 400):
            return 0, "URLhaus: Link not found in database."

        query_status = result.get("query_status", "not_found")
        
        if query_status == "ok":
            status = result.get("url_status", "unknown")
            if status in ["online", "offline"]:
                # URLhaus marks 'online' or 'offline' as known malicious
                return 100, f"LISTED! Status: {status.upper()} (malware/phishing)"
        
        return 0, f"URLhaus: {query_status.replace('_', ' ').title()}"

    async def check_virustotal(self, session: aiohttp.ClientSession, url: str) -> Tuple[int, str]:
        """Checks the URL against VirusTotal using the URL ID lookup."""
        url_id = get_sanitized_link_id(url)
        vt_url = f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}"
        headers = {"x-apikey": self.vt_api_key, "accept": "application/json"}
        
        result = await self._handle_request(session, "GET", vt_url, headers=headers)
        
        if not result:
            return 0, "VirusTotal: API check failed (connection/timeout)."
        
        if result.get("status_code") == 404:
            return 0, "VirusTotal: Link not found in recent scans."
            
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        # Extract the detailed malicious count
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        total_scans = sum(last_analysis_stats.values())
        
        if total_scans == 0:
             return 0, "VirusTotal: No analysis data available."

        # Calculate score: proportional to the number of malicious vendors
        score_percent = round((malicious_count / total_scans) * 100)
        
        if malicious_count > 0:
            details = f"Detected by {malicious_count}/{total_scans} vendors."
        else:
            details = f"No malicious detection out of {total_scans} vendors."
            
        return score_percent, details

# --- Risk Scoring Logic ---

def calculate_risk_score(vt_score: int, hu_score: int, heuristic_score: int) -> Tuple[int, str]:
    """Calculates the final weighted risk score and determines the verdict."""
    
    # Apply weights
    weighted_score = (
        (vt_score * WEIGHT_VIRUSTOTAL / 100) +
        (hu_score * WEIGHT_URLHAUS / 100) +
        (heuristic_score * WEIGHT_HEURISTICS / 100)
    )
    final_score = int(round(weighted_score))
    
    # Determine verdict based on score
    if final_score >= 50:
        verdict = "🔴 Dangerous"
        color_code = "red"
    elif final_score >= 20:
        verdict = "🟡 Suspicious"
        color_code = "orange"
    else:
        verdict = "🟢 Safe"
        color_code = "green"
        
    return final_score, verdict, color_code

# --- Aiogram Bot Setup ---

# Initialize bot and dispatcher
bot = Bot(token=BOT_TOKEN, parse_mode=types.ParseMode.HTML)
dp = Dispatcher(bot)

# Initialize the intelligence manager
threat_intel = ThreatIntelligence(vt_api_key=VIRUSTOTAL_API_KEY)

# --- Telegram Handlers ---

@dp.message_handler(commands=['start', 'help'])
async def send_welcome(message: types.Message):
    """Handles /start and /help commands."""
    
    ATTRIBUTION = "Developed By Ajfar Fatin Ishraq ©️" 

    help_text = (
        f"{hbold('👋 Welcome to PhishGuardBot!')}\n\n"
        f"{ATTRIBUTION}\n\n"
        "I am here to help you detect phishing and malicious links.\n"
        "I consult multiple threat intelligence sources (URLhaus, VirusTotal) "
        "and perform heuristic analysis to give you a clear risk verdict.\n\n"
        f"{hbold('Commands:')}\n"
        "/scan <link> - Scan a link for threats (e.g., "
        f"{code('/scan https://google.com')})\n"
        f"/summary - Show the last {MAX_HISTORY_SIZE} scans from this session.\n"
        f"/file - (Coming soon) Upload a file for malware analysis.\n\n"
        "Stay safe!"
    )
    await message.reply(help_text)

@dp.message_handler(commands=['scan'])
async def handle_scan(message: types.Message):
    """Handles the /scan command, orchestrating the full analysis."""
    
    args = message.get_args().strip()
    
    if not args:
        return await message.reply(
            "Please provide a link to scan. Usage: "
            f"{code('/scan <link>')}"
        )
    
    target_url = args.split()[0]
    
    # 1. Input Validation
    if not validators.url(target_url):
        return await message.reply("❌ Invalid URL format detected. Please check the link and try again.")
    
    # 2. Initial Feedback
    progress_msg = await message.reply(
        f"⏳ {hbold('Scanning link...')} Consulting security sources (VT, URLhaus, Heuristics)."
    )
    
    # 3. Asynchronous Execution and Data Gathering
    vt_res, hu_res = (0, "Check failed"), (0, "Check failed")
    try:
        async with aiohttp.ClientSession() as session:
            # Run all external checks concurrently for speed
            vt_task = threat_intel.check_virustotal(session, target_url)
            hu_task = threat_intel.check_urlhaus(session, target_url)
            
            vt_res, hu_res = await asyncio.gather(vt_task, hu_task)
            
            vt_score, vt_details = vt_res
            hu_score, hu_details = hu_res
            
    except Exception as e:
        await bot.edit_message_text(
            chat_id=message.chat.id, 
            message_id=progress_msg.message_id, 
            text=f"🚨 An unexpected error occurred during API calls: {type(e).__name__}"
        )
        return

    # 4. Internal Heuristics
    heuristic_score, heuristic_details = perform_heuristic_analysis(target_url)

    # 5. Risk Calculation
    final_score, verdict, color_code = calculate_risk_score(vt_score, hu_score, heuristic_score)

    # 6. Logging to In-Memory History
    scan_data = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "url": target_url,
        "score": final_score,
        "verdict": verdict.split()[1], # Just the text part (Safe, Suspicious, Dangerous)
        "vt_score": vt_score,
        "hu_score": hu_score,
        "heuristic_score": heuristic_score,
        "details": f"VT: {vt_details} | HU: {hu_details} | Heuristics: {heuristic_details}"
    }
    log_to_history(scan_data)

    # 7. Final User Output
    output = (
        f"{hbold('🛡️ PhishGuardBot Scan Result 🛡️')}\n\n"
        f"🔗 {hlink('Scanned Link', target_url)}\n"
        f"📝 {hbold('Verdict:')} <b style=\"color:{color_code};\">{verdict}</b>\n"
        f"📊 {hbold('Risk Score:')} {final_score}/100\n\n"
        f"{hbold('--- Detailed Breakdown ---')}\n"
        
        f"🦠 {hbold('VirusTotal Score (Weight 45%):')} {vt_score}%\n"
        f"   - {vt_details}\n"
        
        f"🏚️ {hbold('URLhaus Status (Weight 40%):')} {hu_score}%\n"
        f"   - {hu_details}\n"
        
        f"🧠 {hbold('Heuristic Score (Weight 15%):')} {heuristic_score}%\n"
        f"   - {heuristic_details}\n"
    )
    
    await bot.edit_message_text(
        chat_id=message.chat.id, 
        message_id=progress_msg.message_id, 
        text=output,
        disable_web_page_preview=True # Prevent Telegram from trying to load the link preview
    )

@dp.message_handler(commands=['summary'])
async def handle_summary(message: types.Message):
    """Shows a summary of the most recent scans in the current session."""
    
    if not SCAN_HISTORY:
        return await message.reply("There are no scans recorded yet in this session. Use /scan <link> to start!")

    summary_text = f"{hbold('📊 Recent Scan Summary (Last {len(SCAN_HISTORY)} Scans) 📊')}\n"
    
    # Reverse the list to show the most recent scans first
    for i, scan in enumerate(reversed(SCAN_HISTORY)):
        # Determine color for summary verdict
        color_code = "green"
        if scan['verdict'] == 'Dangerous': color_code = "red"
        elif scan['verdict'] == 'Suspicious': color_code = "orange"
        
        # Format the URL for display (show just the start and end)
        url_display = scan['url']
        if len(url_display) > 50:
            url_display = url_display[:30] + "..." + url_display[-15:]

        summary_text += (
            f"\n\n{hbold(i + 1)}. [{scan['timestamp']}]\n"
            f"   🔗 {url_display}\n"
            f"   📝 {hbold('Verdict:')} <b style=\"color:{color_code};\">{scan['verdict']}</b> | 📊 {hbold('Score:')} {scan['score']}"
        )
    
    summary_text += f"\n\n\nNote: This history is {hbold('in-memory')} and will be lost when the bot restarts. Max history size: {MAX_HISTORY_SIZE}."

    await message.reply(summary_text, disable_web_page_preview=True)


# --- Main Execution ---

if __name__ == '__main__':
    print("Initializing PhishGuardBot...")
    
    if BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        print("\nFATAL ERROR: BOT_TOKEN is not configured. Please set your Telegram Bot token before running.\n")
    elif VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("\nFATAL ERROR: VIRUSTOTAL_API_KEY is not configured. Please set your VirusTotal API key before running.\n")
    else:
        print("Bot running. Press Ctrl+C to stop.")
        # aiogram executor handles the main async loop
        try:
            executor.start_polling(dp, skip_updates=True)
        except Exception as e:
            # Catches connection errors like bad token or network issues that occur during polling
            print(f"\nFATAL RUNTIME ERROR during polling (likely bad token or network issue): {e}\n")