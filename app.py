from flask import Flask, render_template, request, jsonify
from langdetect import detect
from dotenv import load_dotenv
import subprocess
import os
import requests, hashlib
from datetime import datetime
import time
from openai import OpenAI

load_dotenv()

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VT_KEY")  

env = os.environ.copy()
env["DISPLAY"] = os.getenv("DISPLAY", ":0")
env["XAUTHORITY"] = f"/home/{os.getenv('USER')}/.Xauthority"

client = OpenAI(
    api_key=os.getenv("OPENROUTER_API"),
    base_url="https://openrouter.ai/api/v1"
)


def ask_openrouter(prompt):
    try:
        response = client.chat.completions.create(
            model="mistralai/mistral-7b-instruct",
            messages=[
                {"role": "system", "content": "You are a cybersecurity assistant named CyberSentinel."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"OpenRouter Error: {str(e)}"

@app.route('/logs')
def view_logs():
    try:
        with open("logs.txt", "r") as logfile:
            log_content = logfile.read()
    except FileNotFoundError:
        log_content = "No logs available yet."
    return render_template("logs.html", logs=log_content)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    data = request.get_json()
    text = data.get('message', '').lower()
    lang = detect(text)

    response = "Sorry, I didn't understand that command."

    try:
        if "nmap" in text or "and map" in text:
            response = "Running Nmap Scan..."
            subprocess.Popen(["x-terminal-emulator", "-e", "bash", "-c", "nmap -sV 127.0.0.1; exec bash"], env=env)

        elif "firewall" in text:
            response = "Checking firewall status..."
            output = subprocess.getoutput("sudo ufw status")
            response += "\n" + output

        elif "open ports" in text:
            response = "Listing open ports..."
            output = subprocess.getoutput("netstat -tuln")
            response += "\n" + output

        elif "processes" in text or "process" in text:
            response = "Listing running processes..."
            output = subprocess.getoutput("ps aux | head -10")
            response += "\n" + output

        elif "permissions" in text or "permission" in text:
            response = "Checking file permissions in home..."
            output = subprocess.getoutput("ls -l ~ | head -10")
            response += "\n" + output

        elif "wireshark" in text or "wire shark" in text:
            response = "Launching Wireshark..."
            subprocess.Popen(["wireshark"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif "scan for vulnerabilities" in text or "scan for vulnerability" in text:
            response = "Scanning for vulnerabilities with Nmap..."
            output = subprocess.getoutput("nmap --script vuln 127.0.0.1")
            response += "\n" + output

        elif "hydra" in text:
            response = "Starting Hydra brute force attack on FTP (simulated)..."
            subprocess.Popen(["gnome-terminal", "--", "bash", "-c", "hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 ftp; exec bash"], env=env)

        elif "connected" in text or "who is connected" in text:
            response = "Scanning for connected devices..."
            output = subprocess.getoutput("arp -a")
            response += "\n" + output

        elif "system logs" in text:
            response = "Checking recent system logs..."
            output = subprocess.getoutput("journalctl -n 10")
            response += "\n" + output

        elif "monitor traffic" in text:
            response = "Starting live network monitor using iftop..."
            subprocess.Popen(["gnome-terminal", "--", "bash", "-c", "sudo iftop; exec bash"], env=env)

        elif "open youtube" in text:
            response = "Opening YouTube..."
            subprocess.Popen(["xdg-open", "https://www.youtube.com"])

        elif "search in youtube" in text or "in youtube" in text:
            query = text.split("search youtube for")[-1].strip().replace(" ", "+")
            response = f"Searching YouTube for {query}..."
            subprocess.Popen(["xdg-open", f"https://www.youtube.com/search?q={query}"])

        elif "open chrome" in text or "open google" in text:
            response = "Opening Chrome..."
            subprocess.Popen(["google-chrome"])

        elif "search" in text:
            query = text.split("search google for")[-1].strip().replace(" ", "+")
            response = f"Searching Google for {query}..."
            subprocess.Popen(["xdg-open", f"https://www.google.com/search?q={query}"])

        elif "what time" in text:
            now = datetime.now().strftime("%I:%M %p")
            response = f"The current time is {now}."

        else :
            response = ask_openrouter(text)

    except Exception as e:
        response = f"Command error: {str(e)}"

    print(f"Command received: {text}")

    with open("logs.txt", "a") as logfile:
        logfile.write(f"User: {text}\nCyberSentinel: {response}\n\n")

    return jsonify({'response': response})


@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'result': 'No file uploaded.'})

    file = request.files['file']
    file_bytes = file.read()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    file_url = f'https://www.virustotal.com/api/v3/files/{sha256}'
    response = requests.get(file_url, headers=headers)

    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        if malicious > 0:
            return jsonify({'result': f"⚠️ File is malicious (detected by {malicious} engines)."})
        else:
            return jsonify({'result': "✅ File is clean (no malicious engines found)."})
    else:
        upload_url = 'https://www.virustotal.com/api/v3/files'
        upload_response = requests.post(upload_url, files={'file': (file.filename, file_bytes)}, headers=headers)

        if upload_response.status_code == 200:
            file_id = upload_response.json()['data']['id']
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'

            for i in range(18):  
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_data = analysis_response.json()

                if analysis_data['data']['attributes']['status'] == 'completed':
                    stats = analysis_data['data']['attributes']['stats']
                    malicious = stats.get('malicious', 0)
                    if malicious > 0:
                        return jsonify({'result': f"⚠️ File is malicious (detected by {malicious} engines)."})
                    else:
                        return jsonify({'result': "✅ File is clean (no malicious engines found)."})
                time.sleep(1.5)  

            return jsonify({'result': "⏳ Scan is still in progress. Try again in a few seconds."})
        else:
            return jsonify({'result': "❌ Failed to upload the file for scanning."})

if __name__ == '__main__':
    app.run(debug=True)
