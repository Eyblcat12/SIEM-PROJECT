import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from fpdf import FPDF
import os
import sys
from datetime import datetime
from config import DATA_PATH, BASE_DIR

# --- FIX LỖI ENCODING TRÊN WINDOWS (CHO TERMINAL) ---
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

# --- CẤU HÌNH ĐƯỜNG DẪN ---
REPORT_DIR = BASE_DIR.parent / 'reports'
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# --- MÀU SẮC ---
COLOR_PRIMARY = (41, 128, 185)
COLOR_SECONDARY = (52, 73, 94)
COLOR_DANGER = (231, 76, 60)
COLOR_WARNING = (243, 156, 18)
COLOR_SUCCESS = (39, 174, 96)
COLOR_INFO = (52, 152, 219)

def clean_text(text):
    """Hàm làm sạch text: Loại bỏ ký tự không phải latin-1 để tránh lỗi PDF"""
    if not isinstance(text, str):
        return str(text)
    # Thay thế các ký tự lạ bằng '?'
    return text.encode('latin-1', 'replace').decode('latin-1')

class UltimatePDFReport(FPDF):
    def header(self):
        self.set_fill_color(*COLOR_PRIMARY)
        self.rect(10, 10, 10, 10, 'F')
        self.set_font('Arial', 'B', 16)
        self.set_text_color(*COLOR_SECONDARY)
        self.cell(15)
        self.cell(0, 10, 'SIEM AI SECURITY REPORT', 0, 0, 'L')
        self.set_draw_color(*COLOR_PRIMARY)
        self.set_line_width(0.5)
        self.line(10, 25, 200, 25)
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cell(0, 10, f'Generated on {timestamp} | Page {self.page_no()}', 0, 0, 'C')

    def section_title(self, title):
        # Bỏ icon emoji trong title để tránh lỗi
        self.ln(5)
        self.set_font('Arial', 'B', 14)
        self.set_text_color(*COLOR_PRIMARY)
        self.set_fill_color(240, 248, 255)
        # Clean text trước khi in
        self.cell(0, 10, f"  {clean_text(title)}", 0, 1, 'L', 1)
        self.ln(2)
        self.set_text_color(0)

    def body_text(self, text, style='', size=10):
        self.set_font('Arial', style, size)
        self.multi_cell(0, 6, clean_text(text))
        self.ln(2)

    def info_box(self, label, value):
        self.set_font('Arial', 'B', 10)
        self.cell(50, 6, clean_text(label), 0, 0)
        self.set_font('Arial', '', 10)
        self.cell(0, 6, clean_text(str(value)), 0, 1)

    def risk_badge(self, level):
        level = int(level)
        if level >= 14:
            self.set_fill_color(*COLOR_DANGER); text = "CRITICAL"
        elif level >= 10:
            self.set_fill_color(*COLOR_WARNING); text = "HIGH"
        elif level >= 7:
            self.set_fill_color(*COLOR_WARNING); text = "MEDIUM"
        elif level >= 4:
            self.set_fill_color(*COLOR_SUCCESS); text = "LOW"
        else:
            self.set_fill_color(*COLOR_INFO); text = "INFO"
            
        self.set_text_color(255)
        self.set_font('Arial', 'B', 8)
        self.cell(20, 6, text, 0, 0, 'C', 1)
        self.set_text_color(0)

def generate_timeline_chart(df):
    """Vẽ biểu đồ Timeline"""
    plt.style.use('ggplot')
    plt.figure(figsize=(10, 4))
    
    if 'timestamp' in df.columns:
        df['dt'] = pd.to_datetime(df['timestamp'], errors='coerce')
        timeline = df.groupby(df['dt'].dt.hour)['rule.level'].count()
        plt.plot(timeline.index, timeline.values, marker='o', linestyle='-', color='#2980b9', label='Total Events')
        
        if 'is_threat' in df.columns:
            threats = df[df['is_threat'] == 1]
            if not threats.empty:
                threat_timeline = threats.groupby(threats['dt'].dt.hour)['rule.level'].count()
                plt.bar(threat_timeline.index, threat_timeline.values, color='#e74c3c', alpha=0.5, label='Threats')

        plt.title('Security Events Timeline (Last 24h)')
        plt.xlabel('Hour of Day')
        plt.ylabel('Event Count')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        
        chart_path = REPORT_DIR / 'chart_timeline.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        return str(chart_path)
    return None

def generate_threat_actor_table(pdf, df):
    """Tạo bảng Top Threat Actors"""
    if 'data.win.eventdata.image' not in df.columns:
        pdf.body_text("No process image data available.")
        return

    threats = df[df.get('is_threat', 0) == 1]
    if threats.empty:
        pdf.body_text("No active threats detected.")
        return

    top_actors = threats['data.win.eventdata.image'].value_counts().head(5)
    
    pdf.set_font('Arial', 'B', 9)
    pdf.set_fill_color(230, 230, 230)
    
    # Header
    pdf.cell(100, 8, 'Process / Executable', 1, 0, 'L', 1)
    pdf.cell(20, 8, 'Count', 1, 0, 'C', 1)
    pdf.cell(30, 8, 'Avg Level', 1, 0, 'C', 1)
    pdf.cell(40, 8, 'Severity', 1, 1, 'C', 1)
    
    pdf.set_font('Arial', '', 9)
    for proc_name, count in top_actors.items():
        avg_lvl = threats[threats['data.win.eventdata.image'] == proc_name]['rule.level'].mean()
        
        # Clean text trước khi in vào ô
        clean_proc = clean_text(str(proc_name))[-55:]
        
        pdf.cell(100, 8, clean_proc, 1, 0, 'L')
        pdf.cell(20, 8, str(count), 1, 0, 'C')
        pdf.cell(30, 8, f"{avg_lvl:.1f}", 1, 0, 'C')
        pdf.risk_badge(avg_lvl)
        pdf.ln()

def generate_narrative(df):
    threats = df[df.get('is_threat', 0) == 1]
    if threats.empty:
        return "Analysis indicates no significant security incidents during this period. System appears healthy."
    
    top_threat = threats.sort_values('rule.level', ascending=False).iloc[0]
    
    timestamp = str(top_threat.get('timestamp', 'unknown time'))
    agent = str(top_threat.get('agent.name', 'unknown host'))
    level = top_threat.get('rule.level', 0)
    rule_desc = str(top_threat.get('rule.description', 'suspicious activity'))
    process = str(top_threat.get('data.win.eventdata.image', 'unknown process'))
    cmd = str(top_threat.get('data.win.eventdata.commandLine', ''))
    
    narrative = (
        f"At {timestamp}, the agent '{agent}' generated a high-severity alert (Level {level}). "
        f"The system detected '{rule_desc}'. "
    )
    
    if process != 'nan' and process != 'unknown process':
        narrative += f"Investigation reveals that process '{process}' was involved. "
        
    if cmd and cmd != 'nan':
        narrative += f"The command line executed was: '{cmd[:100]}...' "
        
    if 'powershell' in process.lower() or 'cmd' in process.lower():
        narrative += "This usage of system administration tools is indicative of 'Living off the Land' (LotL) tactics. "
        
    if level >= 12:
        narrative += "This is considered a CRITICAL incident requiring immediate containment."
    
    return narrative

def create_pro_report():
    # Dùng ký tự ASCII thường cho log terminal
    print(f"[INFO] Generating Professional Report from: {DATA_PATH}")
    
    if not DATA_PATH.exists():
        print("[ERROR] Data file not found.")
        return

    try:
        df = pd.read_csv(DATA_PATH)
        if 'is_threat' not in df.columns:
             if 'rule.level' in df.columns:
                df['is_threat'] = df['rule.level'].apply(lambda x: 1 if x >= 10 else 0)
             else:
                df['is_threat'] = 0
    except Exception as e:
        print(f"[ERROR] Read CSV failed: {e}")
        return

    pdf = UltimatePDFReport()
    pdf.add_page()

    # 1. SYSTEM METADATA
    # Bỏ icon emoji khi gọi hàm
    pdf.section_title("1. System Metadata") 
    pdf.info_box("Report ID:", f"RPT-{datetime.now().strftime('%Y%m%d-%H%M')}")
    pdf.info_box("Target Environment:", "Wazuh Lab (Production)")
    pdf.info_box("Total Agents:", f"{df['agent.name'].nunique()} Active Agents")
    pdf.info_box("Log Volume:", f"{len(df)} events processed")
    pdf.info_box("Detection Engine:", "AI Engine v3.0 (XGBoost + NLP)")
    pdf.ln(5)

    # 2. EXECUTIVE SUMMARY & NARRATIVE
    pdf.section_title("2. Incident Narrative & Analysis")
    narrative_text = generate_narrative(df)
    pdf.body_text(narrative_text)
    pdf.ln(5)

    # 3. VISUAL ANALYSIS (TIMELINE)
    pdf.section_title("3. Threat Timeline")
    print("[INFO] Drawing charts...")
    try:
        timeline_img = generate_timeline_chart(df)
        if timeline_img:
            pdf.image(timeline_img, x=10, w=190)
            os.remove(timeline_img)
    except Exception as e:
        print(f"[WARN] Chart error: {e}")
    pdf.ln(5)

    # 4. THREAT ACTORS TABLE
    pdf.section_title("4. Top Threat Processes")
    generate_threat_actor_table(pdf, df)
    pdf.ln(10)

    # 5. MITRE ATT&CK MAPPING
    pdf.section_title("5. MITRE ATT&CK Matrix")
    pdf.set_font('Arial', 'B', 9)
    pdf.cell(40, 8, 'Tactic', 1, 0, 'C', 1)
    pdf.cell(40, 8, 'Technique ID', 1, 0, 'C', 1)
    pdf.cell(110, 8, 'Description', 1, 1, 'C', 1)
    
    pdf.set_font('Arial', '', 9)
    mitre_data = [
        ('Execution', 'T1059.001', 'PowerShell Usage'),
        ('Persistence', 'T1078', 'Valid Accounts'),
        ('Defense Evasion', 'T1027', 'Obfuscated Files')
    ]
    for tactic, tid, desc in mitre_data:
        pdf.cell(40, 8, tactic, 1)
        pdf.cell(40, 8, tid, 1)
        pdf.cell(110, 8, desc, 1)
        pdf.ln()
    
    # APPENDIX
    pdf.add_page()
    pdf.section_title("Appendix A: Raw Log Samples")
    
    threats = df[df['is_threat'] == 1].head(10)
    if not threats.empty:
        pdf.set_font('Courier', '', 8)
        for _, row in threats.iterrows():
            # Clean text trước khi in log
            log_text = str(row.get('full_text', ''))[:80]
            log_line = f"[{row.get('timestamp')}] {row.get('agent.name')} | Lvl:{row.get('rule.level')} | {log_text}..."
            # Dùng clean_text bọc ngoài
            pdf.multi_cell(0, 5, clean_text(log_line), 1, 'L')
            pdf.ln(1)
    else:
        pdf.body_text("No threat logs to display.")

    # SAVE
    filename = f"Professional_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = REPORT_DIR / filename
    try:
        pdf.output(str(output_path))
        print(f"[SUCCESS] Report generated: {output_path}")
        return str(output_path)
    except Exception as e:
        print(f"[ERROR] Save PDF failed: {e}")
        return None

if __name__ == '__main__':
    create_pro_report()