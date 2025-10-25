import os
import json
import time
from flask import Flask, request, jsonify, render_template 
from werkzeug.utils import secure_filename
from google import genai

# =========================================================================
# 🛑🛑🛑 المفتاح والتهيئة 🛑🛑🛑
# يتم تعيين المفتاح مباشرة هنا باستخدام المفتاح الذي أرسلته:
os.environ['GEMINI_API_KEY'] = 'AIzaSyCAnPHMXUQQ2PrtD6YAvWpZXLuHEGY-DP0'
# =========================================================================

# --- التهيئة والأمان ---
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# التأكد من وجود مفتاح API في متغيرات البيئة 
if 'GEMINI_API_KEY' not in os.environ:
    print("FATAL ERROR: GEMINI_API_KEY is not set.")
    exit(1)

try:
    client = genai.Client()
except Exception as e:
    # هذا الخطأ لم يعد يظهر بسبب تثبيت المفتاح، لكن نتركه احتياطاً
    print(f"Failed to initialize Gemini Client: {e}") 
    exit(1)


# --- تعريف مخطط JSON (Schema) المُصحَّح (تم إزالة additionalProperties) ---
# ملاحظة: تم تغيير detailed_findings ليستخدم صفائف من الكائنات بدلاً من كائنات بخاصيات غير معروفة.
FINDING_DETAIL_ITEM = {
    "type": "object",
    "properties": {
        "finding_type": {"type": "string", "description": "نوع الاكتشاف (مثل: Brute_Force, SQL_Injection, Reconnaissance)."},
        "line": {"type": "integer"},
        "timestamp_str": {"type": "string", "description": "التاريخ والوقت الحقيقيان للحدث في السجل."},
        "log_entry": {"type": "string", "description": "السطر الحقيقي والمُحلَّل من ملف السجل الذي يمثل هذا الحدث."},
        "ip_matches": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["finding_type", "line", "timestamp_str", "log_entry", "ip_matches"]
}

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "analysis_metadata": {
            "type": "object",
            "properties": {
                "file_name": {"type": "string"},
                "analysis_time": {"type": "string", "description": "الوقت المستغرق للتحليل."},
            },
            "required": ["file_name", "analysis_time"]
        },
        "risk_assessment": {
            "type": "object",
            "properties": {
                "score": {"type": "integer", "description": "درجة المخاطر من 0 إلى 100."},
                "level": {"type": "string", "description": "مستوى المخاطر (Critical, High, Medium, Low)."},
                "color_class": {"type": "string", "description": "اسم فئة اللون (critical, high, medium, low)."},
            },
            "required": ["score", "level", "color_class"]
        },
        "attack_narrative": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "ملخص شامل للهجوم المكتشف."},
                "attacker_intent": {"type": "string", "description": "النية المحتملة للمهاجم (مثل: سرقة بيانات، تعطيل، استطلاع)."},
                "attack_origin_country": {"type": "string", "description": "الدولة المحتملة لأصل الهجوم (استخدم بيانات حقيقية من IPs في الملف)."},
                "stages_found": {"type": "array", "items": {"type": "string"}, "description": "مراحل الهجوم المكتشفة وفقاً لـ MITRE ATT&CK."},
            },
            "required": ["summary", "attacker_intent", "attack_origin_country", "stages_found"]
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "قائمة بالتوصيات الأمنية والإجراءات المضادة."
        },
        "detailed_findings": {
            "type": "object",
            "description": "النتائج التفصيلية مرتبة حسب الخطورة والفئة.",
            "properties": {
                # تم تغيير الهيكل من كائن بخاصيات ديناميكية إلى صفائف ثابتة
                "critical": {"type": "array", "items": FINDING_DETAIL_ITEM, "description": "صفيفة بالأحداث الحرجة."},
                "high": {"type": "array", "items": FINDING_DETAIL_ITEM, "description": "صفيفة بالأحداث عالية الخطورة."},
                "medium": {"type": "array", "items": FINDING_DETAIL_ITEM, "description": "صفيفة بالأحداث متوسطة الخطورة."},
                "low": {"type": "array", "items": FINDING_DETAIL_ITEM, "description": "صفيفة بالأحداث منخفضة الخطورة."}
            },
            "required": ["critical", "high", "medium", "low"]
        },
        "tables": {
            "type": "object",
            "properties": {
                "ip_intelligence": {
                    "type": "array",
                    "items": {"type": "object", "properties": {
                        "عنوان IP": {"type": "string", "description": "عنوان IP تم استخلاصه من ملف السجل."},
                        "النوع": {"type": "string", "description": "داخلي أو خارجي."},
                        "المنظمة": {"type": "string", "description": "المنظمة المالكة (استخدم بيانات حقيقية)."},
                        "الدولة": {"type": "string", "description": "الدولة (استخدم بيانات حقيقية)."},
                        "الدور": {"type": "string", "description": "الدور في الهجوم (مهاجم، ضحية، محايد)."},
                        "الحالة": {"type": "string", "description": "حالة IP (حي، ميت، N/A)."}
                    }, "required": ["عنوان IP", "النوع", "المنظمة", "الدولة", "الدور", "الحالة"]},
                    "description": "جدول استخبارات IP. يجب أن تكون البيانات مُستخرجة من الملف المُحلَّل."
                },
                "rca_analysis": {
                    "type": "array",
                    "items": {"type": "object", "properties": {
                        "عنصر التحليل": {"type": "string"},
                        "النتيجة/التفاصيل": {"type": "string"},
                        "التوصية": {"type": "string"}
                    }, "required": ["عنصر التحليل", "النتيجة/التفاصيل", "التوصية"]},
                    "description": "تحليل السبب الجذري."
                },
                "yara_analysis": {
                    "type": "array",
                    "items": {"type": "object", "properties": {
                        "التحليل": {"type": "string"},
                        "النتيجة": {"type": "string"}
                    }, "required": ["التحليل", "النتيجة"]},
                    "description": "نتائج مطابقة YARA."
                }
            },
            "required": ["ip_intelligence", "rca_analysis", "yara_analysis"]
        },
        "interactive_timeline": {
            "type": "object",
            "description": "بيانات الخط الزمني التفاعلي (Vis.js Timeline).",
            "properties": {
                "groups": {
                    "type": "array",
                    "items": {"type": "object", "properties": {
                        "id": {"type": "integer"},
                        "content": {"type": "string"}
                    }, "required": ["id", "content"]},
                },
                "items": {
                    "type": "array",
                    "items": {"type": "object", "properties": {
                        "id": {"type": "integer"},
                        "group": {"type": "integer"},
                        "content": {"type": "string", "description": "وصف الحدث المستخرج من السجل."},
                        "start": {"type": "string", "format": "date-time", "description": "التاريخ والوقت الحقيقيان للحدث في السجل (بتنسيق ISO 8601 مثل 2024-01-01T10:00:00)."},
                        "style": {"type": "string", "description": "تنسيق لون الحدث حسب الخطورة (مثال: background-color: #ef4444;)."}
                    }, "required": ["id", "group", "content", "start"]},
                }
            },
            "required": ["groups", "items"]
        }
    },
    "required": ["analysis_metadata", "risk_assessment", "attack_narrative", "recommendations", "detailed_findings", "tables", "interactive_timeline"]
}


def analyze_log_with_gemini(log_content, filename):
    start_time = time.time()
    
    # --- التعليمات المُحسّنة (Prompt) ---
    prompt = f"""
    أنت محلل أدلة جنائية رقمية (DFIR) متقدم. يجب عليك تحليل ملف السجل المُرفق بدقة.
    
    محتوى السجل: {log_content[:5000]}... (تم اقتطاع المحتوى لـ 5000 حرف للحجم للحفاظ على استقرار الـ API، لكن قم بتحليل المحتوى بالكامل إذا كان أقصر، وإلا اعتمد على الأجزاء الأكثر صلة في البداية والنهاية لتحديد نمط الهجوم، واجعل النتائج تعكس البيانات الحقيقية المُستخرجة).

    مهم جداً: يجب أن تكون جميع النتائج في حقول **IP Intelligence** و **Interactive Timeline** و **Detailed Findings** مُستخرجة بشكل حقيقي ومباشر من محتوى السجل أعلاه (مثل عناوين IP، الأوقات، سطور السجل).

    1.  **Risk Assessment**: قيّم المخاطر استناداً إلى الأنشطة المكتشفة في السجل.
    2.  **Attack Narrative**: أنشئ سردية متكاملة.
    3.  **Detailed Findings**: استخرج الأحداث الأكثر خطورة. **كل عنصر في الصفائف (critical, high, medium, low) يجب أن يمثل حدثًا واحدًا (one log entry) وأن يحتوي على `finding_type` لتحديد نوعه (مثل Brute_Force).**
    4.  **IP Intelligence**: استخرج عناوين IP الظاهرة في السجل (بما في ذلك الداخلية مثل 192.168.x.x إذا وجدت) وحدد دورها وحالتها (افترض أن IPs الداخلية N/A أو حي، و IPs العامة قد تكون حي/ميت).
    5.  **Interactive Timeline**: قم بإنشاء قائمة بـ 5 إلى 10 أحداث رئيسية لتظهر على الخط الزمني. **يجب أن يكون حقل `start` هو التاريخ والوقت الحقيقيان من السجل بتنسيق ISO 8601.**
    6.  **RCA/YARA**: قم بإجراء تحليل السبب الجذري ومحاكاة نتائج مطابقة YARA.

    قم بإرجاع النتيجة بتنسيق JSON حصرياً ووفقاً للمخطط المُعرَّف.
    """
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "response_schema": ANALYSIS_SCHEMA,
                "temperature": 0.2 
            }
        )
        
        end_time = time.time()
        analysis_time = f"{end_time - start_time:.2f} ثانية"

        # محاولة تحليل الإخراج JSON
        try:
            result_data = json.loads(response.text)
            result_data['analysis_metadata']['file_name'] = filename
            result_data['analysis_metadata']['analysis_time'] = analysis_time
            return result_data
        except json.JSONDecodeError:
            print(f"JSON Decode Error: Output was not valid JSON: {response.text}")
            return {"error": "فشل فك تشفير JSON من النموذج. قد يكون الناتج غير صالح.", "raw_output": response.text}

    except Exception as e:
        # هذا هو المكان الذي كان يظهر فيه خطأ additionalProperties
        return {"error": f"فشل الاتصال بنموذج Gemini: {str(e)}"}

# --- المسارات (Routes) ---

@app.route('/')
def index():
    # استخدام render_template للبحث داخل مجلد 'templates'
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({"error": "لم يتم إرفاق ملف"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "لم يتم اختيار ملف"}), 400
        
    filename = secure_filename(file.filename)
    
    try:
        # قراءة محتوى الملف المُحمَّل
        log_content = file.read().decode('utf-8', errors='ignore')
        if not log_content:
            return jsonify({"error": "ملف السجل فارغ أو لا يمكن قراءته"}), 400
        
        # إرسال المحتوى للتحليل
        analysis_result = analyze_log_with_gemini(log_content, filename)
        
        if "error" in analysis_result:
            return jsonify(analysis_result), 500

        # التحويل إلى JSON وإرسال النتيجة إلى العميل
        return jsonify(analysis_result)

    except Exception as e:
        return jsonify({"error": f"حدث خطأ غير متوقع أثناء المعالجة: {str(e)}"}), 500

if __name__ == '__main__':
    # تشغيل الخادم
    app.run(debug=True)