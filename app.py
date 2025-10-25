import os
import json
import io
from flask import Flask, request, jsonify, render_template
from google import genai
from google.genai import types
from google.genai.errors import APIError

# =========================================================================
# 🛑🛑🛑 خطوة احترافية: قراءة المفتاح من متغيرات البيئة 🛑🛑🛑
# يتم الآن قراءة المفتاح من الإعدادات التي وضعتها في Render.
API_KEY = os.environ.get('GEMINI_API_KEY')

# إذا لم يتم تعيين المفتاح في متغيرات البيئة (وهو سبب الخطأ 502)، نرفع خطأ بيئي حرج.
if not API_KEY:
    print("FATAL ERROR: GEMINI_API_KEY is not set in environment.")
    # هذا الخطأ سيوقف تشغيل Gunicorn ويعطي رسالة واضحة في سجلات Render
    raise EnvironmentError("GEMINI_API_KEY is required but not found in environment variables. Check Render environment settings.")

try:
    client = genai.Client(api_key=API_KEY)
except Exception as e:
    print(f"Error initializing Gemini client: {e}")
    raise

# =========================================================================

app = Flask(__name__, template_folder='templates')

# مخطط JSON المطلوب من النموذج (ضروري للحصول على استجابة منظمة)
ANALYSIS_SCHEMA = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "risk_assessment": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "score": types.Schema(type=types.Type.INTEGER, description="مجموع النقاط من 0 إلى 100."),
                "level": types.Schema(type=types.Type.STRING, description="مستوى المخاطرة العام (Critical, High, Medium, Low)."),
                "color_class": types.Schema(type=types.Type.STRING, description="الفئة اللونية (critical, high, medium, low).")
            },
            required=["score", "level", "color_class"]
        ),
        "attack_narrative": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "summary": types.Schema(type=types.Type.STRING, description="ملخص تنفيذي لسردية الهجوم في فقرة واحدة."),
                "attacker_intent": types.Schema(type=types.Type.STRING, description="النية المرجحة للمهاجم."),
                "attack_origin_country": types.Schema(type=types.Type.STRING, description="البلد أو المنطقة المحتملة لأصل الهجوم."),
                "stages_found": types.Schema(type=types.Type.ARRAY, items=types.Schema(type=types.Type.STRING), description="قائمة بمراحل الهجوم المكتشفة (مثل Reconnaissance, Initial Access).")
            },
            required=["summary", "attacker_intent", "attack_origin_country", "stages_found"]
        ),
        "tables": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "ip_intelligence": types.Schema(
                    type=types.Type.ARRAY,
                    description="جدول يحتوي على عناوين IP ذات الصلة الموجودة في السجل وذكاء التهديد المرتبط بها.",
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "عنوان IP": types.Schema(type=types.Type.STRING),
                            "المنظمة": types.Schema(type=types.Type.STRING, description="المنظمة المالكة للـ IP."),
                            "الدولة": types.Schema(type=types.Type.STRING, description="الدولة أو منطقة الشبكة الخاصة/الداخلية."),
                            "الدور": types.Schema(type=types.Type.STRING, description="مهاجم، وكيل، C2، هدف، خادم داخلي."),
                            "الحالة": types.Schema(type=types.Type.STRING, description="حي، ميت، N/A للشبكات الخاصة.")
                        },
                        required=["عنوان IP", "المنظمة", "الدولة", "الدور", "الحالة"],
                        property_ordering=["عنوان IP", "المنظمة", "الدولة", "الدور", "الحالة"]
                    )
                ),
                "rca_analysis": types.Schema(
                    type=types.Type.ARRAY,
                    description="جدول لتحليل السبب الجذري (RCA) مع النتائج والتوصيات المباشرة.",
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "عنصر التحليل": types.Schema(type=types.Type.STRING, description="نقاط ضعف، تكوين خاطئ، فشل في المصادقة، الخ."),
                            "النتيجة/التفاصيل": types.Schema(type=types.Type.STRING),
                            "التوصية": types.Schema(type=types.Type.STRING)
                        },
                        required=["عنصر التحليل", "النتيجة/التفاصيل", "التوصية"],
                        property_ordering=["عنصر التحليل", "النتيجة/التفاصيل", "التوصية"]
                    )
                ),
                "yara_analysis": types.Schema(
                    type=types.Type.ARRAY,
                    description="جدول بنتائج فحص قواعد YARA (يجب أن يكون محاكاة ذكية Smart Mocking) من النموذج.",
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "القاعدة المطابقة": types.Schema(type=types.Type.STRING, description="اسم قاعدة YARA التي تم مطابقتها."),
                            "الشدة": types.Schema(type=types.Type.STRING, description="الشدة للقاعدة المطابقة."),
                            "النتيجة": types.Schema(type=types.Type.STRING, description="إخراج قاعدة YARA المحاكية.")
                        },
                        required=["القاعدة المطابقة", "الشدة", "النتيجة"],
                        property_ordering=["القاعدة المطابقة", "الشدة", "النتيجة"]
                    )
                )
            },
            required=["ip_intelligence", "rca_analysis", "yara_analysis"]
        ),
        "detailed_findings": types.Schema(
            type=types.Type.OBJECT,
            description="النتائج المفصلة، مجمعة حسب الخطورة.",
            properties={
                "critical": types.Schema(type=types.Type.OBJECT),
                "high": types.Schema(type=types.Type.OBJECT),
                "medium": types.Schema(type=types.Type.OBJECT),
                "low": types.Schema(type=types.Type.OBJECT)
            },
            required=["critical", "high", "medium", "low"]
        ),
        "recommendations": types.Schema(type=types.Type.ARRAY, items=types.Schema(type=types.Type.STRING), description="قائمة بالتوصيات الأمنية والإجراءات المضادة."),
        "interactive_timeline": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "groups": types.Schema(type=types.Type.ARRAY),
                "items": types.Schema(type=types.Type.ARRAY)
            },
            required=["groups", "items"]
        ),
        "analysis_metadata": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "analysis_time": types.Schema(type=types.Type.STRING, description="الوقت المستغرق في التحليل.")
            }
        )
    },
    required=["risk_assessment", "attack_narrative", "tables", "detailed_findings", "recommendations", "interactive_timeline", "analysis_metadata"]
)


@app.route('/')
def index():
    """تقديم صفحة الواجهة الأمامية."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_log():
    """نقطة النهاية لتحليل ملف السجل."""
    
    # التأكد من وجود المفتاح قبل أي عملية
    if not client.api_key:
         return jsonify({"success": False, "error": "خطأ حرج في تهيئة المفتاح API. يرجى التحقق من إعدادات البيئة (Render)."}), 500

    if 'file' not in request.files:
        return jsonify({"success": False, "error": "لم يتم إرفاق ملف (File input name should be 'file')"}), 400

    log_file = request.files['file']
    if log_file.filename == '':
        return jsonify({"success": False, "error": "لم يتم اختيار ملف"}), 400

    if log_file and log_file.filename.endswith(('.log', '.txt', '.csv', '.json', '.jsonl')):
        try:
            # قراءة محتويات الملف مباشرة من الذاكرة
            log_content = log_file.read().decode('utf-8')
            
            # بناء موجه النظام
            system_instruction = (
                "أنت محلل جنائي رقمي آلي وخبير في تحليل سجلات الأنظمة. "
                "مهمتك هي تحليل ملف السجل المقدم وتحديد السبب الجذري لأي حادث أمني (اختراق، محاولة وصول غير مصرح بها، الخ) أو مشكلة نظام. "
                "يجب عليك إرجاع استجابة JSON فقط وفقًا للمخطط المحدد (ANALYSIS_SCHEMA). "
                "يجب أن تكون جميع الردود والتحليلات والجداول والملخصات باللغة العربية الفصحى. "
                "كن دقيقًا وموجزًا في التحليل والنتائج."
            )
            
            # بناء موجه المستخدم
            user_prompt = f"إليك محتوى ملف السجل للتحليل الجنائي. قم بتنفيذ التحليل بناءً على المخطط المطلوب. ملف السجل هو:\n\n---\n\n{log_content}"
            
            # استدعاء Gemini API
            response = client.models.generate_content(
                model='gemini-2.5-flash', # استخدام النموذج المستقر
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    response_schema=ANALYSIS_SCHEMA,
                    # ضبط درجة الحرارة للحصول على استجابات أكثر ثباتًا ومنطقية
                    temperature=0.2 
                )
            )
            
            # تحويل النص المستجاب إلى كائن JSON
            try:
                # إزالة أي علامات Markdown قد تظهر في استجابة النموذج (مثل ```json)
                json_text = response.text.strip().lstrip('```json').rstrip('```')
                analysis_data = json.loads(json_text)
                return jsonify(analysis_data)
            except json.JSONDecodeError:
                print(f"Failed to decode JSON from model response: {response.text}")
                # قد يكون الخطأ هو عدم وجود علامات الاقتباس حول حقول JSON في بعض الحالات النادرة
                return jsonify({"error": "فشل تحليل استجابة الذكاء الاصطناعي إلى JSON. قد يكون المخطط غير مطابق."}), 500

        except APIError as e:
            # خطأ في مفتاح API أو الرصيد أو القيود
            return jsonify({"error": f"خطأ في الاتصال بواجهة Gemini API (API Error): {e.message}"}), 500
        except Exception as e:
            # معالجة الأخطاء العامة
            return jsonify({"error": f"حدث خطأ غير متوقع أثناء المعالجة: {e}"}), 500

    return jsonify({"error": "نوع ملف غير مدعوم. يرجى استخدام .log، .txt، .csv، .json أو .jsonl"}), 400

if __name__ == '__main__':
    # هذا البلوك مخصص للتشغيل المحلي فقط
    if 'RENDER' not in os.environ:
        print("Running Flask locally (Development Mode)...")
        app.run(debug=True, host='0.0.0.0', port=5000)