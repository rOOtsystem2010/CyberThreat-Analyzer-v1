import os
import json
import io
from flask import Flask, request, jsonify, render_template_string
from flask_compress import Compress
from google import genai
from google.genai import types
from google.genai.errors import APIError

# =========================================================================
# قراءة المفتاح من متغيرات البيئة
API_KEY = os.environ.get('GEMINI_API_KEY')

# إذا لم يتم تعيين المفتاح، لا نرفع خطأ حرج يوقف عمل التطبيق.
# بدلاً من ذلك، نستخدم مفتاحًا وهميًا (FAKE_KEY) للسماح للتهيئة بالمرور،
# ونقوم بالفحص الحقيقي داخل دالة /analyze.
if not API_KEY:
    print("WARNING: GEMINI_API_KEY is not set. API calls will fail.")
    API_KEY = "FAKE_KEY"

try:
    # تهيئة العميل باستخدام المفتاح الفعلي أو الوهمي
    client = genai.Client(api_key=API_KEY)
except Exception as e:
    # هذا الخطأ نادر الحدوث في هذه المرحلة، لكنه يحمي من حالات تعطل المكتبة
    print(f"Error initializing Gemini client: {e}")
    # إذا حدث خطأ، نتأكد من أن المفتاح سيبقى 'FAKE_KEY' لكي يتم الفحص لاحقًا
    pass

# =========================================================================

app = Flask(__name__)
Compress(app) # تهيئة ضغط Gzip

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
                "critical": types.Schema(
                    type=types.Type.ARRAY, 
                    description="قائمة بالنتائج الحرجة.",
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "النتيجة": types.Schema(type=types.Type.STRING),
                            "التوصية": types.Schema(type=types.Type.STRING)
                        },
                        required=["النتيجة", "التوصية"]
                    )
                ),
                "high": types.Schema(
                    type=types.Type.ARRAY, 
                    description="قائمة بالنتائج ذات الخطورة العالية.",
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "النتيجة": types.Schema(type=types.Type.STRING),
                            "التوصية": types.Schema(type=types.Type.STRING)
                        },
                        required=["النتيجة", "التوصية"]
                    )
                ),
                "medium": types.Schema(
                    type=types.Type.ARRAY, 
                    description="قائمة بالنتائج ذات الخطورة المتوسطة.",
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "النتيجة": types.Schema(type=types.Type.STRING),
                            "التوصية": types.Schema(type=types.Type.STRING)
                        },
                        required=["النتيجة", "التوصية"]
                    )
                ),
                "low": types.Schema(
                    type=types.Type.ARRAY, 
                    description="قائمة بالنتائج ذات الخطورة المنخفضة.",
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "النتيجة": types.Schema(type=types.Type.STRING),
                            "التوصية": types.Schema(type=types.Type.STRING)
                        },
                        required=["النتيجة", "التوصية"]
                    )
                )
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
    """تقديم صفحة الواجهة الأمامية مع HTML و JavaScript مدمجين."""
    
    # محتوى HTML كاملاً مدمجاً مع Tailwind CSS
    html_content = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberThreat Analyzer v1.0.2</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;700&display=swap');
        body {
            font-family: 'Cairo', sans-serif;
            background-color: #0d1117; /* Dark background */
            color: #c9d1d9; /* Light text */
        }
        .container-main {
            max-width: 1200px;
        }
        .section-header {
            border-right: 4px solid #38bdf8;
        }
        /* تحديد الألوان لفئات المخاطر */
        .critical { background-color: #ef4444; }
        .high { background-color: #f97316; }
        .medium { background-color: #facc15; }
        .low { background-color: #22c55e; }
        
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body class="p-4 md:p-8">

    <div class="container-main mx-auto">
        <header class="text-center py-6">
            <h1 class="text-3xl font-bold text-sky-400">محلل التهديدات السيبرانية CYBERTHREAT ANALYZER v1.0.2</h1>
            <p class="text-gray-400 mt-1">مدعوم بخوارزميات Gemini - تحليل وتحديد التهديدات السيبرانية</p>
        </header>

        <!-- قسم إدخال البيانات والتحليل -->
        <div class="bg-gray-800 p-6 rounded-xl shadow-2xl mb-8">
            <h2 class="text-2xl font-semibold mb-4 text-white section-header pr-3">نقطة إدخال البيانات / التحليل</h2>
            
            <form id="analysisForm" class="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                <!-- ملف السجل -->
                <div class="col-span-1">
                    <label for="logFile" class="block text-sm font-medium text-gray-300 mb-2">اختر ملف السجل (.log, .txt, .jsonl, ...)</label>
                    <input type="file" id="logFile" name="file" required class="block w-full text-sm text-gray-500
                        file:mr-4 file:py-2 file:px-4
                        file:rounded-full file:border-0
                        file:text-sm file:font-semibold
                        file:bg-sky-50 file:text-sky-700
                        hover:file:bg-sky-100
                    ">
                </div>

                <!-- زر التحليل -->
                <div class="col-span-1 md:col-span-2 flex items-end">
                    <button type="submit" id="analyzeButton" class="w-full md:w-auto px-6 py-3 bg-sky-600 hover:bg-sky-700 text-white font-bold rounded-xl transition duration-200 shadow-md flex items-center justify-center">
                        <span id="buttonText">بدء التحليل الدقيق</span>
                        <svg id="spinner" class="animate-spin -ml-1 mr-3 h-5 w-5 text-white hidden" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                    </button>
                </div>
            </form>

            <div id="messageBox" class="mt-4 p-3 rounded-lg text-sm hidden"></div>
        </div>

        <!-- قسم عرض النتائج -->
        <div id="resultsSection" class="hidden">
            
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                
                <!-- ملخص المخاطر (التقييم) -->
                <div class="md:col-span-1 bg-gray-700 p-6 rounded-xl shadow-xl text-center">
                    <h3 class="text-xl font-bold text-gray-300 mb-4">ملخص المخاطر</h3>
                    <div id="riskAssessment" class="p-4 rounded-xl text-white">
                        <p class="text-5xl font-extrabold" id="riskScore">--</p>
                        <p class="text-2xl font-semibold mt-2" id="riskLevel">غير مُحلل</p>
                    </div>
                </div>

                <!-- سردية الهجوم (Narrative) -->
                <div class="md:col-span-3 bg-gray-700 p-6 rounded-xl shadow-xl">
                    <h3 class="text-xl font-bold text-gray-300 mb-4 section-header pr-3">سردية الهجوم (AI Narrative)</h3>
                    <p id="attackSummary" class="text-gray-300 leading-relaxed mb-4">... ملخص الهجوم الذي تم اكتشافه بواسطة Gemini API سيظهر هنا ...</p>
                    <div class="grid grid-cols-3 gap-4 text-sm mt-4">
                        <div class="bg-gray-600 p-3 rounded-lg">
                            <p class="font-bold text-sky-300">نية المهاجم:</p>
                            <p id="attackerIntent">--</p>
                        </div>
                        <div class="bg-gray-600 p-3 rounded-lg">
                            <p class="font-bold text-sky-300">أصل الهجوم:</p>
                            <p id="attackOrigin">--</p>
                        </div>
                        <div class="bg-gray-600 p-3 rounded-lg">
                            <p class="font-bold text-sky-300">مراحل الهجوم:</p>
                            <p id="attackStages">--</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- قسم التفاصيل والجداول -->
            <div class="bg-gray-800 p-6 rounded-xl shadow-2xl">
                
                <!-- شريط التبويبات -->
                <div class="flex flex-wrap border-b border-gray-700 mb-6">
                    <button class="tab-button active bg-gray-700 text-white font-semibold py-2 px-4 rounded-t-lg transition-colors duration-150" data-tab="findings">النتائج التفصيلية والمصفوفات</button>
                    <button class="tab-button text-gray-400 hover:bg-gray-700 hover:text-white font-semibold py-2 px-4 rounded-t-lg transition-colors duration-150" data-tab="ipIntel">استخبارات IP وحالة البنية</button>
                    <button class="tab-button text-gray-400 hover:bg-gray-700 hover:text-white font-semibold py-2 px-4 rounded-t-lg transition-colors duration-150" data-tab="rca">تحليل السبب الجذري (RCA)</button>
                    <button class="tab-button text-gray-400 hover:bg-gray-700 hover:text-white font-semibold py-2 px-4 rounded-t-lg transition-colors duration-150" data-tab="yara">محاكاة YARA المطابقة</button>
                    <button class="tab-button text-gray-400 hover:bg-gray-700 hover:text-white font-semibold py-2 px-4 rounded-t-lg transition-colors duration-150" data-tab="recommendations">التوصيات والإجراءات المضادة</button>
                    <button class="tab-button text-gray-400 hover:bg-gray-700 hover:text-white font-semibold py-2 px-4 rounded-t-lg transition-colors duration-150" data-tab="timeline">الخط الزمني التفاعلي</button>
                </div>

                <!-- محتوى التبويبات -->
                <div id="tabContents">
                    
                    <!-- 1. النتائج التفصيلية والمصفوفات (الافتراضي) -->
                    <div id="findings" class="tab-content active p-4 bg-gray-700 rounded-xl">
                        <h4 class="text-xl font-bold mb-4 text-sky-300">النتائج المفصلة (مجمعة حسب الخطورة)</h4>
                        <div id="detailedFindings" class="space-y-6">
                            <!-- النتائج سيتم إدراجها هنا بواسطة JS -->
                        </div>
                    </div>

                    <!-- 2. استخبارات IP وحالة البنية -->
                    <div id="ipIntel" class="tab-content p-4">
                        <h4 class="text-xl font-bold mb-4 text-sky-300">استخبارات IP وحالة البنية</h4>
                        <table class="min-w-full divide-y divide-gray-700">
                            <thead class="bg-gray-700">
                                <tr>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">عنوان IP</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">المنظمة</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">الدولة</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">الدور</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">الحالة</th>
                                </tr>
                            </thead>
                            <tbody id="ipIntelBody" class="bg-gray-800 divide-y divide-gray-700">
                                <!-- البيانات سيتم إدراجها هنا بواسطة JS -->
                            </tbody>
                        </table>
                    </div>

                    <!-- 3. تحليل السبب الجذري (RCA) -->
                    <div id="rca" class="tab-content p-4">
                        <h4 class="text-xl font-bold mb-4 text-sky-300">تحليل السبب الجذري (RCA)</h4>
                        <table class="min-w-full divide-y divide-gray-700">
                            <thead class="bg-gray-700">
                                <tr>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">عنصر التحليل</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">النتيجة/التفاصيل</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">التوصية</th>
                                </tr>
                            </thead>
                            <tbody id="rcaBody" class="bg-gray-800 divide-y divide-gray-700">
                                <!-- البيانات سيتم إدراجها هنا بواسطة JS -->
                            </tbody>
                        </table>
                    </div>

                    <!-- 4. محاكاة YARA المطابقة -->
                    <div id="yara" class="tab-content p-4">
                        <h4 class="text-xl font-bold mb-4 text-sky-300">محاكاة YARA المطابقة</h4>
                        <table class="min-w-full divide-y divide-gray-700">
                            <thead class="bg-gray-700">
                                <tr>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">القاعدة المطابقة</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">الشدة</th>
                                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-300 uppercase tracking-wider">النتيجة</th>
                                </tr>
                            </thead>
                            <tbody id="yaraBody" class="bg-gray-800 divide-y divide-gray-700">
                                <!-- البيانات سيتم إدراجها هنا بواسطة JS -->
                            </tbody>
                        </table>
                    </div>

                    <!-- 5. التوصيات والإجراءات المضادة -->
                    <div id="recommendations" class="tab-content p-4">
                        <h4 class="text-xl font-bold mb-4 text-sky-300">التوصيات والإجراءات المضادة</h4>
                        <ul id="recommendationsList" class="list-disc pr-6 space-y-2">
                            <!-- البيانات سيتم إدراجها هنا بواسطة JS -->
                        </ul>
                    </div>
                    
                    <!-- 6. الخط الزمني التفاعلي (ملاحظة: هذا يتطلب مكتبة JS خارجية، سنعرض بيانات خام فقط) -->
                    <div id="timeline" class="tab-content p-4">
                        <h4 class="text-xl font-bold mb-4 text-sky-300">بيانات الخط الزمني (Groups & Items)</h4>
                        <pre id="timelineData" class="bg-gray-900 p-4 rounded-lg text-sm overflow-auto text-green-300 h-64">
                            ... البيانات الخام للخط الزمني سيتم عرضها هنا ...
                            (ملاحظة: يتطلب هذا القسم مكتبة رسوم بيانية مثل Vis.js للعرض التفاعلي، ولكننا نعرض JSON الخام لضمان عمل الواجهة الأمامية.)
                        </pre>
                    </div>

                </div>
            </div>
        </div>

        <!-- قسم التذييل -->
        <footer class="mt-8 text-center text-sm text-gray-500">
            <p>وقت التحليل: <span id="analysisTime">--</span></p>
        </footer>

    </div>
    
    <!-- JavaScript لعملية AJAX والتفاعل مع الواجهة الأمامية -->
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const form = document.getElementById('analysisForm');
            const resultsSection = document.getElementById('resultsSection');
            const messageBox = document.getElementById('messageBox');
            const analyzeButton = document.getElementById('analyzeButton');
            const buttonText = document.getElementById('buttonText');
            const spinner = document.getElementById('spinner');

            const tabButtons = document.querySelectorAll('.tab-button');
            const tabContents = document.querySelectorAll('.tab-content');
            
            // ==========================================================
            // وظائف التبويبات (Tabs)
            // ==========================================================
            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    const targetTab = button.getAttribute('data-tab');

                    // إزالة التنشيط من جميع الأزرار والمحتويات
                    tabButtons.forEach(btn => {
                        btn.classList.remove('active', 'bg-gray-700', 'text-white');
                        btn.classList.add('text-gray-400', 'hover:bg-gray-700', 'hover:text-white');
                    });
                    tabContents.forEach(content => {
                        content.classList.remove('active');
                    });

                    // تنشيط الزر والمحتوى المطلوب
                    button.classList.add('active', 'bg-gray-700', 'text-white');
                    button.classList.remove('text-gray-400', 'hover:bg-gray-700', 'hover:text-white');
                    document.getElementById(targetTab).classList.add('active');
                });
            });

            // ==========================================================
            // وظائف المساعدة في العرض (Rendering Helpers)
            // ==========================================================
            
            function showMessage(message, type = 'error') {
                messageBox.classList.remove('hidden', 'bg-red-900', 'bg-green-900');
                if (type === 'error') {
                    messageBox.classList.add('bg-red-900', 'text-red-300');
                } else if (type === 'success') {
                    messageBox.classList.add('bg-green-900', 'text-green-300');
                }
                messageBox.innerHTML = message;
            }

            function hideMessage() {
                messageBox.classList.add('hidden');
            }

            function renderDetailedFindings(findings) {
                const container = document.getElementById('detailedFindings');
                container.innerHTML = ''; // تنظيف المحتوى القديم

                const categories = [
                    { key: 'critical', title: 'نتائج حرجة (Critical)', color: 'bg-red-700', text: 'text-red-100' },
                    { key: 'high', title: 'نتائج عالية (High)', color: 'bg-orange-600', text: 'text-orange-100' },
                    { key: 'medium', title: 'نتائج متوسطة (Medium)', color: 'bg-yellow-600', text: 'text-yellow-100' },
                    { key: 'low', title: 'نتائج منخفضة (Low)', color: 'bg-green-600', text: 'text-green-100' },
                ];

                categories.forEach(cat => {
                    if (findings[cat.key] && findings[cat.key].length > 0) {
                        const html = `
                            <div class="p-4 rounded-xl ${cat.color} ${cat.text} shadow-lg">
                                <h5 class="text-lg font-bold mb-3 border-b border-opacity-50 pb-2">${cat.title} (${findings[cat.key].length} نتيجة)</h5>
                                <ul class="list-disc pr-6 space-y-3">
                                    ${findings[cat.key].map(item => `
                                        <li>
                                            <p class="font-semibold">${item.النتيجة}</p>
                                            <p class="text-sm opacity-90 mt-1"><strong>التوصية:</strong> ${item.التوصية}</p>
                                        </li>
                                    `).join('')}
                                </ul>
                            </div>
                        `;
                        container.insertAdjacentHTML('beforeend', html);
                    }
                });
            }

            function renderTable(data, tableId) {
                const tbody = document.getElementById(tableId);
                tbody.innerHTML = '';
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center text-gray-500">لا توجد بيانات متاحة في هذا القسم.</td></tr>';
                    return;
                }

                data.forEach(row => {
                    const rowHtml = Object.values(row).map(val => 
                        `<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">${val}</td>`
                    ).join('');
                    // استخدام Object.keys للحصول على عدد الأعمدة وتعيين colspan بشكل ديناميكي
                    const colspan = Object.keys(data[0] || {}).length || 5; 
                    
                    tbody.insertAdjacentHTML('beforeend', `
                        <tr class="hover:bg-gray-700 transition duration-150">
                            ${rowHtml}
                        </tr>
                    `);
                });
            }

            // ==========================================================
            // وظيفة معالجة الاستجابة (Main Renderer)
            // ==========================================================
            function renderAnalysisResults(data) {
                // إظهار قسم النتائج
                resultsSection.classList.remove('hidden');

                // 1. تقييم المخاطر (Risk Assessment)
                const risk = data.risk_assessment;
                document.getElementById('riskScore').textContent = risk.score;
                document.getElementById('riskLevel').textContent = risk.level;
                
                const riskDiv = document.getElementById('riskAssessment');
                riskDiv.className = 'p-4 rounded-xl text-white'; // إعادة تعيين الفئات
                riskDiv.classList.add(risk.color_class);

                // 2. سردية الهجوم (Attack Narrative)
                const narrative = data.attack_narrative;
                document.getElementById('attackSummary').textContent = narrative.summary;
                document.getElementById('attackerIntent').textContent = narrative.attacker_intent;
                document.getElementById('attackOrigin').textContent = narrative.attack_origin_country;
                document.getElementById('attackStages').textContent = narrative.stages_found.join(' | ');

                // 3. النتائج التفصيلية (Detailed Findings) - **هذا هو إصلاح خطأ 'slice is not a function'**
                renderDetailedFindings(data.detailed_findings);

                // 4. الجداول (Tables)
                renderTable(data.tables.ip_intelligence, 'ipIntelBody');
                renderTable(data.tables.rca_analysis, 'rcaBody');
                renderTable(data.tables.yara_analysis, 'yaraBody');

                // 5. التوصيات
                const recList = document.getElementById('recommendationsList');
                recList.innerHTML = data.recommendations.map(rec => `<li>${rec}</li>`).join('');

                // 6. الخط الزمني (Raw Data)
                document.getElementById('timelineData').textContent = JSON.stringify(data.interactive_timeline, null, 2);

                // 7. البيانات الوصفية (Metadata)
                document.getElementById('analysisTime').textContent = data.analysis_metadata.analysis_time;
            }

            // ==========================================================
            // معالج إرسال النموذج (Form Submission Handler)
            // ==========================================================
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                hideMessage();
                
                // عرض حالة التحميل
                analyzeButton.disabled = true;
                buttonText.textContent = 'جاري التحليل...';
                spinner.classList.remove('hidden');
                
                try {
                    const logFile = document.getElementById('logFile').files[0];
                    if (!logFile) {
                        showMessage('يجب اختيار ملف سجل أولاً.', 'error');
                        return;
                    }
                    
                    const formData = new FormData();
                    formData.append('file', logFile);
                    
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        body: formData
                    });

                    const data = await response.json();
                    
                    if (response.ok) {
                        // نجاح استجابة Flask والـ AI
                        renderAnalysisResults(data);
                        showMessage('تم التحليل بنجاح. راجع النتائج أدناه.', 'success');
                    } else {
                        // خطأ من Flask (مثل خطأ API Key أو JSON Decode Error)
                        // نستخدم data.error لأننا نرجعها من Flask عند فشل /analyze
                        throw new Error(data.error || 'حدث خطأ غير معروف في الخادم.');
                    }

                } catch (error) {
                    console.error('Fetch Error:', error);
                    // عرض رسالة الخطأ الواردة من الخادم أو الخطأ العام
                    showMessage(`فشل التحليل: ${error.message || 'يرجى التحقق من سجلات الخادم.'}`, 'error');
                    resultsSection.classList.add('hidden');
                } finally {
                    // إخفاء حالة التحميل
                    analyzeButton.disabled = false;
                    buttonText.textContent = 'بدء التحليل الدقيق';
                    spinner.classList.add('hidden');
                }
            });
        });
    </script>
</body>
</html>
"""
    return render_template_string(html_content)

@app.route('/analyze', methods=['POST'])
def analyze_log():
    """نقطة النهاية لتحليل ملف السجل."""
    
    # الفحص الحقيقي: التحقق من أن المفتاح موجود وله قيمة فعلية
    if not API_KEY or API_KEY == "FAKE_KEY":
         return jsonify({"success": False, "error": "خطأ حرج: المفتاح (GEMINI_API_KEY) غير مهيأ بشكل صحيح في بيئة النشر. يرجى التحقق من متغيرات Vercel البيئية. (المفتاح فارغ أو غير متوفر)"}), 500

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
            
            # معالجة JSON القوية لخطأ JSON.parse
            try:
                # 1. تنظيف النص: إزالة المسافات البيضاء وعلامات Markdown (مثل ```json)
                json_text = response.text.strip().lstrip('```json').rstrip('```')
                
                # 2. التحقق للتأكد من أن النص يبدأ بـ { أو [ قبل محاولة التحويل
                if not json_text.startswith('{') and not json_text.startswith('['):
                    print(f"JSON Parsing Failed: Response did not start with {{ or [. Beginning of text: {json_text[:200]}...")
                    raise json.JSONDecodeError("Response is not valid JSON.", doc=json_text, pos=0)

                analysis_data = json.loads(json_text)
                return jsonify(analysis_data)
            
            except json.JSONDecodeError as e:
                # خطأ في تحليل JSON
                return jsonify({"success": False, "error": "فشل تحليل استجابة الذكاء الاصطناعي إلى JSON. قد يكون النموذج أضاف نصاً غير مطلوباً. (JSON Decode Error)"}), 500

        except APIError as e:
            # خطأ في مفتاح API أو الرصيد أو القيود. هذه النقطة هي التي تفشل إذا كان المفتاح غير صحيح فعليًا.
            return jsonify({"success": False, "error": f"خطأ في الاتصال بواجهة Gemini API (API Error). تحقق من المفتاح وقيود الرصيد: {e.message}"}), 500
        except Exception as e:
            # معالجة الأخطاء العامة
            return jsonify({"success": False, "error": f"حدث خطأ غير متوقع أثناء المعالجة: {e}"}), 500

    return jsonify({"success": False, "error": "نوع ملف غير مدعوم. يرجى استخدام .log، .txt، .csv، .json أو .jsonl"}), 400

if __name__ == '__main__':
    if 'RENDER' not in os.environ and 'VERCEL' not in os.environ:
        print("Running Flask locally (Development Mode)...")
        app.run(debug=True, host='0.0.0.0', port=5000)
