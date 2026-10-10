import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Middleware for JSON body
app.use(express.json({ limit: '20mb' }));

// Serve static assets from public folder (e.g. videos, images)
app.use(express.static(path.resolve(__dirname, 'public')));

// Initialize Gemini Client
let geminiClient: GoogleGenAI | null = null;
const apiKey = process.env.GEMINI_API_KEY;

if (apiKey) {
  try {
    geminiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.error('Error initializing Gemini Client:', err);
  }
}

// Fallback heuristic evaluator for Vietnamese middle-school scam detection
function analyzeTextHeuristically(text: string) {
  const lower = text.toLowerCase();
  const redFlags: string[] = [];
  let score = 15; // baseline

  // Urgency & Fear tactics
  if (lower.includes('khẩn cấp') || lower.includes('ngay lập tức') || lower.includes('trong 15 phút') || lower.includes('khóa tài khoản') || lower.includes('bị đình chỉ') || lower.includes('bị phong tỏa')) {
    score += 25;
    redFlags.push('Tạo áp lực tâm lý khẩn cấp, hối thúc hành động ngay lập tức để nạn nhân mất bình tĩnh');
  }

  // Impersonation
  if (lower.includes('công an') || lower.includes('viện kiểm sát') || lower.includes('tòa án') || lower.includes('điều tra viên') || lower.includes('lệnh bắt')) {
    score += 35;
    redFlags.push('Dấu hiệu mạo danh cơ quan công an / pháp luật (Cơ quan nhà nước không bao giờ làm việc hay yêu cầu chuyển tiền qua tin nhắn/mạng xã hội)');
  }
  if (lower.includes('thầy') || lower.includes('cô') || lower.includes('giáo viên') || lower.includes('học phí') || lower.includes('quỹ lớp') || lower.includes('nhà trường')) {
    if (lower.includes('chuyển') || lower.includes('stk') || lower.includes('ngân hàng') || lower.includes('tiền')) {
      score += 25;
      redFlags.push('Đề cập đến giáo viên/nhà trường yêu cầu chuyển tiền vào tài khoản cá nhân');
    }
  }

  // Financial / Freebies / Games
  if (lower.includes('trúng thưởng') || lower.includes('quà tặng') || lower.includes('iphone') || lower.includes('xe máy') || lower.includes('kim cương') || lower.includes('free fire') || lower.includes('robux') || lower.includes('nạp thẻ') || lower.includes('nhận miễn phí')) {
    score += 30;
    redFlags.push('Đánh vào tâm lý ham quà, ham đồ game miễn phí hoặc nạp lậu');
  }

  // Employment / Task scams
  if (lower.includes('cộng tác viên') || lower.includes('việc nhẹ lương cao') || lower.includes('like tiktok') || lower.includes('chốt đơn') || lower.includes('hoa hồng') || lower.includes('nhiệm vụ')) {
    score += 30;
    redFlags.push('Dấu hiệu chiêu trò bẫy "Cộng tác viên làm nhiệm vụ Shopee/TikTok nhận hoa hồng"');
  }

  // OTP and sensitive info
  if (lower.includes('otp') || lower.includes('mã xác thực') || lower.includes('mật khẩu') || lower.includes('số cccd') || lower.includes('đăng nhập')) {
    score += 35;
    redFlags.push('Yêu cầu cung cấp mã OTP, mật khẩu hoặc thông tin định danh nhạy cảm');
  }

  // Money borrowing
  if (lower.includes('chuyển khoản') || lower.includes('stk') || lower.includes('mượn tiền') || lower.includes('kẹt tiền') || lower.includes('cấp cứu') || lower.includes('tai nạn')) {
    score += 25;
    redFlags.push('Yêu cầu mượn tiền hoặc chuyển khoản với lý do gặp nạn, kẹt tiền khẩn cấp');
  }

  // Normalize score
  score = Math.min(score, 95);
  score = Math.max(score, 10);

  let riskLevel: 'THẤP' | 'TRUNG BÌNH' | 'CAO' | 'RẤT CAO' = 'THẤP';
  if (score >= 80) riskLevel = 'RẤT CAO';
  else if (score >= 60) riskLevel = 'CAO';
  else if (score >= 35) riskLevel = 'TRUNG BÌNH';

  if (redFlags.length === 0) {
    redFlags.push('Nội dung không chứa các từ khóa lừa đảo phổ biến đã biết');
  }

  return {
    riskLevel,
    riskScore: score,
    suspiciousSigns: redFlags,
    explanation:
      riskLevel === 'THẤP'
        ? 'Nội dung tin nhắn chưa thấy dấu hiệu đáng ngờ điển hình. Tuy nhiên em hãy luôn cẩn thận khi có yêu cầu chia sẻ thông tin cá nhân hoặc bấm vào liên kết.'
        : `Tin nhắn có ${redFlags.length} dấu hiệu đáng ngờ thường gặp trong các vụ lừa đảo nhắm vào học sinh và phụ huynh. Kẻ xấu thường lợi dụng danh nghĩa giáo viên, người thân hoặc đánh vào tâm lý sợ hãi, ham quà tặng.`,
    recommendations: [
      'Áp dụng ngay quy trình 4 bước: DỪNG lại, không vội trả lời hay làm theo.',
      'Gọi điện thoại trực tiếp bằng số di động thông thường hoặc gặp mặt người gửi để XÁC MINH.',
      'Tuyệt đối KHÔNG chia sẻ mã OTP, mật khẩu hay chuyển tiền.',
      'BÁO CÁO ngay cho cha mẹ hoặc thầy cô giáo chủ nhiệm để được hướng dẫn xử lý.',
    ],
    disclaimer:
      'Lưu ý quan trọng: Kết quả phân tích dựa trên thuật toán nhận diện dấu hiệu và không thể khẳng định chắc chắn 100% nội dung là lừa đảo. Em hãy luôn xác minh trực tiếp với người thật trước khi đưa ra bất kỳ quyết định nào!',
  };
}

// Route: Analyze Message / Image
app.post('/api/analyze-message', async (req, res) => {
  try {
    const { message, imageBase64, mimeType = 'image/jpeg' } = req.body;

    if (!message && !imageBase64) {
      return res.status(400).json({ error: 'Vui lòng cung cấp tin nhắn hoặc hình ảnh' });
    }

    if (geminiClient) {
      try {
        const promptText = `Bạn là Chuyên gia An toàn số của Hệ thống "AI SCAM CHECK - THCS XÀ PHIÊN", chuyên hỗ trợ học sinh THCS (11-15 tuổi) nhận diện và ứng phó lừa đảo trực tuyến.
Hãy phân tích nội dung/hình ảnh sau và trả về kết quả theo định dạng JSON chính xác.

Nội dung tin nhắn: "${message || '(Phân tích theo ảnh được đính kèm)'}"

Yêu cầu phân tích:
1. Đánh giá mức độ rủi ro: "THẤP", "TRUNG BÌNH", "CAO", hoặc "RẤT CAO".
2. Điểm rủi ro từ 0 đến 100.
3. Danh sách các dấu hiệu đáng ngờ (gạch đầu dòng cụ thể, dễ hiểu cho học sinh cấp 2).
4. Giải thích chi tiết nhưng ngắn gọn, dễ hiểu, phù hợp học sinh.
5. Danh sách các khuyến nghị xử lý an toàn (gắn với quy trình 4 bước: DỪNG -> KIỂM TRA -> XÁC MINH -> BÁO CÁO).
6. LƯU Ý PHÁP LÝ & AN TOÀN: Không được khẳng định chắc chắn 100% là lừa đảo, luôn nêu rõ đây là đánh giá dấu hiệu rủi ro.

Chỉ trả về JSON hợp lệ với cấu trúc sau:
{
  "riskLevel": "THẤP" | "TRUNG BÌNH" | "CAO" | "RẤT CAO",
  "riskScore": number (0-100),
  "suspiciousSigns": ["dấu hiệu 1", "dấu hiệu 2", ...],
  "explanation": "giải thích dễ hiểu cho học sinh",
  "recommendations": ["khuyến nghị 1", "khuyến nghị 2", ...],
  "disclaimer": "Lưu ý: Kết quả phân tích dựa trên thuật toán nhận diện và không khẳng định chắc chắn 100% một nội dung là lừa đảo. Luôn xác minh với người thật qua kênh trực tiếp."
}`;

        let response;
        if (imageBase64) {
          const cleanBase64 = imageBase64.replace(/^data:image\/[a-zA-Z]+;base64,/, '');
          response = await geminiClient.models.generateContent({
            model: 'gemini-3.8-flash',
            contents: {
              parts: [
                {
                  inlineData: {
                    mimeType: mimeType || 'image/jpeg',
                    data: cleanBase64,
                  },
                },
                { text: promptText },
              ],
            },
            config: {
              responseMimeType: 'application/json',
            },
          });
        } else {
          response = await geminiClient.models.generateContent({
            model: 'gemini-3.8-flash',
            contents: promptText,
            config: {
              responseMimeType: 'application/json',
            },
          });
        }

        const rawText = response.text || '';
        try {
          const parsed = JSON.parse(rawText);
          return res.json(parsed);
        } catch {
          // If JSON parse failed, clean and try or fallback
          const jsonMatch = rawText.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            return res.json(JSON.parse(jsonMatch[0]));
          }
        }
      } catch (geminiError) {
        console.error('Gemini API call failed, falling back to heuristic engine:', geminiError);
      }
    }

    // Heuristic Fallback
    const result = analyzeTextHeuristically(message || 'Hình ảnh đính kèm có dấu hiệu thông báo giao dịch hoặc yêu cầu nạp tiền');
    return res.json(result);
  } catch (error: any) {
    console.error('Error analyzing message:', error);
    res.status(500).json({ error: error.message || 'Lỗi xử lý hệ thống' });
  }
});

// Route: Analyze Link / URL / QR
app.post('/api/analyze-link', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'Vui lòng cung cấp đường link hoặc nội dung QR' });
    }

    const lowerUrl = url.toLowerCase().trim();
    const redFlags: string[] = [];
    let score = 20;

    // Check suspicious domain traits
    const isIpAddress = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lowerUrl);
    if (isIpAddress) {
      score += 45;
      redFlags.push('Đường link sử dụng trực tiếp địa chỉ IP số thay vì tên miền chuẩn (rất nguy hiểm)');
    }

    // Shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'cutt.ly', 'is.gd', 's.id', 'shorturl.at'];
    if (shorteners.some((s) => lowerUrl.includes(s))) {
      score += 30;
      redFlags.push('Đường link bị rút gọn nhằm che giấu trang đích thực sự');
    }

    // Brand spoofing
    const brands = ['facebook', 'garena', 'shopee', 'vietcombank', 'mbbank', 'techcombank', 'zalo', 'tiktok', 'google', 'microsoft'];
    for (const b of brands) {
      if (lowerUrl.includes(b)) {
        // Check if legit domain or spoofed
        const isLegit =
          lowerUrl.startsWith(`https://${b}.com`) ||
          lowerUrl.startsWith(`https://www.${b}.com`) ||
          lowerUrl.startsWith(`https://${b}.vn`) ||
          lowerUrl.startsWith(`https://www.${b}.vn`);
        if (!isLegit && !lowerUrl.includes(`${b}.com/`) && !lowerUrl.includes(`${b}.vn/`)) {
          score += 40;
          redFlags.push(`Có chứa tên thương hiệu quen thuộc "${b}" nhưng không phải trang web chính thức (dấu hiệu giả mạo tinh vi)`);
        }
      }
    }

    // Risky TLDs
    const riskyTlds = ['.xyz', '.top', '.club', '.online', '.tk', '.ml', '.ga', '.cf', '.buzz', '.vip', '.work', '.site'];
    if (riskyTlds.some((tld) => lowerUrl.includes(tld))) {
      score += 25;
      redFlags.push('Sử dụng đuôi tên miền giá rẻ hoặc miễn phí thường bị đối tượng lừa đảo lợi dụng');
    }

    // Sensitive keywords in URL
    if (lowerUrl.includes('login') || lowerUrl.includes('dang-nhap') || lowerUrl.includes('nhanqua') || lowerUrl.includes('tri-an') || lowerUrl.includes('kimcuong') || lowerUrl.includes('binh-chon') || lowerUrl.includes('otp')) {
      score += 30;
      redFlags.push('Đường dẫn chứa từ khóa dụ dỗ đăng nhập, nhận quà, kim cương hoặc bình chọn');
    }

    // Protocol check
    if (lowerUrl.startsWith('http://')) {
      score += 20;
      redFlags.push('Trang web không có chứng chỉ bảo mật HTTPS (giao thức HTTP không an toàn)');
    }

    score = Math.min(score, 98);
    score = Math.max(score, 10);

    let riskLevel: 'THẤP' | 'TRUNG BÌNH' | 'CAO' | 'RẤT CAO' = 'THẤP';
    if (score >= 80) riskLevel = 'RẤT CAO';
    else if (score >= 60) riskLevel = 'CAO';
    else if (score >= 35) riskLevel = 'TRUNG BÌNH';

    if (redFlags.length === 0) {
      redFlags.push('Tên miền có cấu trúc bình thường, không chứa tiền tố/hậu tố giả mạo đã biết');
    }

    return res.json({
      url,
      riskLevel,
      riskScore: score,
      suspiciousSigns: redFlags,
      explanation:
        riskLevel === 'THẤP'
          ? 'Đường link chưa có dấu hiệu bất thường rõ rệt. Tuy nhiên, trước khi điền bất kỳ thông tin cá nhân hay mật khẩu nào, em hãy kiểm tra lại thanh địa chỉ xem đúng tên miền chính thức không.'
          : `Đường link này chứa ${redFlags.length} điểm bất thường cảnh báo rủi ro cao. Rất nhiều kẻ xấu tạo ra trang web giống hệt trang thật (Phishing) để đánh cắp tài khoản Facebook, Zalo hoặc mã OTP.`,
      recommendations: [
        'DỪNG LẠI: Tuyệt đối KHÔNG bấm vào link hoặc quét mã QR nếu nguồn gửi chưa được xác thực.',
        'KIỂM TRA: Quan sát kỹ tên miền chính xác trước dấu chấm cuối cùng (ví dụ facebook.com khác với facebook-quatang.xyz).',
        'XÁC MINH: Hỏi lại trực tiếp người gửi xem tài khoản của họ có bị hack nick tự động gửi link lạ không.',
        'BÁO CÁO: Báo cho thầy cô, phụ huynh hoặc tính năng báo cáo spam trên mạng xã hội.',
      ],
      disclaimer:
        'Lưu ý quan trọng: Phân tích dựa trên kỹ thuật đánh giá cấu trúc tên miền và không khẳng định chắc chắn 100% độ an toàn hay nguy hiểm tuyệt đối. Em hãy luôn cẩn trọng khi truy cập liên kết lạ!',
    });
  } catch (error: any) {
    console.error('Error analyzing link:', error);
    res.status(500).json({ error: error.message || 'Lỗi xử lý đường link' });
  }
});

// Route: Analyze Scenario with AI
app.post('/api/analyze-scenario', async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!description) {
      return res.status(400).json({ error: 'Vui lòng cung cấp mô tả tình huống' });
    }

    if (geminiClient) {
      try {
        const prompt = `Bạn là Chuyên gia An toàn số tại trường THCS Xà Phiên. Hãy phân tích tình huống lừa đảo sau đây mà học sinh hoặc gia đình có thể gặp phải:

Tiêu đề: ${title || 'Tình huống thực tế'}
Chi tiết tình huống: "${description}"

Hãy phân tích và trả về định dạng JSON:
{
  "riskLevel": "THẤP" | "TRUNG BÌNH" | "CAO" | "RẤT CAO",
  "riskScore": number (0-100),
  "suspiciousSigns": ["dấu hiệu lừa đảo cụ thể 1", "dấu hiệu 2", ...],
  "psychologicalTrick": "Thủ đoạn tâm lý mà kẻ lừa đảo đang sử dụng (ví dụ: đánh vào lòng tham, nỗi sợ hãi công an, tình cảm gia đình, áp lực thời gian)",
  "explanation": "Lời giải thích dễ hiểu, gần gũi với học sinh THCS",
  "stepByStepAction": [
    "Bước 1 - DỪNG: ...",
    "Bước 2 - KIỂM TRA: ...",
    "Bước 3 - XÁC MINH: ...",
    "Bước 4 - BÁO CÁO: ..."
  ],
  "disclaimer": "Lưu ý quan trọng: Phân tích chỉ mang tính chất định hướng an toàn phòng ngừa và không thể khẳng định chắc chắn 100% trong mọi trường hợp. Học sinh cần tham vấn người lớn tin cậy."
}`;

        const response = await geminiClient.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
          },
        });

        const raw = response.text || '';
        try {
          return res.json(JSON.parse(raw));
        } catch {
          const match = raw.match(/\{[\s\S]*\}/);
          if (match) return res.json(JSON.parse(match[0]));
        }
      } catch (err) {
        console.error('Gemini scenario error, fallback to rule engine:', err);
      }
    }

    // Heuristic Fallback for scenario
    const base = analyzeTextHeuristically(description);
    return res.json({
      riskLevel: base.riskLevel,
      riskScore: base.riskScore,
      suspiciousSigns: base.suspiciousSigns,
      psychologicalTrick:
        'Kẻ xấu đang lợi dụng tâm lý lo sợ bị kỷ luật/vướng pháp luật hoặc sự vội vàng tin tưởng người thân để ép nạn nhân chuyển tiền.',
      explanation: base.explanation,
      stepByStepAction: [
        'Bước 1 - DỪNG: Không nghe máy tiếp, không làm theo bất kỳ yêu cầu chuyển khoản nào.',
        'Bước 2 - KIỂM TRA: Ghi nhớ số điện thoại gọi đến, chụp lại màn hình tin nhắn.',
        'Bước 3 - XÁC MINH: Gọi số điện thoại chính thức của thầy cô, nhà trường hoặc bố mẹ để đối chiếu sự thật.',
        'Bước 4 - BÁO CÁO: Báo cho Đoàn Đội nhà trường THCS Xà Phiên hoặc Tổng đài 111 để được hỗ trợ.',
      ],
      disclaimer: base.disclaimer,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Lỗi phân tích tình huống' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    appName: 'AI SCAM CHECK – THCS XÀ PHIÊN',
    geminiActive: !!geminiClient,
  });
});

// Setup Vite middleware in dev or static files in production
async function startServer() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port} in ${isDev ? 'development' : 'production'} mode`);
  });
}

startServer();
