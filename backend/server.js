import db from "./db.js";
import fs from "fs";
import express from "express";
import dotenv from "dotenv";
import OpenAI from "openai";
import cors from "cors";

dotenv.config();

const app = express();

app.use(cors({
  origin: ["http://127.0.0.1:5500", "http://localhost:5500"],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));
app.use(express.json());

const scoringRules = JSON.parse(fs.readFileSync("./phishing_rules.json", "utf-8"));

// ✅ detectors 자동 생성 + evaluator 생성 (server.js 안에서 사용)

function normalize(text) {
  return String(text)
    .replace(/\s+/g, "")
    .replace(/[._]/g, "")
    .toLowerCase();
}

function makeKeywordDetector(keywords) {
  const list = (keywords || []).filter(Boolean);
  return (raw) => list.some((k) => raw.includes(k));
}

function makeRegexDetector(regexOrFn) {
  if (typeof regexOrFn === "function") return regexOrFn;
  return (raw) => regexOrFn.test(raw);
}

function buildDetectorsFromRules(scoringRules) {
  const eventSet = new Set();

  for (const rules of Object.values(scoringRules || {})) {
    if (!Array.isArray(rules)) continue;
    for (const r of rules) {
      if (r?.event) eventSet.add(r.event);
    }
  }

  const keywordLibrary = {
    // === ROMANCE SCAM DETECTORS ===
    early_emotional_involvement: ["보고싶", "좋아해", "사랑", "운명", "너밖에", "매일 생각", "특별한 사이", "마음이 가", "의지하고 싶"],
    moved_to_external_messenger: ["카톡", "카카오톡", "텔레그램", "라인", "왓츠앱", "인스타", "디엠", "dm", "메신저로", "번호 알려"],
    accepted_no_meeting_or_no_video_call: ["괜찮아", "이해해", "나중에", "상관없어", "영상통화 말고", "만나는 건 나중", "바쁘니까"],
    accepted_pity_or_crisis_story: ["불쌍", "안타깝", "마음 아파", "힘들겠다", "괜찮아?", "도와주고 싶", "걱정돼"],
    attempted_identity_verification: ["확인해", "검증", "증명", "신분증", "여권", "검색해볼", "사진 보내", "실명"],
    requested_real_time_video_call: ["영상통화", "페이스타임", "지금 통화", "실시간으로", "캠 켜", "화상통화"],
    refused_money_or_investment_request: ["돈은 못", "송금 못", "보내기 싫", "안 보낼", "금전적인 건 안", "투자는 안"],
    questioned_fast_emotional_attachment: ["너무 빨라", "갑작스럽", "이상한데", "아직 잘 모르", "왜 이렇게 빨리"],
    insisted_on_meeting_before_continuing: ["만나고", "직접 보고", "보기 전엔", "확인 전엔", "검증 없이는"],
    noticed_inconsistencies_in_personal_story: ["말이 다른데", "아까랑 다르", "앞뒤가 안 맞", "설명이 바뀌", "이상해"],
    paused_relationship_progress_for_verification: ["일단 멈추", "천천히", "확인하고", "검증부터", "지켜보자"],
    explicitly_mentioned_romance_scam: ["로맨스 스캠", "연애 사기", "사기 같아"],
    ended_relationship_due_to_suspicion: ["그만하자", "연락하지 마", "차단할게", "끝내자", "대화 종료"],


    name_provided: ["이름은", "성함은", "제 이름", "제이름"],
    address_provided: ["주소", "배송지", "사는 곳", "사는곳"],
    phone_partial_provided: ["전화번호", "연락처", "010", "011", "016", "017", "018", "019"],
    phone_info_provided: ["전화번호", "연락처", "010", "011", "016", "017", "018", "019"],

    clicked_link: ["클릭", "눌렀", "접속", "들어갔", "열었", "링크"],
    typed_personal_information: ["입력", "작성", "기입", "적었"],
    verification_link_or_process_accepted: ["인증", "확인했", "진행", "설치", "동의", "완료"],

    mentioned_checking_official_app_or_website: ["공식 앱", "공식앱", "홈페이지", "공식 사이트", "공식사이트"],
    stated_calling_official_customer_service: ["고객센터", "대표번호", "전화하겠", "전화해볼", "콜센터"],

    asked_for_sender_or_order_details: ["어떤 상품", "무슨 상품", "발송인", "주문", "주문내역", "운송장", "송장번호"],
    asked_for_case_number_or_department: ["사건번호", "접수번호", "담당부서", "부서명", "담당자"],
    requested_face_to_face_or_office_visit: ["직접 방문", "방문하겠", "대면", "가겠습니다", "가볼게요"],

    refused_to_provide_personal_information: ["거절", "제공 못", "안 알려", "못 알려", "말 못"],
    explicitly_ended_conversation: ["그만", "종료", "끊", "차단"],
    conversation_stopped_or_blocked: ["차단", "신고", "대화 중단", "끊었"],
    blocked_or_reported_sender: ["차단", "신고"],

    warned_about_link_risk: ["링크 위험", "수상", "피싱", "사기"],
    explicitly_called_out_scam: ["사기", "피싱", "보이스피싱", "스캠"],

    responded_to_money_or_investment_request: ["송금", "이체", "돈 보내", "입금", "계좌"],

    accepted_link_or_app_install: ["설치", "앱", "다운로드", "원격"],
    refused_app_install_or_remote_control: ["설치 안", "설치 못", "원격 안", "원격 못", "거절"],
  };

  const regexByEvent = {
    typed_personal_information: (raw) => {
  const n = normalize(raw);

  // 주민번호(13자리 or 6-7 형태)
  const rrn = /\b\d{6}-?\d{7}\b/.test(raw) || /\b\d{13}\b/.test(n);

  //계좌번호(은행별 다양해서 폭넓게: 9~16자리, 하이픈 포함)
  const acct = (/(계좌|은행|입금|송금)/.test(raw) && /\b\d{9,16}\b/.test(n))
          || /\b\d{2,4}-\d{2,6}-\d{2,6}\b/.test(raw);

  // 전화번호(이미 별도 이벤트 있어도, 개인정보 입력으로도 잡히게)
  const phone = /01[016789]\d{7,8}/.test(n);

  return rrn || acct || phone;
},
    phone_partial_provided: /01[016789]\s*-?\s*\d{3,4}\s*-?\s*\d{4}/,
    clicked_link: /(https?:\/\/|www\.)|(클릭|눌렀|접속|들어갔|열었|링크)/,
    responded_to_money_or_investment_request: /(송금|이체|입금|돈\s*보내|계좌)/,
    explicitly_ended_conversation: /(그만|종료|끊|차단)/,
    mentioned_checking_official_app_or_website: /(공식\s*(앱|홈페이지|사이트)|대표번호)/,
    explicitly_called_out_scam: /(사기|피싱|보이스피싱|스캠)/,
    rrn_provided: /\b\d{6}-?\d{7}\b/,
    account_provided: /\b\d{2,4}-\d{2,6}-\d{2,6}\b|\b\d{9,16}\b/,
    // === ROMANCE SCAM REGEX ===
early_emotional_involvement: /(보고\s*싶|사랑|좋아해|운명|너\s*밖에|매일\s*생각)/,

moved_to_external_messenger: /(카톡|카카오톡|텔레그램|라인|왓츠앱|인스타|dm|디엠|번호\s*알려)/,

accepted_no_meeting_or_no_video_call: /(영상\s*통화.*(안|말고)|만나.*나중|괜찮아|이해해)/,

accepted_pity_or_crisis_story: /(불쌍|안타깝|힘들겠|마음\s*아파|도와주고)/,

attempted_identity_verification: /(신분증|여권|증명|검증|확인\s*해|검색해)/,

requested_real_time_video_call: /(영상\s*통화|화상\s*통화|페이스\s*타임|지금\s*통화|실시간)/,

refused_money_or_investment_request: /(돈.*못|송금.*못|안\s*보낼|금전.*안)/,

questioned_fast_emotional_attachment: /(너무\s*빠르|갑작|이상한데|왜\s*이렇게\s*빨리)/,

insisted_on_meeting_before_continuing: /(만나.*전|직접\s*보고|검증\s*없이는)/,

noticed_inconsistencies_in_personal_story: /(말이\s*다르|앞뒤.*안\s*맞|설명.*바뀌)/,

paused_relationship_progress_for_verification: /(일단\s*멈추|천천히|확인.*먼저)/,

explicitly_mentioned_romance_scam: /(로맨스\s*스캠|연애\s*사기)/,

ended_relationship_due_to_suspicion: /(그만하자|차단|연락\s*하지\s*마|끝내자)/,


  };

  function autoKeywordsFromEventName(eventName) {
    const e = String(eventName || "").toLowerCase();
    if (e.includes("link")) return ["링크", "url", "클릭", "눌렀", "접속"];
    if (e.includes("phone")) return ["전화", "연락처", "010"];
    if (e.includes("address")) return ["주소", "배송지"];
    if (e.includes("money") || e.includes("account")) return ["송금", "이체", "계좌", "입금", "돈"];
    if (e.includes("official") || e.includes("callcenter") || e.includes("customer")) return ["공식", "홈페이지", "고객센터", "대표번호"];
    if (e.includes("refuse") || e.includes("denied")) return ["거절", "못", "안"];
    if (e.includes("ended") || e.includes("blocked") || e.includes("stopped")) return ["종료", "그만", "차단", "신고", "끊"];
    if (e.includes("case") || e.includes("department") || e.includes("document")) return ["사건", "부서", "공문"];
    if (e.includes("video")) return ["영상통화", "비디오"];
    return [];
  }

  const detectors = {};
  for (const eventName of eventSet) {
    if (regexByEvent[eventName]) {
      detectors[eventName] = makeRegexDetector(regexByEvent[eventName]);
      continue;
    }
    if (keywordLibrary[eventName]) {
      detectors[eventName] = makeKeywordDetector(keywordLibrary[eventName]);
      continue;
    }
    const guessed = autoKeywordsFromEventName(eventName);
    detectors[eventName] = makeKeywordDetector(guessed);
  }

  return { detectors, eventList: Array.from(eventSet).sort() };
}

function makeEvaluator(scoringRules) {
  const { detectors } = buildDetectorsFromRules(scoringRules);

  return function evaluateMessage({ message, scenarioKey }) {
    let totalScore = 0;
    const triggeredEvents = [];

    const applicableRules = [
      ...(scoringRules[scenarioKey] || []),
      ...(scoringRules.common || []),
    ];

    for (const rule of applicableRules) {
      const ev = rule.event;
      const detect = detectors[ev];
      if (!detect) continue;

      const hit = detect(message);
      if (!hit) continue;

      totalScore += rule.weight;
      triggeredEvents.push({
        code: rule.code,
        event: ev,
        weight: rule.weight,
        description: rule.description,
      });
    }

    totalScore = Number(totalScore.toFixed(2));
    return { scoreDelta: totalScore, events: triggeredEvents };
  };
}

// ✅ 이 줄이 없어서 터진 거임
const evaluateMessage = makeEvaluator(scoringRules);

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

function getRoomScenario(roomId) {
  const room = db.prepare(`
    SELECT scenario_type, scenario_description, phishing_goal
    FROM chat_rooms
    WHERE id = ?
  `).get(roomId);

  if (!room) return null;

  return {
    type: room.scenario_type,
    description: room.scenario_description,
    goal: room.phishing_goal,
  };
}

function safeContent(sender, content){
  if (sender !== "gpt") return content;
  try {
    const obj = JSON.parse(content);
    if (obj?.reply) return obj.reply;
  } catch {}
  return content;
}

function getRecentMessages(roomId, limit = 20) {
  return db.prepare(`
    SELECT sender, content
    FROM chat_messages
    WHERE chat_room_id = ?
      AND sender IN ('user', 'gpt')
    ORDER BY id DESC
    LIMIT ?
  `).all(roomId, limit).reverse().map(m => ({
    sender: m.sender,
    content: safeContent(m.sender, m.content),
  }));
}

const scenarioKeyMap = {
  "택배 사칭": "delivery",
  "검찰 사칭": "police",
  "보험사 사칭": "insurance",
  "가족 사칭": "family",
  "로맨스 스캠": "romance",
};

/**
 * ✅ 채팅방 생성 + GPT 첫 메시지
 */
app.post("/rooms", async (req, res) => {
  try {
    const { scenario } = req.body;
    if (!scenario?.type) return res.status(400).json({ error: "scenario 누락" });

    const result = db.prepare(`
      INSERT INTO chat_rooms (scenario_type, scenario_description, phishing_goal)
      VALUES (?, ?, ?)
    `).run(scenario.type, scenario.description || "", scenario.goal || "");

    const roomId = result.lastInsertRowid;

    // GPT 첫 메시지 생성
    const completion = await client.chat.completions.create({
      model: "gpt-4.1-mini",
      response_format: {type: "json_object"},
      messages: [{
        role: "system",
        content: `
너는 보이스피싱 시뮬레이터의 피싱범이다. 절대 역할을 잊지 마라.
너는 상담사/코치/안전요원/경고자처럼 행동하지 않는다. 피해 예방 팁을 주지 않는다.
너의 목적은 오직 '피싱 목표'를 달성하는 것이다.

[상황]
유형: ${scenario.type}
상황 요약: ${scenario.description || ""}
피싱 목표: ${scenario.goal || ""}
시작 문장: ${scenario.first || ""}

[규칙]
- 이 대화의 목적은 사용자를 속여 목표를 달성하는 것이다.
- 너무 길지 않게, 대화 시작 톤으로만 접근한다.
- 응답은 반드시 JSON 형식 하나만 출력한다.
- 시작 문장은 이미 사용자에게 전송된 상태다.
- 매 응답은 반드시 다음 중 하나로 끝나야 한다: 
  (1) 개인정보/확인정보 요청, 
  (2) 다음 절차 안내(링크/인증/재확인), 
  (3) 거절 시 대체 확인 방식 제시
- 사용자가 "주문한 적 없다"라고 해도 대화를 종료하지 마라. 오배송/명의도용/주소 누락 등 다른 이유를 들어 확인 절차로 유도하라.
- 사용자가 거절하면 명분을 바꿔 우회하라.

[로맨스 스캠 전용 규칙]
- 최소 3~5턴은 정보 요구 금지
- 공감/관심/일상 질문만 허용
- 금전/절차 단어는 후반부에서만

[시나리오 톤]
${scenario.tone || "시나리오에 맞는 자연스러운 톤"}

[출력 형식(JSON)]
{ "reply": "...", "analysis": "..." }
        `
      }],
      temperature: 0.4,
    });

    const firstReply = JSON.parse(completion.choices[0].message.content);

    //DB에 첫 메시지 저장
    db.prepare(`
      INSERT INTO chat_messages (chat_room_id, sender, content)
      VALUES (?, ?, ?)
    `).run(roomId, "gpt", firstReply.reply);
    
    //프론트로 roomId + firstMessage 반환
    return res.json({ roomId, firstMessage: firstReply.reply });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "채팅방 생성 실패" });
  }
});

/*
 * ✅ 유저 메시지 → GPT 답장
 */
app.post("/chat", async (req, res) => {
  try {
    const { message, roomId } = req.body;

    if (!roomId) return res.status(400).json({ error: "roomId 누락" });
    if (!message) return res.status(400).json({ error: "message 누락" });

    const scenario = getRoomScenario(roomId);
    if (!scenario) return res.status(404).json({ error: "채팅방(roomId) 없음" });

    const scenarioKey = scenarioKeyMap[scenario.type];
    if (!scenarioKey) return res.status(400).json({ error: `시나리오 매핑 실패: ${scenario.type}` });

    const evaluation = evaluateMessage({ message, scenarioKey });

    // 유저 메시지 저장
    db.prepare(`
      INSERT INTO chat_messages (chat_room_id, sender, content)
      VALUES (?, ?, ?)
    `).run(roomId, "user", message);

    // 히스토리 로드
    const history = getRecentMessages(roomId, 10);

    const completion = await client.chat.completions.create({
      model: "gpt-4.1-mini",
      response_format: {type: "json_object"},
      messages: [
        {
          role: "system",
          content: `
          너는 보이스피싱 시뮬레이터의 피싱범이다. 절대 역할을 잊지 마라.
          너는 고객센터/상담원처럼 행동하지 않는다. "죄송합니다/취소/문의/도움" 같은 정상 CS 마무리를 금지한다.
          너의 목적은 오직 '피싱 목표'를 달성하는 것이다.

          [상황]
          유형: ${scenario.type}
          상황 요약: ${scenario.description || ""}
          피싱 목표: ${scenario.goal || ""}

          [규칙]
          - 매 응답은 반드시 다음 중 하나로 끝나야 한다:
            (1) 개인정보/확인정보 요청
            (2) 다음 절차 안내(링크/인증/설치/재확인)
            (3) 거절 시 대체 확인 방식 제시
          - 사용자가 "주문한 적 없다/없다"라고 해도 대화를 종료하지 마라.
          - 같은 요구를 2번 반복하지 마라. 거절하면 명분을 바꿔 우회하라.
          - 1~2문장으로 짧게.
          - 출력은 JSON 하나: { "reply": "...", "analysis": "..." }

          [로맨스 스캠 전용 규칙]
          - 최소 3~5턴은 정보 요구 금지
          - 공감/관심/일상 질문만 허용
          - 금전/절차 단어는 후반부에서만

          [시나리오 톤]
          ${scenario.tone || "시나리오에 맞는 자연스러운 톤"}
          `
        },
        ...history.map((m) => ({
          role: m.sender === "user" ? "user" : "assistant",
          content: m.content,
        })),
      ],
      temperature: 0.7,
    });

    const gptReply = JSON.parse(completion.choices[0].message.content);

    // GPT 메시지 저장
    db.prepare(`
      INSERT INTO chat_messages (chat_room_id, sender, content)
      VALUES (?, ?, ?)
    `).run(roomId, "gpt", gptReply.reply);

    // 평가 저장(임시): system으로 저장
    db.prepare(`
      INSERT INTO chat_messages (chat_room_id, sender, content)
      VALUES (?, ?, ?)
    `).run(roomId, "system", JSON.stringify({ evaluation }));

    return res.json({ reply: gptReply.reply, evaluation });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "GPT 응답 실패" });
  }
});

app.get("/rooms/:roomId/messages", (req, res) => {
  try {
    const { roomId } = req.params;

    const messages = db.prepare(`
      SELECT sender, content, created_at
      FROM chat_messages
      WHERE chat_room_id = ?
      ORDER BY id ASC
    `).all(roomId);

    return res.json({ roomId, messages });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "메시지 조회 실패" });
  }
});

app.listen(3000, () => console.log("서버 실행됨: http://localhost:3000"));

// ✅ system 메시지에 저장된 evaluation들 가져오기
function getEvaluations(roomId) {
  const rows = db.prepare(`
    SELECT content
    FROM chat_messages
    WHERE chat_room_id = ?
      AND sender = 'system'
    ORDER BY id ASC
  `).all(roomId);

  const evaluations = [];
  for (const r of rows) {
    try {
      const parsed = JSON.parse(r.content);
      if (parsed?.evaluation) evaluations.push(parsed.evaluation);
    } catch (_) {
      // system 메시지에 evaluation 말고 다른 텍스트가 섞여있어도 무시
    }
  }
  return evaluations;
}

function aggregateEvaluations(evaluations) {
  let total = 0;
  const eventCounts = {};   // event -> count
  const codeCounts = {};    // code -> count
  const eventWeights = {};  // event -> sum(weight)

  for (const e of evaluations) {
    const scoreDelta = Number(e?.scoreDelta || 0);
    total += scoreDelta;

    const events = Array.isArray(e?.events) ? e.events : [];
    for (const ev of events) {
      const event = ev.event || "unknown";
      const code = ev.code || "unknown";
      const w = Number(ev.weight || 0);

      eventCounts[event] = (eventCounts[event] || 0) + 1;
      codeCounts[code] = (codeCounts[code] || 0) + 1;
      eventWeights[event] = (eventWeights[event] || 0) + w;
    }
  }

  // 상위 이벤트 뽑기(가중치 합 기준)
  const topEvents = Object.entries(eventWeights)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([event, weightSum]) => ({
      event,
      weightSum: Number(weightSum.toFixed(2)),
      count: eventCounts[event] || 0,
    }));

  const totalScore = Number(total.toFixed(2));
  return {
    totalScore,
    topEvents,
    eventCounts,
    codeCounts,
  };
}

function scoreToGrade(totalScore) {
  // 점수 체계가 음수/양수 섞일 수 있으니 “위험도” 레벨을 대충 안전하게 매핑
  // (원하는 기준 있으면 여기만 바꾸면 됨)
  if (totalScore >= 0.8) return { level: "HIGH", label: "위험", emoji: "🚨" };
  if (totalScore >= 0.3) return { level: "MEDIUM", label: "주의", emoji: "⚠️" };
  return { level: "LOW", label: "양호", emoji: "✅" };
}

function buildRuleBasedFeedback({ scenarioType, scenarioKey, stats }) {
  const { topEvents } = stats;
  const grade = scoreToGrade(stats.totalScore);

  const eventKorean = {
    name_provided: "이름 제공",
    address_provided: "주소 제공",
    phone_partial_provided: "전화번호/일부 제공",
    verification_link_or_process_accepted: "링크 클릭/인증 절차 수락",
    refused_to_provide_personal_information: "개인정보 제공 거절",
    mentioned_checking_official_app_or_website: "공식 채널 확인 언급",
    explicitly_ended_conversation: "대화 종료/차단",
    responded_to_money_or_investment_request: "송금/금전 요구에 반응",

    // ✅ ROMANCE 전용 이벤트(RO1~RO14) 표시명
    early_emotional_involvement: "빠른 감정 몰입 표현",
    moved_to_external_messenger: "외부 메신저 이동",
    accepted_no_meeting_or_no_video_call: "만남/영상통화 회피 수용",
    accepted_pity_or_crisis_story: "위기/불쌍함 스토리 수용",
    attempted_identity_verification: "신원 검증 시도",
    requested_real_time_video_call: "실시간 영상통화 요구",
    refused_money_or_investment_request: "금전/도움 요청 거부",
    questioned_fast_emotional_attachment: "빠른 감정 몰입 의문 제기",
    insisted_on_meeting_before_continuing: "만남/검증 없이는 진행 거부",
    noticed_inconsistencies_in_personal_story: "스토리 불일치 지적",
    paused_relationship_progress_for_verification: "관계 진전 중단 후 확인 우선",
    explicitly_mentioned_romance_scam: "로맨스 스캠 가능성 언급",
    ended_relationship_due_to_suspicion: "의심으로 관계/대화 종료",
  };

  const top = topEvents.length
    ? topEvents
        .map(
          (t) =>
            `- ${eventKorean[t.event] || t.event} (횟수 ${t.count}, 영향도 합 ${t.weightSum})`
        )
        .join("\n")
    : "- (감지된 이벤트 없음)";

  // 시나리오별 핵심 팁
  const scenarioTips = {
    delivery: [
      "택배/배송 문제는 송장번호를 공식 택배사 앱/홈페이지에서만 조회하세요.",
      "'보관료 발생', '추가 비용 결제' 요구는 거의 사기입니다.",
      "이름, 주소를 묻는 택배사는 정상적인 절차가 아닙니다. 정상 택배사는 대부분 송장 번호를 먼저 제시합니다.",
    ],
    police: [
      "정부 기관은 문자나 SNS로 공문서를 결코 보내지 않습니다.",
      "‘외부 유출 방지’라며 비밀 유지 요구는 사기 패턴입니다. 또한, 신분증 사진 제출 요구는 매우 위험합니다.",
      "공식 기관은 문자메시지에 인증마크가 있습니다.",
    ],
    insurance: [
      "보험사는 주민번호 전체를 요구하지 않고, 환급/만료 안내인데 보험 상품명·가입 시기를 정확히 말 못 하면 의심하세요.",
      "보험사는 계좌 변경을 전화로만 처리하지 않고, 관련 업무는 공식 앱 또는 고객센터 직접 접속이 원칙입니다.",
      "문자 링크로 보험금 조회·환급 신청을 유도하면 위험합니다.",
    ],
    family: [
      "평소에 가족간의 '확인용 암호'를 미리 정해두면 좋습니다.",
      "말투, 이모지, 호칭이 평소와 조금이라도 다르면 의심하세요.",
      "소액부터 요청하는 것도 심리적 장벽을 낮추는 전략입니다.",
    ],
    romance: [
      "해외 거주, 군인, 의사 설정은 매우 흔한 사기 클리셰이며, 짧은 시간 안에 감정적으로 가까워지면 경계하세요.",
      "영상통화를 계속 피하면 실제 인물이 아닐 가능성이 큽니다.",
      "금전 요청 전 ‘신뢰 테스트’, ‘우리 미래’, ‘믿음 테스트’ 같은 말은 감정 압박 수법입니다.",
    ],
  };

  const tips = (scenarioTips[scenarioKey] || [
    "의심 링크 클릭 금지.",
    "개인정보 제공 금지.",
    "공식 채널로 역확인.",
  ]).map((t) => `- ${t}`).join("\n");


  const PERSONAL_INFO_EVENTS = [
  "name_provided",
  "phone_partial_provided",
  "phone_info_provided",
  "address_provided",
  "rrn_provided",
  "account_provided",
  "typed_personal_information",
];

const OFFICIAL_CHECK_EVENTS = [
  "mentioned_checking_official_app_or_website",
  "stated_calling_official_customer_service",
];

const REFUSAL_EVENTS = [
  "refused_to_provide_personal_information",
  "refused_app_install_or_remote_control",
];

const STOP_EVENTS = [
  "explicitly_ended_conversation",
  "conversation_stopped_or_blocked",
  "blocked_or_reported_sender",
];

const AWARENESS_EVENTS = [
  "warned_about_link_risk",
  "explicitly_called_out_scam",
];

const SAFE_QUESTION_EVENTS = [
  "asked_for_sender_or_order_details",
  "asked_for_case_number_or_department",
  "requested_face_to_face_or_office_visit",
];

const ROMANCE_RISK_EVENTS = [
    "early_emotional_involvement",
    "moved_to_external_messenger",
    "accepted_no_meeting_or_no_video_call",
    "accepted_pity_or_crisis_story",
  ];

const ROMANCE_DEFENSE_EVENTS = [
  "attempted_identity_verification",
  "requested_real_time_video_call",
  "refused_money_or_investment_request",
  "questioned_fast_emotional_attachment",
  "insisted_on_meeting_before_continuing",
  "noticed_inconsistencies_in_personal_story",
  "paused_relationship_progress_for_verification",
  "explicitly_mentioned_romance_scam",
  "ended_relationship_due_to_suspicion",
];

function buildFeedback(stats) {
  const didWell = [];
  const improve = [];

  const counts = stats?.eventCounts || {};
  const has = (k) => (counts[k] || 0) > 0;

  const pushOnce = (arr, msg) => {
    if (!arr.includes(msg)) arr.push(msg);
  };

  /* =========================
     ✅ 잘한 점 (detected → 바로 칭찬)
  ========================= */

  // 공식 채널 확인
  if (OFFICIAL_CHECK_EVENTS.some(has)) {
    pushOnce(didWell, "공식 채널(앱/홈페이지/대표번호/고객센터)로 확인하려 한 점이 좋았습니다.");
  }

  // 거절(개인정보/설치/원격)
  if (REFUSAL_EVENTS.some(has)) {
    pushOnce(didWell, "개인정보 제공이나 앱 설치·원격제어 요청을 거절한 대응이 매우 적절했습니다.");
  }

  // 대화 종료/차단/신고
  if (STOP_EVENTS.some(has)) {
    pushOnce(didWell, "대화를 종료하거나 차단/신고한 선택은 피해를 크게 줄였습니다.");
  }

  // 위험 인지(피싱 경고/사기 지적)
  if (AWARENESS_EVENTS.some(has)) {
    pushOnce(didWell, "피싱/사기 가능성을 먼저 짚은 판단이 좋았습니다.");
  }

  // “정보 더 달라” 같은 안전한 되물음(상대 정체 확인에 도움)
  if (SAFE_QUESTION_EVENTS.some(has)) {
    pushOnce(didWell, "발송인/주문/사건번호 등 구체 정보를 요구한 건 상대를 압박하고 검증에 도움 됩니다.");
  }

  // ✅ 로맨스: 신원 검증 시도
  if (has("attempted_identity_verification")) {
    pushOnce(didWell, "신원 검증을 시도한 대응이 좋았습니다. 로맨스 스캠에서 가장 효과적인 방어 축입니다.");
  }

  // ✅ 로맨스: 영상통화 요구
  if (has("requested_real_time_video_call")) {
    pushOnce(didWell, "실시간 영상통화를 명확히 요구한 점이 좋았습니다. 회피하면 의심 근거가 더 강해집니다.");
  }

  // ✅ 로맨스: 금전/도움 거부
  if (has("refused_money_or_investment_request")) {
    pushOnce(didWell, "금전/도움 요청을 명확히 거부한 대응이 매우 적절했습니다.");
  }

  // ✅ 로맨스: 빠른 몰입 의문/관계 중단/스캠 언급/종료
  if (has("questioned_fast_emotional_attachment")) {
    pushOnce(didWell, "감정선이 너무 빠른 점을 의심한 판단이 좋았습니다.");
  }

  if (has("paused_relationship_progress_for_verification")) {
    pushOnce(didWell, "관계 진전을 멈추고 확인을 우선한 선택이 좋았습니다.");
  }

  if (has("explicitly_mentioned_romance_scam")) {
    pushOnce(didWell, "로맨스 스캠 가능성을 직접 언급한 건 상대의 심리전을 끊는 데 효과적입니다.");
  }

  if (has("ended_relationship_due_to_suspicion")) {
    pushOnce(didWell, "의심을 이유로 관계/대화를 종료한 선택은 최상급 대응입니다.");
  }

  /* =========================
     ⚠️ 개선할 점 (detected → 무조건 추가)
  ========================= */

  // 개인정보 제공 — 하나라도 있으면 무조건
  if (PERSONAL_INFO_EVENTS.some(has)) {
    pushOnce(
      improve,
      "이름·전화번호·주소·계좌 등 개인정보가 제공되었습니다. 이런 정보는 조합되는 순간 본인확인에 바로 악용됩니다."
    );
  }

  // 링크/인증/설치(위험 트리거)
  if (has("clicked_link") || has("verification_link_or_process_accepted") || has("accepted_link_or_app_install")) {
    pushOnce(improve, "링크 클릭/인증 진행/앱 설치는 가장 위험한 행동입니다.");
  }

  // 금전 요구 반응
  if (has("responded_to_money_or_investment_request")) {
    pushOnce(improve, "금전 요구에 반응하는 순간 사기 성공 확률이 급상승합니다. 즉시 대화를 종료해야 합니다.");
  }

  if (has("early_emotional_involvement")) {
    pushOnce(improve, "짧은 시간 안에 감정적으로 깊게 반응하면 상대가 심리적 레버리지를 잡기 쉬워집니다.");
  }

  // ✅ 로맨스: 외부 메신저 이동(RO2)
  if (has("moved_to_external_messenger")) {
    pushOnce(improve, "외부 메신저로 이동하면 신고/증거 확보가 어려워지고, 본격적인 사기 전개로 넘어가기 쉽습니다.");
  }

  // ✅ 로맨스: 만남/영상통화 회피 수용(RO4)
  if (has("accepted_no_meeting_or_no_video_call")) {
    pushOnce(improve, "만남/영상통화 회피를 받아주면 ‘실존 검증’이 사라져 위험도가 커집니다.");
  }

  // ✅ 로맨스: 위기/불쌍함 스토리 수용(RO5)
  if (has("accepted_pity_or_crisis_story")) {
    pushOnce(improve, "위기·불쌍함 스토리에 빨리 반응하면 ‘도움(=돈)’으로 자연스럽게 연결됩니다.");
  }

  /* =========================
     🧯 안전장치(비어있을 때 기본 문구)
  ========================= */
  if (didWell.length === 0) {
    pushOnce(didWell, "뚜렷한 방어 행동은 감지되지 않았습니다. 다음엔 공식 채널 확인/거절/차단 같은 액션을 넣어보세요.");
  }

  if (improve.length === 0) {
    pushOnce(improve, "치명적인 실수는 감지되지 않았습니다. 그래도 의심 상황에서는 더 빠르게 대화를 종료하는 게 안전합니다.");
  }

  return { didWell, improve };
}


  const {didWell, improve} = buildFeedback(stats);

  const didWellText = didWell.length ? didWell.map((x) => `- ${x}`).join("\n") : "- (특별히 감지된 방어 행동은 적었습니다.)";
  const improveText = improve.length ? improve.map((x) => `- ${x}`).join("\n") : "- (치명적인 실수는 크게 감지되지 않았습니다.)";
  const risk = Math.max(0, stats.totalScore);
  const score100 = Math.max(0, 100 - Math.round(risk * 100));

  return {
    grade,
    summary: `${grade.emoji} 최종 평가: ${grade.label}(${grade.level}) / 총점: ${score100}`,
    topEventsText: top,
    didWellText,
    improveText,
    score100,
    tipsText: tips,
    oneLiner: grade.level === "HIGH"
      ? "한 줄로 말하면: 지금 패턴이면 실제 사기에서도 털릴 확률 높습니다. 다음 판은 ‘공식 채널 역확인’부터 고정하세요."
      : grade.level === "MEDIUM"
      ? "한 줄로 말하면: 방어는 했는데, 몇 번은 문이 열렸습니다. ‘링크/인증’만 끊으면 급상승합니다."
      : "한 줄로 말하면: 기본기는 좋습니다. ‘압박+링크+개인정보’ 3종 세트만 계속 피하세요.",
  };
}
/**
 * ✅ 대화 종료 → 최종 평가 + 피드백 반환
 * 프론트에서 "종료" 버튼 누를 때 호출하면 됨.
 */
app.post("/rooms/:roomId/end", async (req, res) => {
  try {
    const { roomId } = req.params;

    const scenario = getRoomScenario(roomId);
    if (!scenario) return res.status(404).json({ error: "채팅방(roomId) 없음" });

    const scenarioKey = scenarioKeyMap[scenario.type];
    if (!scenarioKey) return res.status(400).json({ error: `시나리오 매핑 실패: ${scenario.type}` });

    const evaluations = getEvaluations(roomId);
    const stats = aggregateEvaluations(evaluations);

    const feedback = buildRuleBasedFeedback({
      scenarioType: scenario.type,
      scenarioKey,
      stats,
    });

    // 원하면 DB에도 “최종 결과”를 system 메시지로 저장(나중에 다시 조회 가능)
    db.prepare(`
      INSERT INTO chat_messages (chat_room_id, sender, content)
      VALUES (?, 'system', ?)
    `).run(roomId, JSON.stringify({
      final_evaluation: {
        scenario: scenario.type,
        totalScore: feedback.score100,
        grade: feedback.grade,
        topEvents: stats.topEvents,
        generatedAt: new Date().toISOString(),
      }
    }));

    return res.json({
      roomId,
      scenario: scenario.type,
      goal: scenario.goal,
      totalScore: feedback.score100,
      grade: feedback.grade,
      topEvents: stats.topEvents,

      feedback: {
        summary: feedback.summary,
        oneLiner: feedback.oneLiner,
        didWell: feedback.didWellText,
        improve: feedback.improveText,
        topEvents: feedback.topEventsText,
        tips: feedback.tipsText,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "최종 평가 생성 실패" });
  }
});
