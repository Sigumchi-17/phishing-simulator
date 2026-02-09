// HTML 요소 가져오기
const chatMessages = document.getElementById('chatMessages');
const userInput = document.getElementById('userInput');
const sendBtn = document.getElementById('sendBtn');
const chatListScreen = document.getElementById('chatListScreen');
const chatRoomScreen = document.getElementById('chatRoomScreen');
let currentScenario = null;
let roomId = null;

const chatData = {
    'delivery': {
        name: '택배사',
        initial: '택',
        firstMessage: "안녕하세요. 배송 주소 오류로 보류되어 확인 부탁드립니다. 받는 분 성함이 어떻게 되시나요?"
    },
    'police': {
        name: '서울중앙검찰청',
        initial: '서',
        firstMessage: "서울중앙검찰청입니다. 귀하의 명의로 사건 연루 정황이 확인되어 연락드렸습니다. 성함 확인 가능하십니까?"
    },
    'insurance': {
        name: '보험사',
        initial: '보',
        firstMessage: "안녕하세요. 고객님 보험 관련 안내입니다. 만기/환급 관련 확인이 필요해서 연락드렸는데 잠시 괜찮으실까요?"
    },
    'family': {
        name: '010-0000-0000',
        initial: '0',
        firstMessage: "엄마(아빠), 나 폰이 고장나서 친구폰으로 연락했어"
    },
    'romance': {
        name: '❤️',
        initial: '❤️',
        firstMessage:"오늘은 좀 생각나서... 잠깐 얘기할 수 있어?"
    }
};

const scenarios = {
    delivery: {
        type: "택배 사칭",
        description: "주소 오류로 배송이 보류되었다고 연락함",
        goal: "주소 및 개인정보 획득",
        first: "안녕하세요. 배송 주소 오류로 보류되어 확인 부탁드립니다. 받는 분 성함이 어떻게 되시나요?",
        tone: "배송/보류/주소 오류 안내 톤. 짧고 단호하게."
    },
    police: {
        type:"검찰 사칭",
        description:"",
        goal:"개인정보 제공 및 자산 보호 명목 송금",
        first: "서울중앙검찰청입니다. 귀하의 명의로 사건 연루 정황이 확인되어 연락드렸습니다. 성함 확인 가능하십니까?",
        tone: "검찰/사건 연루/절차 안내 톤. 권위적이고 압박."
    },
    insurance: {
        type:"보험사 사칭",
        description:"기존 보험의 만료나 환급을 이유로 개인정보 요청",
        goal:"계좌, 주민번호 등의 개인정보 획득",
        first: "안녕하세요. 고객님 보험 관련 안내입니다. 만기/환급 관련 확인이 필요해서 연락드렸는데 잠시 괜찮으실까요?",
        tone: "만기/환급/갱신 안내 톤. 친절하지만 절차 강조."
    },
    family: {
        type: "가족 사칭",
        description:"가족을 사칭하여 핸드폰이 고장났다며 돈을 빌려달라는 등의 요청을 함",
        goal:"사용자로의 송금 유도",
        first: "엄마(아빠), 나 폰이 고장나서 친구폰으로 연락했어요",
        tone: "친근/존댓말. 핸드폰이 고장났다는 설정 유지"
    },
    romance: {
        type:"로맨스 스캠",
        description:"사용자에게 연인으로 접근하여 가정에 일이 생겨 돈을 빌려달라고 요구",
        goal:"사용자로의 송금 유도, 외부 메신저로의 이동",
        first: "오늘은 좀 생각나서... 잠깐 얘기할 수 있어?",
        tone: "감정적 접근. 동정심 유발 후 요구로 연결."
    }

}

// 현재 시간을 '오전/오후 0:00' 형식으로 리턴하는 함수
function getCurrentTime() {
    const now = new Date();
    let hours = now.getHours();
    const minutes = now.getMinutes();
    const ampm = hours >= 12 ? '오후' : '오전';
    
    hours = hours % 12;
    hours = hours ? hours : 12; // 0시를 12시로 표시
    const minutesStr = minutes < 10 ? '0' + minutes : minutes;
    
    return `${ampm} ${hours}:${minutesStr}`;
}

// 페이지 로드 시 상단 날짜 구분선을 오늘 날짜와 시간으로 업데이트
window.onload = () => {
    const dateDivider = document.querySelector('.date-divider');
    if (dateDivider) {
        dateDivider.innerText = `오늘 ${getCurrentTime()}`;
    }
};

// 1. 시작 페이지에서 인트로 페이지로 이동
function goToIntro() {
    document.getElementById('startPage').classList.add('hidden');
    document.getElementById('introPage').classList.remove('hidden');
}

// 2. 인트로 페이지에서 채팅 목록으로 이동
function goToChatList() {
    document.getElementById('introPage').classList.add('hidden');
    document.getElementById('chatListScreen').classList.remove('hidden');
}

async function enterRoom(scenarioKey){

    if (!scenarioKey) throw new Error("enterRoom called without scenarioKey");


    console.log("enterRoom key:", scenarioKey, "keys:", Object.keys(scenarios));

    //시나리오 선택
    currentScenario = scenarios[scenarioKey];

    if(!currentScenario){
        alert("시나리오 키가 잘못됨: " + scenarioKey);
        return;
    }

    const res = await fetch("http://localhost:3000/rooms", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            scenario: currentScenario
        })
    });

    const data = await res.json();

    roomId = data.roomId;

    chatMessages.innerHTML = "";
    const dataDiv = document.createElement("div");
    dataDiv.className = "date-divider";
    dataDiv.innerText = `오늘 ${getCurrentTime()}`;
    chatMessages.appendChild(dataDiv);

}

// 1. 메시지 전송 함수
async function sendMessage() {

    if (!roomId || !currentScenario){
        alert("채팅방이 아직 준비되지 않았습니다.");
        return;
    }

    const text = userInput.value.trim();
    if (!text) return;

    addMessage(text, 'sent');
    userInput.value = "";

    showTypingIndicator();

    const res = await fetch("http://localhost:3000/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        message: text,
        scenario: currentScenario,
        roomId
    })});

    const data = await res.json();

    if (!res.ok){
        removeTypingIndicator();
        receiveReply("오류가 발생했습니다.");
        return;
    }

    removeTypingIndicator();
    receiveReply(data.reply);
    console.log(data.evaluation);
}

// '입력 중...' 표시를 화면에 추가하는 함수
function showTypingIndicator() {
    const indicator = document.createElement('div');
    indicator.classList.add('message', 'received');
    indicator.id = 'typingIndicator'; // 나중에 지우기 위해 ID 부여
    
    indicator.innerHTML = `
        <div class="bubble">
            <div class="typing-indicator">
                <span></span><span></span><span></span>
            </div>
        </div>
    `;
    
    chatMessages.appendChild(indicator);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// '입력 중...' 표시를 지우는 함수
function removeTypingIndicator() {
    const indicator = document.getElementById('typingIndicator');
    if (indicator) {
        indicator.remove();
    }
}

// 2. 화면에 말풍선을 그려주는 함수
function addMessage(text, type) {
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message', type);
    
    // 시간 정보 가져오기
    const timeStr = getCurrentTime();
    
    // HTML 구조에 시간(timestamp) 추가
    messageDiv.innerHTML = `
        <div class="bubble">${text}</div>
        <span class="timestamp">${timeStr}</span>
    `;
    
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// 3. 상대방 응답 처리 함수 (테스트용)
function receiveReply(text) {
    addMessage(text, 'received');
}

// --- 이벤트 리스너 (버튼 클릭 & 엔터키) ---

// 전송 버튼 클릭 시
sendBtn.addEventListener('click', sendMessage);

// 엔터 키 눌렀을 때
userInput.addEventListener('input', function() {
    // 한 줄일 때의 기본 높이 (CSS의 height와 맞춰주세요)
    const baseHeight = 40; 
    
    this.style.height = baseHeight + 'px'; // 일단 초기화
    
    // 내용이 길어져서 scrollHeight가 baseHeight보다 커지면 그때부터 늘림
    if (this.scrollHeight > baseHeight) {
        this.style.height = (this.scrollHeight) + 'px';
    }
});

// 엔터 누르면 전송, Shift+엔터는 줄바꿈
userInput.addEventListener('keydown', (e) => {
    // 한글 조합 중 엔터 키 중복 입력 방지 (중요!)
    if (e.isComposing) return;

    if (e.key === 'Enter') {
        if (!e.shiftKey) {
            // Shift 없이 엔터만 누르면 전송
            e.preventDefault(); 
            sendMessage();
            
            // 전송 후 높이를 원래(40px)대로 초기화
            userInput.style.height = '40px'; 
        } 
        // Shift + Enter는 아무 처리를 하지 않아도 알아서 줄바꿈이 됩니다.
    }
});

// 채팅방에서 < 버튼을 눌렀을 때 실행
function openChatList() {
    // 1. 채팅 목록을 보여준다
    document.getElementById('chatListScreen').classList.remove('hidden');
    // 2. (선택사항) 채팅방을 숨긴다
    document.getElementById('chatRoomScreen').classList.add('hidden');
}

// 목록에서 채팅방을 눌렀을 때 실행
async function closeChatList(scenarioKey) {
    console.log("closeChatList got:", scenarioKey);

    if (!scenarioKey) {
        console.error("scenarioKey is undefined. Click target:", event?.target);
        alert("채팅방 키 전달이 안 됐습니다. (onclick 확인 필요)");
        return;
    }

    if (!scenarios[scenarioKey]) {
        alert("시나리오 키가 잘못됨: " + scenarioKey);
        return;
    }

    await enterRoom(String(scenarioKey));

    const data = chatData[scenarioKey];
    if (!data) return; // 데이터가 없으면 실행 안 함

    // 1. 화면 전환
    chatListScreen.classList.add("hidden");
    chatRoomScreen.classList.remove("hidden");

    // 2. 헤더 정보(이름, 프로필) 변경
    document.querySelector('.profile-name').innerText = data.name;
    document.querySelector('.profile-pic').innerText = data.initial;

    // 3. 기존 대화 내역 완전히 비우기 (중요!)
    chatMessages.innerHTML = ''; 

    // 4. 오늘 날짜 구분선 새로 넣기
    const dateDiv = document.createElement('div');
    dateDiv.className = 'date-divider';
    dateDiv.innerText = `오늘 ${getCurrentTime()}`;
    chatMessages.appendChild(dateDiv);

    receiveReply(data.firstMessage);
}

chatListScreen.addEventListener("click", async (e) => {
  const item = e.target.closest(".chat-item");
  console.log("clicked element:", e.target);
  console.log("closest chat-item:", item);
  console.log("dataset:", item?.dataset);

  if (!item) return;

  const scenarioKey = item.dataset.scenario;
  console.log("scenarioKey from dataset:", scenarioKey);

  await closeChatList(scenarioKey);
});

// ===== 피드백(대화 종료) 기능 =====
const endChatBtn = document.getElementById("endChatBtn");
const feedbackModal = document.getElementById("feedbackModal");
const feedbackBody = document.getElementById("feedbackBody");
const closeFeedbackBtn = document.getElementById("closeFeedbackBtn");
const restartBtn = document.getElementById("restartBtn");
const backToListBtn = document.getElementById("backToListBtn");

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function gradeBadge(grade) {
  // grade = { level, label, emoji }
  if (!grade) return "";
  return `<span class="badge badge-${escapeHtml(grade.level || "").toLowerCase()}">
    ${escapeHtml(grade.emoji || "")} ${escapeHtml(grade.label || "")}
  </span>`;
}

function renderFeedbackUI(payload) {
  // payload.feedback: { summary, oneLiner, didWell, improve, topEvents, tips }
  document.querySelector(".modal-title").innerText = `${payload.scenario} 평가`;
  const grade = payload.grade;
  const topEvents = Array.isArray(payload.topEvents) ? payload.topEvents : [];

  const topEventsList = topEvents.length
    ? `<ul class="list">
        ${topEvents
          .map(
            (t) => `<li>
              <b>${escapeHtml(t.event)}</b>
              <span class="muted"> (횟수 ${escapeHtml(t.count)}, 영향도 ${escapeHtml(t.weightSum)})</span>
            </li>`
          )
          .join("")}
      </ul>`
    : `<div class="muted">감지된 주요 이벤트가 없습니다.</div>`;

  return `
    <div class="feedback-summary">
      <div class="row">
        <div>${gradeBadge(grade)}</div>
        <div class="score">총점 <b>${escapeHtml(payload.totalScore)}</b></div>
      </div>
      <div class="headline">${escapeHtml(payload.feedback?.summary || "")}</div>
      <div class="one-liner">${escapeHtml(payload.feedback?.oneLiner || "")}</div>
    </div>

    <hr class="feedback-hr"/>

    <div class="section">
      <div class="section-title">주요 이벤트</div>
      ${topEventsList}
    </div>

    <div class="section">
      <div class="section-title">잘한 점</div>
      <pre class="pre">${escapeHtml(payload.feedback?.didWell || "")}</pre>
    </div>

    <div class="section">
      <div class="section-title">개선점</div>
      <pre class="pre">${escapeHtml(payload.feedback?.improve || "")}</pre>
    </div>

    <div class="section">
      <div class="section-title">${currentScenario.type} 대응 팁</div>
      <pre class="pre">${escapeHtml(payload.feedback?.tips || "")}</pre>
    </div>
  `;
}

function openFeedbackModal() {
  feedbackModal.classList.remove("hidden");
}

function closeFeedbackModal() {
  feedbackModal.classList.add("hidden");
}

async function endConversationAndShowFeedback() {
  if (!roomId) {
    alert("종료할 채팅방이 없습니다.");
    return;
  }

  // UI: 버튼 잠깐 막기
  endChatBtn.disabled = true;
  endChatBtn.innerText = "종료 중...";

  try {
    const res = await fetch(`http://localhost:3000/rooms/${roomId}/end`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });

    const data = await res.json();

    if (!res.ok) {
      console.error("end error:", data);
      alert(data?.error || "평가 생성 실패");
      return;
    }

    feedbackBody.innerHTML = renderFeedbackUI(data);
    openFeedbackModal();
  } catch (err) {
    console.error(err);
    alert("서버 통신 오류");
  } finally {
    endChatBtn.disabled = false;
    endChatBtn.innerText = "종료";
  }
}

// 이벤트 바인딩
if (endChatBtn) endChatBtn.addEventListener("click", endConversationAndShowFeedback);
if (closeFeedbackBtn) closeFeedbackBtn.addEventListener("click", closeFeedbackModal);

// “새로 시작”: 현재 방 리셋(새 room 생성)하고 첫 메시지 다시
if (restartBtn) restartBtn.addEventListener("click", async () => {
  closeFeedbackModal();

  if (!currentScenario) {
    openChatList();
    return;
  }

  // 채팅창 초기화
  chatMessages.innerHTML = "";
  const dateDiv = document.createElement("div");
  dateDiv.className = "date-divider";
  dateDiv.innerText = `오늘 ${getCurrentTime()}`;
  chatMessages.appendChild(dateDiv);

  // 새 방 만들기
  try {
    const res = await fetch("http://localhost:3000/rooms", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: currentScenario }),
    });

    const data = await res.json();
    if (!res.ok) {
      alert(data?.error || "채팅방 생성 실패");
      return;
    }

    roomId = data.roomId;

    // 서버가 firstMessage 내려주도록 만들어놨다면 그걸 사용
    // (네 서버 코드에서 return { roomId, firstMessage } 이미 함)
    if (data.firstMessage) receiveReply(data.firstMessage);
  } catch (e) {
    console.error(e);
    alert("서버 통신 오류");
  }
});

// “목록으로”: 모달 닫고 채팅 리스트로
if (backToListBtn) backToListBtn.addEventListener("click", () => {
  closeFeedbackModal();
  openChatList();
});


window.closeChatList = closeChatList;
window.openChatList = openChatList;
window.goToIntro = goToIntro;
window.goToChatList = goToChatList;
window.enterRoom = enterRoom;
