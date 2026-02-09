# phishing-simulator

보이스피싱 상황을 시뮬레이션하고, 사용자의 대응을 점수화하여
위험도 평가 및 맞춤 피드백을 제공하는 웹 서비스입니다.

## 주요 기능
- 시나리오별 보이스피싱 대화 시뮬레이션
- 사용자 메시지 기반 이벤트 탐지 및 점수화
- 대화 종료 후 위험도 평가 및 시나리오 맞춤 피드백 제공

## 폴더 구조
- backend/ : Express + OpenAI API 서버
- frontend/ : 정적 웹 프론트엔드

## 실행 방법
1. backend 폴더에 `.env` 파일 생성
```env
OPENAI_API_KEY=본인_API_키
