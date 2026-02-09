import Database from "better-sqlite3";

const db = new Database("phishing.db");

// 채팅방 테이블
db.prepare(`
  CREATE TABLE IF NOT EXISTS chat_rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_type TEXT,
    scenario_description TEXT,
    phishing_goal TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ended_at DATETIME
  )
`).run();

// 채팅 메시지 테이블
db.prepare(`
  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_room_id INTEGER,
    sender TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

export default db;
