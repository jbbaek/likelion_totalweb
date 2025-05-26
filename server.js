const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");

const db = mysql.createConnection({
  host: "localhost",
  user: "manager",
  password: "1234",
  database: "users",
});

db.connect((err) => {
  if (err) {
    console.error("MySQL 연결 실패:", err);
    process.exit(1);
  }
  console.log("MySQL 연결 성공");
});

const app = express();
app.use(bodyParser.json());
app.use(cors()); // CORS 허용 (프론트-백 분리시 필요)

// 아이디 중복확인
app.post("/api/check-id", (req, res) => {
  const { id } = req.body;
  db.query("SELECT id FROM users WHERE id=?", [id], (err, results) => {
    if (err) return res.status(500).json({ result: false, error: "DB오류" });
    if (results.length > 0) return res.json({ result: false }); // 이미 존재
    res.json({ result: true }); // 사용가능
  });
});

// 회원가입
app.post("/api/signup", async (req, res) => {
  const { id, password } = req.body;
  try {
    // 1. 비밀번호 해시화
    const hashedPassword = await bcrypt.hash(password, 10);
    // 2. DB 저장
    db.query(
      "INSERT INTO users (id, password) VALUES (?, ?)",
      [id, hashedPassword],
      (err) => {
        if (err)
          return res
            .status(500)
            .json({ result: false, error: "DB오류 또는 중복" });
        res.json({ result: true });
      }
    );
  } catch (err) {
    res.status(500).json({ result: false, error: "서버 오류" });
  }
});

// 로그인
app.post("/api/login", (req, res) => {
  const { id, password } = req.body;
  db.query("SELECT * FROM users WHERE id=?", [id], async (err, results) => {
    if (err) return res.status(500).json({ result: false, error: "DB오류" });
    if (results.length === 1) {
      // 1. DB에 저장된 해시값 가져오기
      const user = results[0];
      // 2. 입력 비밀번호와 해시값 비교
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        res.json({ result: true });
      } else {
        res.json({ result: false });
      }
    } else {
      res.json({ result: false });
    }
  });
});

app.listen(3000, () => {
  console.log("서버 실행 중 → http://localhost:3000");
});
