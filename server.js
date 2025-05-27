const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("express-session");

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

// CORS 설정 (프론트가 다른 포트면 origin에 프론트 주소)
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

//세션 쿠키 key를 'id'로 지정!
app.use(
  session({
    name: "id", // ← 쿠키 key가 'id'로 나옴!
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60, // 1시간
    },
  })
);

app.use(express.static("public"));

app.get("/", (req, res) => {
  res.redirect("/signup.html");
});

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
    const hashedPassword = await bcrypt.hash(password, 10);
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

// 로그인 (세션 쿠키 생성)
app.post("/api/login", (req, res) => {
  const { id, password } = req.body;
  db.query("SELECT * FROM users WHERE id=?", [id], async (err, results) => {
    if (err) return res.status(500).json({ result: false, error: "DB오류" });
    if (results.length === 1) {
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        req.session.userId = user.id; // 세션 저장
        res.json({ result: true });
      } else {
        res.json({ result: false });
      }
    } else {
      res.json({ result: false });
    }
  });
});

// 로그아웃 (세션 제거)
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ result: true });
  });
});

// 세션 체크 API
app.get("/api/check-session", (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, userId: req.session.userId });
  } else {
    res.json({ loggedIn: false });
  }
});

app.listen(3000, () => {
  console.log("서버 실행 중 → http://localhost:3000");
});
