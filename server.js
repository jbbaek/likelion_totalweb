// 필요한 패키지들 불러오기
const express = require("express"); // 웹 서버 프레임워크
const bodyParser = require("body-parser"); // 요청 데이터(body) 파싱용
const mysql = require("mysql2"); // MySQL 연동
const cors = require("cors"); // CORS 정책 허용
const bcrypt = require("bcrypt"); // 비밀번호 해시/검증용
const session = require("express-session"); // 세션 관리

// MySQL 데이터베이스 연결 생성
const db = mysql.createConnection({
  host: "localhost",
  user: "manager",
  password: "1234",
  database: "users",
});

// MySQL 서버와 연결 시도
db.connect((err) => {
  if (err) {
    console.error("MySQL 연결 실패:", err); // 연결 실패시 에러 로그 출력
    process.exit(1); // 서버 종료
  }
  console.log("MySQL 연결 성공"); // 성공 시 메시지 출력
});

const app = express(); // Express 앱 생성

app.use(bodyParser.json()); // 요청의 body를 JSON으로 자동 변환 (req.body로 사용)

// CORS 허용 설정 (다른 도메인/포트에서 오는 요청 허용)
// 실제 배포 시 origin을 "http://localhost:8080"처럼 제한 가능
app.use(
  cors({
    origin: true, // 모든 오리진 허용(true), 배포시 도메인 명시 추천
    credentials: true, // 인증정보(쿠키 등) 포함 허용
  })
);

// ★ express-session 사용: 로그인/로그아웃 상태를 서버가 세션 쿠키로 기억
app.use(
  session({
    name: "id", // 쿠키 key를 'id'로 지정 (브라우저 쿠키 key에 표시됨)
    secret: "your-secret-key", // 세션 암호화 비밀키(아무거나 OK, 보통 .env로 관리)
    resave: false, // 세션을 매 요청마다 저장할지(변경될 때만 저장)
    saveUninitialized: true, // 세션이 변경되지 않아도 저장할지(비추천, 실습용은 OK)
    cookie: {
      httpOnly: true, // 자바스크립트로 쿠키 접근 금지(XSS 방지)
      maxAge: 1000 * 60 * 60, // 쿠키 유효시간 (1시간)
    },
  })
);

// public 폴더에 있는 파일을 정적 파일로 서비스 (ex: signup.html, login.html)
app.use(express.static("public"));

// 루트(/)로 접속 시 회원가입 페이지로 자동 리다이렉트
app.get("/", (req, res) => {
  res.redirect("/signup.html");
});

// ----------------------- API 구현부 ----------------------------

// [1] 아이디 중복확인
app.post("/api/check-id", (req, res) => {
  const { id } = req.body; // 요청 body에서 id 추출
  // users 테이블에서 같은 id가 있는지 검색
  db.query("SELECT id FROM users WHERE id=?", [id], (err, results) => {
    if (err) return res.status(500).json({ result: false, error: "DB오류" });
    if (results.length > 0) return res.json({ result: false }); // 이미 존재
    res.json({ result: true }); // 사용가능
  });
});

// [2] 회원가입
app.post("/api/signup", async (req, res) => {
  const { id, password } = req.body; // body에서 id, password 추출
  try {
    // 비밀번호를 bcrypt로 해시(암호화)
    const hashedPassword = await bcrypt.hash(password, 10);
    // users 테이블에 id와 암호화된 비밀번호 저장
    db.query(
      "INSERT INTO users (id, password) VALUES (?, ?)",
      [id, hashedPassword],
      (err) => {
        if (err)
          // 중복/DB오류 발생시 에러 반환
          return res
            .status(500)
            .json({ result: false, error: "DB오류 또는 중복" });
        res.json({ result: true }); // 성공 시 true 반환
      }
    );
  } catch (err) {
    // 예외(해시화 실패 등) 발생시
    res.status(500).json({ result: false, error: "서버 오류" });
  }
});

// [3] 로그인 (세션 쿠키 생성)
app.post("/api/login", (req, res) => {
  const { id, password } = req.body;
  // users 테이블에서 해당 id로 유저 조회
  db.query("SELECT * FROM users WHERE id=?", [id], async (err, results) => {
    if (err) return res.status(500).json({ result: false, error: "DB오류" });
    if (results.length === 1) {
      const user = results[0];
      // 입력한 비밀번호와 저장된 해시값 비교
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        req.session.userId = user.id; // 세션에 userId 저장 (로그인 상태)
        res.json({ result: true }); // 로그인 성공
      } else {
        res.json({ result: false }); // 비밀번호 틀림
      }
    } else {
      res.json({ result: false }); // 해당 id 없음
    }
  });
});

// [4] 로그아웃 (세션 제거)
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    // 세션 파괴
    res.json({ result: true }); // 성공 응답
  });
});

// [5] 로그인 상태(세션) 체크용 API (프론트에서 로그인 유지 확인 등에 사용)
app.get("/api/check-session", (req, res) => {
  if (req.session.userId) {
    // 로그인 되어 있음
    res.json({ loggedIn: true, userId: req.session.userId });
  } else {
    // 로그인 안 됨
    res.json({ loggedIn: false });
  }
});

// 서버 실행 (3000번 포트에서)
app.listen(3000, () => {
  console.log("서버 실행 중 → http://localhost:3000");
});
