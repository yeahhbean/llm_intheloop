// app.js
const express = require("express");
const path = require("path");
const app = express();

// 1. public 폴더를 정적 디렉토리로 등록 (CSS, JS, 이미지)
app.use(express.static(path.join(__dirname, "public")));

// 2. views 폴더의 HTML 파일을 라우팅
app.get("/views/:page", (req, res) => {
  const page = req.params.page;
  res.sendFile(path.join(__dirname, "views", page));
});

// 3. 루트로 접속하면 메인 페이지 보여주기
app.get("/", (req, res) => {
  res.redirect("/views/main.html");
});

// 4. 서버 실행
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`server running at http://localhost:${PORT}`);
});
