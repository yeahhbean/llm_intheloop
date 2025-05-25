// scripts/generate_html.js
const { DateTime } = require("luxon");
const fs = require("fs");
const path = require("path");
const { detectVulnerability } = require("../detection/detect");

console.log("🔁 [generate_html.js] 시작됨");

// 1. HTML escape 함수
function escapeHTML(str) {
  if (!str) return "";
  return str
    .toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// 2. 템플릿 미리 읽기
const template = fs.readFileSync("./templates/reportTemplate.html", "utf-8");

// 3. data 폴더 내 JSON 파일 전체 가져오기
const dataDir = "./data";
const jsonFiles = fs
  .readdirSync(dataDir)
  .filter((file) => file.endsWith(".json"));

if (jsonFiles.length === 0) {
  console.log("data 폴더에 JSON 파일이 없습니다.");
  process.exit(1);
}

// 4. 각각의 JSON 파일에 대해 리포트 생성
jsonFiles.forEach((filename, index) => {
  const inputPath = path.join(dataDir, filename);
  const jsonData = JSON.parse(fs.readFileSync(inputPath, "utf-8"));
  const result = detectVulnerability(jsonData);

  console.log(
    `[${index + 1}/${jsonFiles.length}] ${filename} → ${result.vuln_type}`
  );

  // === 현재 시각 (KST)
  const now = DateTime.now().setZone("Asia/Seoul");
  const formattedTimestamp = now.toFormat("yyyyMMddHHmm"); // 파일명용
  const formattedDisplayTime = now.toFormat("yyyy-MM-dd HH:mm:ss"); // 템플릿용

  // === JSON <script> 삽입용 문자열 생성 (주의: < 문자 이스케이프 필요)
  const jsonRaw = JSON.stringify(jsonData, null, 2).replace(/</g, "\\u003c");

  // === HTML 템플릿 채우기
  const filled = template
    .replace(/{{vuln_type}}/g, escapeHTML(result.vuln_type))
    .replace(/{{severity}}/g, escapeHTML(result.severity))
    .replace(/{{description}}/g, escapeHTML(result.description))
    .replace(/{{url}}/g, escapeHTML(jsonData.url))
    .replace(/{{method}}/g, escapeHTML(jsonData.method))
    .replace(/{{payload}}/g, escapeHTML(jsonData.payload))
    .replace(
      /{{response_status}}/g,
      escapeHTML(String(jsonData.response_status))
    )
    .replace(/{{json_data}}/g, jsonRaw)
    .replace(/{{generated_time}}/g, escapeHTML(formattedDisplayTime));

  // === 리포트 파일명
  const reportName = `report_${path.basename(
    filename,
    ".json"
  )}_${formattedTimestamp}.html`;
  const outputPath = path.join("./reports", reportName);

  // === 저장
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, filled, "utf-8");

  console.log(`생성됨: ${outputPath}`);
});
