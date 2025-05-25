function detectVulnerability(data) {
  const {
    url,
    method,
    headers,
    params,
    body,
    payload,
    response_status,
    response_headers,
    response_body,
    timestamp,
  } = data;

  const result = (vuln_type, severity, exploitability, description) => ({
    vuln_type,
    severity,
    exploitability,
    description,
  });

  const responseCodeOk =
    response_status && response_status.toString().startsWith("2");

  const safeMatch = (val, regex) => typeof val === "string" && val.match(regex);
  const safeIncludes = (val, str) =>
    typeof val === "string" && val.includes(str);
  const safeLowerIncludes = (val, str) =>
    typeof val === "string" && val.toLowerCase().includes(str.toLowerCase());

  // === OS Command Injection (우선순위 상향)
  if (
    typeof payload === "string" &&
    /[;&|`]|(\bwhoami\b|\buname\b|\bping\b|\bcat\b)/i.test(payload) &&
    typeof response_body === "string" &&
    /(uid=\d+|root:x:|Linux version|total \d+|hostname=)/i.test(response_body)
  ) {
    return result(
      "OS Command Injection",
      "High",
      "Confirmed",
      "명령어 삽입이 의심되며 시스템 정보가 노출되었습니다."
    );
  }

  // === LFI vs Path Traversal 구분
  const isTraversal = typeof payload === "string" && payload.includes("../");
  const isSuspiciousFile =
    typeof response_body === "string" &&
    /root:x:|bin\/bash|\/bin\/sh|\.bashrc|etc\/shadow|web\.xml|application\.yml/i.test(
      response_body
    );
  const lfiContext =
    url.includes("include") || url.includes("page") || url.endsWith(".php");

  if (isTraversal && isSuspiciousFile) {
    if (lfiContext) {
      return result(
        "Local File Inclusion (LFI)",
        "High",
        "Confirmed",
        "include 함수 기반 파일 포함 동작으로 판단되며, 시스템 파일이 노출되었습니다."
      );
    } else {
      return result(
        "Path Traversal",
        "Medium",
        "Likely",
        "디렉토리 탐색 기법을 통해 민감 파일에 접근한 정황이 있으며, LFI는 아닙니다."
      );
    }
  }

  // === XSS (정확한 태그 포함 + 응답에서 HTML 컨텍스트 확인)
  if (
    typeof payload === "string" &&
    /<script|<img|<svg|<iframe|onerror=|alert\(/i.test(payload) &&
    typeof response_body === "string" &&
    new RegExp(payload.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(
      response_body
    )
  ) {
    return result(
      "XSS",
      "High",
      "Confirmed",
      "스크립트 입력이 escape 없이 응답에 포함되어 있습니다."
    );
  }

  // === SQL Injection ===
  const sqlKeywords =
    /('|--|\/\*|\*\/|UNION|SELECT|INSERT|UPDATE|DELETE|OR\s+1=1|SLEEP\(|BENCHMARK\()/i;
  const sqlErrors =
    /(syntax error|SQLSTATE|mysql|PostgreSQL|unterminated|unclosed|ORA-)/i;

  if (safeMatch(payload, sqlKeywords)) {
    if (safeMatch(response_body, /(SLEEP|BENCHMARK)/i)) {
      return result(
        "SQL Injection (Time-Based)",
        "High",
        "Likely",
        "시간 지연 함수가 포함되어 있으며, 응답 시간 지연으로 보아 시간 기반 블라인드 SQLi가 의심됩니다."
      );
    }
    if (safeMatch(response_body, /Warning|Traceback|at line|SQL error/i)) {
      return result(
        "SQL Injection (Error-Based)",
        "High",
        "Confirmed",
        "응답에 SQL 오류 메시지가 포함되어 있어 오류 기반 SQLi가 확인됩니다."
      );
    }
    if (responseCodeOk) {
      return result(
        "SQL Injection (Boolean-Based)",
        "Medium",
        "Likely",
        "조건문 기반 SQLi로 추정되는 논리적 페이로드에 대해 200 응답이 반환되었습니다."
      );
    }
  }

  // === NoSQL Injection
  if (
    (typeof payload === "object" &&
      JSON.stringify(payload).match(
        /\$ne|\$gt|\$lt|\$regex|\$where|\$exists/i
      )) ||
    (typeof body === "string" && body.match(/\$ne|\$gt|\$lt|\$regex/))
  ) {
    return result(
      "NoSQL Injection",
      "Medium",
      "Likely",
      "입력에 MongoDB 연산자가 포함되어 있으며 NoSQLi 시도가 의심됩니다."
    );
  }

  // === Open Redirect
  if (
    typeof payload === "string" &&
    /^https?:\/\//i.test(payload) &&
    typeof response_headers?.Location === "string" &&
    response_headers.Location.startsWith(payload)
  ) {
    return result(
      "Open Redirect",
      "Low",
      "Confirmed",
      "입력값이 검증 없이 외부 URL로 리다이렉션에 사용되었습니다."
    );
  }

  // === IDOR
  if (
    safeMatch(url, /id=|user_id=|uid=|account=/i) &&
    safeMatch(response_body, /"username":|"email":|"role":|"user_id":|admin/i)
  ) {
    return result(
      "Insecure Direct Object Reference (IDOR)",
      "High",
      "Likely",
      "ID 값을 조작해 타인의 정보가 노출되는 것으로 보입니다."
    );
  }

  return result("None", "None", "None", "탐지된 취약점이 없습니다.");
}

module.exports = { detectVulnerability };
