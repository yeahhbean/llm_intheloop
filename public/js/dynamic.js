// nav 링크 클릭 시 페이지 이동 처리
document.querySelectorAll(".nav-links li").forEach((item) => {
  item.addEventListener("click", () => {
    const text = item.textContent.trim();

    // 각 메뉴에 맞는 HTML 경로 지정 (views 폴더 내부로 가정)
    let targetPage = "";

    switch (text) {
      case "Main":
        targetPage = "/views/main.html";
        break;
      case "How it works":
        targetPage = "/views/how.html";
        break;
      case "Team":
        targetPage = "/views/index.html"; // 팀 소개 페이지
        break;
      case "FAQ":
        targetPage = "/views/faq.html";
        break;
      default:
        console.warn("Unknown nav item:", text);
        return;
    }

    // 이동 실행
    window.location.href = targetPage;
  });
});
