(function(){
  const ENTER_DELAY_MS = 30;
  const EXIT_DELAY_MS = 280;

  window.smoothNavigate = function(url, delay){
    if(!url){ return; }
    const d = Number.isFinite(delay) ? delay : EXIT_DELAY_MS;
    document.body.classList.add("page-leave");
    setTimeout(() => { window.location.href = url; }, d);
  };

  document.addEventListener("DOMContentLoaded", () => {
    setTimeout(() => document.body.classList.add("page-ready"), ENTER_DELAY_MS);

    document.querySelectorAll('a[href$=".html"]').forEach((a) => {
      a.addEventListener("click", (e) => {
        const href = a.getAttribute("href");
        if(!href || a.target === "_blank" || a.hasAttribute("download")) return;
        e.preventDefault();
        window.smoothNavigate(href);
      });
    });
  });
})();
