const language = document.getElementById('language');
let saved;
try { saved = localStorage.getItem('hello-language'); } catch (_) {}
language.value = ['en', 'ru'].includes(saved) ? saved : navigator.language.startsWith('ru') ? 'ru' : 'en';
function translate() {
  const lang = language.value;
  document.documentElement.lang = lang;
  language.setAttribute('aria-label', lang === 'ru' ? 'Язык' : 'Language');
  document.querySelectorAll('[data-en]').forEach(el => { el.textContent = el.dataset[lang]; });
  document.querySelectorAll('[data-alt-en]').forEach(el => { el.alt = el.getAttribute(`data-alt-${lang}`); });
  const button = document.getElementById('download');
  if (/Windows/i.test(navigator.userAgent)) {
    button.href = 'https://github.com/LeraZybin/HelloAndByeDPI/releases/download/v__VERSION__/HelloAndByeDPI-windows-x64-__VERSION__.zip';
    button.textContent = lang === 'ru' ? 'Скачать для Windows ↓' : 'Download for Windows ↓';
  } else if (/Macintosh|Mac OS X/i.test(navigator.userAgent) && !/iPhone|iPad/i.test(navigator.userAgent)) {
    button.textContent = lang === 'ru' ? 'Скачать для Mac ↓' : 'Download for Mac ↓';
  }
  try { localStorage.setItem('hello-language', lang); } catch (_) {}
}
language.addEventListener('change', translate);
translate();
