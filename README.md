# INSELLERS VPN — компьютерная версия (Windows / macOS / Linux)

Tauri-приложение. Здесь только код клиента (`desktop/`) и сборка; сервер, бот и мини-апп — в закрытом репозитории,
откуда `desktop/` копируется сюда автоматически при изменениях.

Сборка: `.github/workflows/desktop.yml` — ночью (04:00 МСК), если за сутки менялась `desktop/`, и вручную
(Actions → desktop → Run workflow). Готовые файлы публикуются на vpn.insellers.su, приложение обновляется само.

Secrets репозитория: `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (ключ подписи обновлений —
тот же, что был в закрытом репо: открытый ключ зашит в tauri.conf.json), `DESKTOP_UPLOAD_KEY` (загрузка на сервер).
