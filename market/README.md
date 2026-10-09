# INSELLERS — Android, Windows и macOS

Это отдельный клиент рынка, не VPN. VPN-клиент в `desktop/` и его сборка не изменены.

Приложения загружают **https://bot.insellers.su/**. Интерфейс, каталог, товары, заявки и сообщения общие с Telegram mini-app. Новый интерфейс приходит при следующем открытии/обновлении страницы без новой сборки установщика. Обновлятор оболочки проверяет новые выпуски при запуске. В меню есть «Проверить обновления». На Windows/macOS после согласия пакет скачивается, проверяется и приложение перезапускается для установки; Mac проверяет minisign-подпись пакета и версии тем же открытым ключом, что в VPN, затем заменяет приложение и перезапускает его; подпись Developer ID для самообновления не требуется. На Android после проверки SHA-256, имени пакета, версии и того же ключа подписи открывается системная установка с согласием владельца. Старый выпуск 1.0.3 без обновлятора нужно один раз заменить новым установщиком.

Вход: приложение создаёт запрос на пять минут; пользователь открывает ссылку в Telegram, сверяет код и явно подтверждает вход. Приватный ключ опроса никогда не включается в ссылку. Сервер проверяет подписанный Telegram start_param. Веб-сессия сохраняется в Secure/HttpOnly cookie на семь дней, токен запросов хранится только в памяти страницы. В профиле можно выйти. Требуется сервер mini-app с `/api/native/*` из соответствующего обновления.

## Сборка

- Windows/macOS: Node 22, `cd market/apps/desktop`, `npm ci`, `npm test`, `npm run dist -- --win --x64` на Windows или `npm run dist -- --mac --arm64 --x64` на macOS. Electron и electron-builder закреплены в lockfile. На Windows используется NSIS, на Mac — DMG для Intel и Apple Silicon.
- Android: JDK 17+, Gradle 8.13, SDK platform 35/build-tools 35.0.0. `cd market/apps/android`, `gradle --no-daemon assembleDebug assembleRelease lint`. Android 8+; загрузка фото/видео через системный выбор файлов, внешние ссылки через системные приложения. Библиотек и привилегированного JavaScript bridge нет.
- `.github/workflows/market.yml` собирает все три платформы при изменениях `market/`, проверяет их и публикует отдельный INSELLERS release только когда все сборки успешны. VPN workflow не затрагивается.

## Подпись

Первый выпуск — для проверки на устройствах. Windows/macOS без подписи разработчика и нотарификации Apple. Для Android без ключа создаётся `INSELLERS-android-test.apk`; между CI-сборками тестовый ключ меняется, поэтому такой APK не подходит для постоянных обновлений и массового выпуска.

Для стабильного Android APK задайте в **GitHub repository secrets**, не в исходниках: `MARKET_ANDROID_KEYSTORE_BASE64`, `MARKET_ANDROID_KEYSTORE_PASSWORD`, `MARKET_ANDROID_KEY_ALIAS`, `MARKET_ANDROID_KEY_PASSWORD`. CI будет публиковать `INSELLERS-android.apk`. Сохраните ключ безопасно: без него нельзя подписать совместимое обновление. Подпись Windows и Apple требует отдельных сертификатов владельца; их нельзя заменить VPN-ключом Tauri updater — это разные виды подписи.

Все окружения разработки и тесты работают без production-секретов. Перед загрузкой проверьте SHA256SUMS.txt из того же выпуска.

## Канал обновлений

CI публикует latest.yml для Windows, latest-mac-signed.json, подписанные ZIP и подписи для Mac, latest-android.json для Android в том же успешном release. Windows SHA-512 проверяет electron-updater; Mac проверяет SHA-256 и minisign/Ed25519 с привязкой подписанной версии, а также bundle ID/версию внутри ZIP; Android дополнительно проверяет настоящую подпись APK против установленного приложения. Проверки TLS, хеша и подписи не отключены. Desktop проверяет при запуске и раз в шесть часов; Android при запуске и через меню. Нет привилегированного IPC для загружаемой веб-страницы.

Mac использует уже настроенные VPN secrets TAURI_SIGNING_PRIVATE_KEY и TAURI_SIGNING_PRIVATE_KEY_PASSWORD. Открытый ключ закреплён в mac-updates.cjs; перед публикацией CI проверяет подписи обоих ZIP. Для необязательной подписи Developer ID/нотарификации предусмотрены MARKET_MAC_CSC_LINK, MARKET_MAC_CSC_KEY_PASSWORD, MARKET_APPLE_ID, MARKET_APPLE_APP_SPECIFIC_PASSWORD, MARKET_APPLE_TEAM_ID. Windows signing при необходимости: MARKET_WIN_CSC_LINK и MARKET_WIN_CSC_KEY_PASSWORD. Эти секреты добавляются в GitHub settings, не в чат или исходники. Тестовые Android APK с разными ключами не поддерживают совместимое обновление без удаления. Полный Mac цикл замены/перезапуска требует проверки на настоящем Mac; здесь проверены криптография в Electron и сборка на нативном CI.
