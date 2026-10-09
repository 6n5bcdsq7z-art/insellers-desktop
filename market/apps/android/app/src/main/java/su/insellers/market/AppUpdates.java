package su.insellers.market;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.widget.Toast;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class AppUpdates {
    private static final String FEED = "https://github.com/6n5bcdsq7z-art/insellers-desktop/releases/latest/download/latest-android.json";
    private final Activity activity;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final SharedPreferences prefs;
    private boolean checking;
    private boolean installerOpen;
    private int offered;
    private final DownloadManager downloads;
    private final android.os.Handler handler = new android.os.Handler(android.os.Looper.getMainLooper());
    private boolean polling;
    private final Runnable poll = new Runnable() {
        @Override public void run() { if (!polling) return; resume(); handler.postDelayed(this, 2000); }
    };
    AppUpdates(Activity activity) {
        this.activity = activity;
        prefs = activity.getSharedPreferences("app_updates", Context.MODE_PRIVATE);
        try { if (prefs.contains("download") && prefs.getInt("version", 0) <= version(installed())) prefs.edit().clear().apply(); }
        catch (Exception ignored) { /* invalid package state is rejected during verification */ }
        downloads = (DownloadManager) activity.getSystemService(Context.DOWNLOAD_SERVICE);

    }
    private void ui(Runnable action) { activity.runOnUiThread(() -> { if (!activity.isFinishing() && !activity.isDestroyed()) action.run(); }); }
    private void message(String text) { ui(() -> new AlertDialog.Builder(activity).setTitle("Обновление INSELLERS").setMessage(text).setPositiveButton("Хорошо", null).show()); }
    private static String hex(byte[] bytes) { StringBuilder b = new StringBuilder(); for (byte value : bytes) b.append(String.format("%02x", value & 255)); return b.toString(); }
    private PackageInfo installed() throws Exception { return activity.getPackageManager().getPackageInfo(activity.getPackageName(), signingFlags()); }
    private int signingFlags() { return Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES; }
    private String certificate(PackageInfo info) throws Exception {
        Signature[] signatures = Build.VERSION.SDK_INT >= 28 ? info.signingInfo.getApkContentsSigners() : info.signatures;
        if (signatures == null || signatures.length != 1) throw new Exception("Неподдерживаемая подпись");
        return hex(MessageDigest.getInstance("SHA-256").digest(signatures[0].toByteArray()));
    }
    private long version(PackageInfo info) { return Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode; }
    void check(boolean manual) {
        if (checking || prefs.contains("download")) { if (manual) { installerOpen = false; resume(); } return; }
        checking = true;
        worker.execute(() -> {
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) new URL(FEED).openConnection();
                connection.setConnectTimeout(15000); connection.setReadTimeout(15000);
                byte[] data;
                try (java.io.InputStream input = connection.getInputStream(); java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {
                    byte[] buf = new byte[4096]; int n;
                    while ((n = input.read(buf)) != -1) { if (out.size() + n > 65536) throw new Exception("Слишком большой ответ"); out.write(buf, 0, n); }
                    data = out.toByteArray();
                }
                JSONObject feed = new JSONObject(new String(data, java.nio.charset.StandardCharsets.UTF_8));
                int next = feed.getInt("versionCode"); PackageInfo current = installed();
                if (next <= version(current)) { if (manual) message("Установлена последняя версия."); return; }
                if (!manual && offered == next) return;
                offered = next;
                if (!certificate(current).equals(feed.getString("certificate_sha256"))) {
                    message("Новая версия доступна, но её ключ подписи отличается от этой тестовой сборки. Обновление без удаления возможно только с тем же постоянным ключом подписи."); return;
                }
                String url = feed.getString("url"), hash = feed.getString("sha256");
                Uri uri = Uri.parse(url);
                if (!"https".equals(uri.getScheme()) || !"github.com".equals(uri.getHost()) || uri.getUserInfo() != null
                        || !uri.getPath().startsWith("/6n5bcdsq7z-art/insellers-desktop/releases/download/market-") || !hash.matches("[a-f0-9]{64}")) throw new Exception("Некорректное обновление");
                ui(() -> new AlertDialog.Builder(activity).setTitle("Доступна версия " + feed.optString("version"))
                    .setMessage("Скачать и установить обновление INSELLERS? Ваши данные сохранятся.")
                    .setPositiveButton("Обновить", (d, which) -> download(uri, hash, next)).setNegativeButton("Позже", null).show());
            } catch (Exception error) { if (manual) message("Не удалось проверить обновления. Проверьте интернет и попробуйте ещё раз."); }
            finally { if (connection != null) connection.disconnect(); ui(() -> checking = false); }
        });
    }
    private void download(Uri uri, String hash, int next) {
        if (prefs.contains("download")) return;
        File file = new File(activity.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), "INSELLERS-update.apk");
        if (file.exists() && !file.delete()) { message("Не удалось подготовить загрузку."); return; }
        try {
            DownloadManager.Request request = new DownloadManager.Request(uri).setTitle("Обновление INSELLERS")
                .setMimeType("application/vnd.android.package-archive")
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                .setDestinationInExternalFilesDir(activity, Environment.DIRECTORY_DOWNLOADS, "INSELLERS-update.apk");
            long id = downloads.enqueue(request);
            prefs.edit().putLong("download", id).putString("hash", hash).putInt("version", next).apply();
            Toast.makeText(activity, "Обновление загружается…", Toast.LENGTH_LONG).show();
        } catch (Exception error) { message("Не удалось начать загрузку."); }
    }
    void resume() { if (prefs.contains("download")) completeDownload(); }
    private void completeDownload() {
        long id = prefs.getLong("download", -1);
        if (id < 0) return;
        try (Cursor cursor = downloads.query(new DownloadManager.Query().setFilterById(id))) {
            if (!cursor.moveToFirst()) { prefs.edit().clear().apply(); return; }
            int status = cursor.getInt(cursor.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS));
            if (status == DownloadManager.STATUS_FAILED) { prefs.edit().clear().apply(); message("Загрузка не удалась. Проверьте интернет и повторите."); return; }
            if (status != DownloadManager.STATUS_SUCCESSFUL || checking || installerOpen) return;
        }
        checking = true;
        worker.execute(() -> {
            try {
                File file = new File(activity.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), "INSELLERS-update.apk");
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                try (FileInputStream input = new FileInputStream(file)) { byte[] buf = new byte[8192]; int n; while ((n = input.read(buf)) != -1) digest.update(buf, 0, n); }
                if (!hex(digest.digest()).equals(prefs.getString("hash", ""))) throw new Exception("Контрольная сумма не совпала");
                PackageInfo next = activity.getPackageManager().getPackageArchiveInfo(file.getAbsolutePath(), signingFlags());
                PackageInfo current = installed();
                if (next == null || !activity.getPackageName().equals(next.packageName) || version(next) != prefs.getInt("version", -1)
                        || version(next) <= version(current) || !certificate(next).equals(certificate(current))) throw new Exception("Несовместимый пакет или подпись");
                ui(() -> install(id));
            } catch (Exception error) { prefs.edit().clear().apply(); downloads.remove(id); message("Проверка обновления не пройдена. Установка отменена."); }
            finally { ui(() -> checking = false); }
        });
    }
    private void install(long id) {
        installerOpen = true;
        if (!activity.getPackageManager().canRequestPackageInstalls()) {
            new AlertDialog.Builder(activity).setTitle("Разрешить обновление")
                .setMessage("Разрешите INSELLERS устанавливать обновления, затем вернитесь в приложение.")
                .setPositiveButton("Открыть настройки", (d, which) -> activity.startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + activity.getPackageName()))))
                .setNegativeButton("Позже", null).show();
            return;
        }
        Uri uri = downloads.getUriForDownloadedFile(id);
        if (uri == null) { message("Файл обновления не найден."); return; }
        try { activity.startActivity(new Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)); }
        catch (Exception error) { message("Не удалось открыть установщик Android."); }
    }
    void foreground() { installerOpen = false; if (!polling) { polling = true; handler.post(poll); } }
    void background() { polling = false; handler.removeCallbacks(poll); }
    void close() { background(); worker.shutdownNow(); }
}
