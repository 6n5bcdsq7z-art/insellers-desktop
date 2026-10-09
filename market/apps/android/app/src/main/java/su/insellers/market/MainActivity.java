package su.insellers.market;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;
import android.webkit.CookieManager;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

public class MainActivity extends Activity {
    private static final String ENTRY = "https://bot.insellers.su/?app=android";
    private static final int FILE_REQUEST = 31;
    private WebView web;
    private AppUpdates updates;
    private ValueCallback<Uri[]> fileCallback;

    private boolean internal(Uri uri) {
        return "https".equals(uri.getScheme()) && "bot.insellers.su".equals(uri.getHost())
                && (uri.getPort() == -1 || uri.getPort() == 443) && uri.getUserInfo() == null;
    }
    private void external(Uri uri) {
        String scheme = uri.getScheme();
        if (!("https".equals(scheme) || "http".equals(scheme) || "tg".equals(scheme)
                || "tel".equals(scheme) || "mailto".equals(scheme))) return;
        try { startActivity(new Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE)); }
        catch (ActivityNotFoundException e) { Toast.makeText(this, "Нет приложения для этой ссылки", Toast.LENGTH_SHORT).show(); }
    }
    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        updates = new AppUpdates(this);
        updates.check(false);
        web = new WebView(this); setContentView(web);
        web.setOnApplyWindowInsetsListener((v, insets) -> {
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);
        web.getSettings().setAllowFileAccess(false);
        web.getSettings().setAllowContentAccess(true);
        web.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.getSettings().setSupportMultipleWindows(true);
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                if (internal(request.getUrl())) return false;
                if (request.isForMainFrame()) external(request.getUrl());
                return true;
            }
            @Override public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) view.loadDataWithBaseURL(ENTRY,
                    "<html lang='ru'><meta name='viewport' content='width=device-width,initial-scale=1'><body style='font:18px sans-serif;padding:32px'><h1>INSELLERS</h1><p>Проверьте интернет.</p><a href='" + ENTRY + "'>Повторить</a></body></html>", "text/html", "UTF-8", null);
            }
            @Override public void onPageFinished(WebView view, String url) { CookieManager.getInstance().flush(); }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                try { startActivityForResult(params.createIntent(), FILE_REQUEST); }
                catch (ActivityNotFoundException e) { fileCallback.onReceiveValue(null); fileCallback = null; }
                return true;
            }
            @Override public boolean onCreateWindow(WebView view, boolean dialog, boolean gesture, android.os.Message message) {
                if (!gesture) return false;
                WebView popup = new WebView(MainActivity.this);
                popup.setWebViewClient(new WebViewClient() {
                    @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest request) {
                        if (internal(request.getUrl())) web.loadUrl(request.getUrl().toString());
                        else external(request.getUrl());
                        v.destroy(); return true;
                    }
                });
                ((WebView.WebViewTransport) message.obj).setWebView(popup); message.sendToTarget(); return true;
            }
        });
        if (savedState == null || web.restoreState(savedState) == null) web.loadUrl(ENTRY);
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == FILE_REQUEST && fileCallback != null) {
            fileCallback.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data)); fileCallback = null;
        }
    }
    @Override public boolean onCreateOptionsMenu(android.view.Menu menu) {
        menu.add("Проверить обновления").setOnMenuItemClickListener(item -> { updates.check(true); return true; });
        return true;
    }
    @Override protected void onResume() { super.onResume(); if (updates != null) updates.foreground(); }
    @Override protected void onPause() { updates.background(); CookieManager.getInstance().flush(); super.onPause(); }
    @Override protected void onSaveInstanceState(Bundle out) { web.saveState(out); super.onSaveInstanceState(out); }
    @Override public void onBackPressed() { if (web.canGoBack()) web.goBack(); else super.onBackPressed(); }
    @Override protected void onDestroy() {
        if (fileCallback != null) fileCallback.onReceiveValue(null);
        updates.close(); web.destroy(); super.onDestroy();
    }
}
