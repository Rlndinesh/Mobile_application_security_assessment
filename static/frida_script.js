Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    Activity.onResume.implementation = function () {
        console.log("[*] App Resumed");
        this.onResume();
    };

    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.implementation = function (url) {
        console.log("[!] Intercepted WebView Load URL: " + url);
        return this.loadUrl(url);
    };
});
