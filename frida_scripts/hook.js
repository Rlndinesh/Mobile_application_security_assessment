Java.perform(function () {
    console.log("Frida script started...");

    var MainActivity = Java.use("com.app.damnvulnerablebank.MainActivity");
    MainActivity.onCreate.overload("android.os.Bundle").implementation = function (bundle) {
        console.log("MainActivity.onCreate called!");
        this.onCreate(bundle);
    };

    var SensitiveClass = Java.use("com.app.damnvulnerablebank.SensitiveClass");
    SensitiveClass.getData.implementation = function () {
        console.log("Intercepted sensitive data!");
        return "Fake Data";
    };
});
