// // script.js
// Java.perform(function() {
//     console.log("Inside the frida script");

//     // Example: Hook a method in a specific class
//     var MainActivity = Java.use("com.example.app.MainActivity");
//     MainActivity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
//         console.log("MainActivity.onCreate called");
//         this.onCreate(bundle);  // Call the original method
//     };

//     // Add more hooks as needed
// });
// Frida script for dynamic analysis

Java.perform(function () {
    var Activity = Java.use('android.app.Activity');
    var Log = Java.use('android.util.Log');
    var HttpClient = Java.use('org.apache.http.impl.client.DefaultHttpClient');

    // Hooking onResume method of Activity
    Activity.onResume.implementation = function () {
        console.log('onResume() called');
        // You can perform additional actions here or log method calls
        this.onResume();
    };

    // Example hook for logging HTTP requests made by HttpClient
    HttpClient.execute.overload('org.apache.http.client.methods.HttpUriRequest').implementation = function (request) {
        console.log('HTTP Request URL:', request.getRequestLine().toString());
        var response = this.execute(request);
        console.log('HTTP Response Status:', response.getStatusLine().toString());
        return response;
    };

    // Example hook for logging sensitive method calls
    var SensitiveClass = Java.use('com.example.SensitiveClass');
    SensitiveClass.sensitiveMethod.implementation = function (arg1, arg2) {
        console.log('Sensitive method called with arguments:', arg1, arg2);
        return this.sensitiveMethod(arg1, arg2);
    };

    // Example hook for logging method calls based on conditions
    var TargetClass = Java.use('com.example.TargetClass');
    TargetClass.targetMethod.implementation = function (arg1, arg2) {
        if (arg1 === 'targetValue') {
            console.log('Target method called with specific value:', arg1, arg2);
        }
        return this.targetMethod(arg1, arg2);
    };
});
