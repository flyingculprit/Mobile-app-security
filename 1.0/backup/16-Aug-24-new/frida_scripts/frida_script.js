Java.perform(function() {
    var MainActivity = Java.use('com.example.MainActivity');
    MainActivity.someMethod.implementation = function(arg) {
        console.log('someMethod called with arg: ' + arg);
        return this.someMethod(arg);
    };
});
