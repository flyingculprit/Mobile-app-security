Java.perform(function() {
    try {
        // Replace 'com.example.MainActivity' with the correct class name
        var MainActivity = Java.use('com.example.MainActivity');
        
        // Replace 'someMethod' with the actual method name and specify the correct argument type if necessary
        MainActivity.someMethod.implementation = function(arg) {
            // Log the method call with the argument
            console.log('someMethod called with arg: ' + arg);

            // Call the original method
            return this.someMethod(arg);
        };

        console.log('Frida script loaded and hooked into someMethod successfully.');

    } catch (error) {
        // Log any errors encountered
        console.error('Error in Frida script: ' + error.message);
    }
});
