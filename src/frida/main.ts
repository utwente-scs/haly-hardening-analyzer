global.context = '{{context}}'
global.safeMode = '{{safeMode}}';

if (Java.available) {
    // Save the application's class loader since the default class loader is
    // replaced by Frida's class loader after using Java.registerClass
    Java.perform(() => {
        global.appClassLoader = Java.classFactory.loader;
    });
}

require("./inc/util");

if (Process.platform == 'darwin') {
    require("./inc/dump");
}

// Register detectors
let detectors = require.context(
    "./detectors",
    true,
    /\.ts$/
)
for (let key of detectors.keys()) {
    detectors(key);
}
